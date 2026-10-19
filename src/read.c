/* SPDX-License-Identifier: MIT */
/*
 * Reading a package: every entry is checked before anything is trusted.
 * Files are unpacked with openat() under a fresh directory, by names that
 * passed apf_valid_path(), so no entry can land outside it.
 */
#define _GNU_SOURCE
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "apf.h"

#define MAX_SIGNATURE_FILE 4096

struct reader {
	struct archive *archive;
	int dirfd;
	uint64_t unpacked;
	char *error;
	size_t error_size;
};

#define FAIL(...) do { snprintf(r->error, r->error_size, __VA_ARGS__); return false; } while (0)

static int compare_files(const void *a, const void *b) {
	return strcmp(((const struct apf_file *)a)->path, ((const struct apf_file *)b)->path);
}

char *apf_content_list(const struct apf_file *files, int count, size_t *length) {
	size_t size = (size_t)count * (64 + 22 + APF_PATH_MAX + 2) + 1;
	char *text = malloc(size);
	if (!text) {
		return NULL;
	}
	size_t used = 0;
	for (int i = 0; i < count; i++) {
		char hex[65];
		sha256_hex(files[i].sha256, hex);
		used += (size_t)snprintf(text + used, size - used, "%s %llu %s\n", hex,
			(unsigned long long)files[i].size, files[i].path);
	}
	text[used] = 0;
	*length = used;
	return text;
}

/* Opens the directory that will hold path's last component, creating the
 * ones before it. Returns a descriptor the caller closes unless it is dirfd. */
static int open_parent(int dirfd, const char *path, const char **name) {
	char buffer[APF_PATH_MAX];
	snprintf(buffer, sizeof(buffer), "%s", path);
	int fd = dirfd;
	char *component = buffer;
	for (char *slash; (slash = strchr(component, '/')); component = slash + 1) {
		*slash = 0;
		if (mkdirat(fd, component, 0755) < 0 && errno != EEXIST) {
			goto fail;
		}
		int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (fd != dirfd) {
			close(fd);
		}
		fd = next;
		if (fd < 0) {
			return -1;
		}
	}
	*name = path + (component - buffer);
	return fd;
fail:
	if (fd != dirfd) {
		close(fd);
	}
	return -1;
}

/* Reads the current entry's data: hashes it, unpacks it when there is a
 * directory, keeps it in memory when keep is set (up to limit bytes). */
static bool read_data(struct reader *r, const char *path, bool executable,
		struct apf_file *file, char **keep, size_t limit) {
	int out = -1, parent = -1;
	if (r->dirfd >= 0) {
		const char *name;
		parent = open_parent(r->dirfd, path, &name);
		out = parent < 0 ? -1 : openat(parent, name,
			O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
		if (parent >= 0 && parent != r->dirfd) {
			close(parent);
		}
		if (out < 0) {
			FAIL("%s: cannot unpack (%s)", path, errno == EEXIST ? "duplicate entry" : strerror(errno));
		}
	}
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	EVP_DigestInit_ex(hash, EVP_sha256(), NULL);
	char *buffer = keep ? malloc(limit + 1) : NULL;
	char chunk[65536];
	uint64_t size = 0;
	bool ok = !keep || buffer;
	for (la_ssize_t n; ok && (n = archive_read_data(r->archive, chunk, sizeof(chunk))) != 0;) {
		if (n < 0) {
			snprintf(r->error, r->error_size, "%s: %s", path, archive_error_string(r->archive));
			ok = false;
			break;
		}
		size += (uint64_t)n;
		r->unpacked += (uint64_t)n;
		if (r->unpacked > APF_MAX_UNPACKED || (keep && size > limit)) {
			snprintf(r->error, r->error_size, "%s: too large", path);
			ok = false;
			break;
		}
		EVP_DigestUpdate(hash, chunk, (size_t)n);
		if (keep) {
			memcpy(buffer + size - (uint64_t)n, chunk, (size_t)n);
		}
		for (la_ssize_t written = 0; out >= 0 && written < n;) {
			ssize_t w = write(out, chunk + written, (size_t)(n - written));
			if (w < 0 && errno != EINTR) {
				snprintf(r->error, r->error_size, "%s: %s", path, strerror(errno));
				ok = false;
				break;
			}
			written += w < 0 ? 0 : w;
		}
	}
	EVP_DigestFinal_ex(hash, file->sha256, NULL);
	EVP_MD_CTX_free(hash);
	if (out >= 0) {
		ok = fchmod(out, executable ? 0755 : 0644) == 0 && ok;
		ok = close(out) == 0 && ok;
	}
	if (!ok) {
		free(buffer);
		return false;
	}
	snprintf(file->path, sizeof(file->path), "%s", path);
	file->size = size;
	file->executable = executable;
	if (keep) {
		buffer[size] = 0;
		*keep = buffer;
	}
	return true;
}

/* "0123456789abcdef.sig" -> the key id, or false. */
static bool signature_name(const char *name, char id[APF_KEY_ID_SIZE]) {
	if (strlen(name) != APF_KEY_ID_SIZE - 1 + 4 || strcmp(name + APF_KEY_ID_SIZE - 1, ".sig") != 0) {
		return false;
	}
	for (int i = 0; i < APF_KEY_ID_SIZE - 1; i++) {
		if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) {
			return false;
		}
	}
	memcpy(id, name, APF_KEY_ID_SIZE - 1);
	id[APF_KEY_ID_SIZE - 1] = 0;
	return true;
}

/* Whether the last id in ids appears before it. */
static bool repeated_id(char ids[][APF_KEY_ID_SIZE], int last) {
	for (int i = 0; i < last; i++) {
		if (strcmp(ids[i], ids[last]) == 0) {
			return true;
		}
	}
	return false;
}

static const struct apf_file *find_file(const struct apf_package *package, const char *path) {
	struct apf_file key;
	snprintf(key.path, sizeof(key.path), "%s", path);
	return bsearch(&key, package->files, (size_t)package->file_count, sizeof(key), compare_files);
}

static bool read_entries(struct reader *r, struct apf_package *package) {
	char *list = NULL, *manifest = NULL;
	size_t manifest_size = 0;
	char *signatures[APF_MAX_SIGNATURES] = { 0 };
	char signature_ids[APF_MAX_SIGNATURES][APF_KEY_ID_SIZE];
	int signature_count = 0, capacity = 0, entries = 0;
	bool ok = false;
	struct archive_entry *entry;
	int status;

	while ((status = archive_read_next_header(r->archive, &entry)) == ARCHIVE_OK) {
		const char *raw = archive_entry_pathname(entry);
		char path[APF_PATH_MAX + 1];
		if (++entries > APF_MAX_ENTRIES) {
			snprintf(r->error, r->error_size, "too many entries");
			goto done;
		}
		if (!raw || strlen(raw) > APF_PATH_MAX) {
			snprintf(r->error, r->error_size, "bad entry name");
			goto done;
		}
		snprintf(path, sizeof(path), "%s", raw);
		mode_t type = archive_entry_filetype(entry);
		if (type == AE_IFDIR) {
			size_t length = strlen(path);
			if (length > 0 && path[length - 1] == '/') {
				path[length - 1] = 0;
			}
			if (!apf_valid_path(path)) {
				snprintf(r->error, r->error_size, "bad directory name: %s", raw);
				goto done;
			}
			continue; /* directories are created for the files in them */
		}
		if (type != AE_IFREG || !apf_valid_path(path) || strcmp(path, "META-INF") == 0) {
			snprintf(r->error, r->error_size, "not an allowed file: %s", raw);
			goto done;
		}
		bool executable = (archive_entry_perm(entry) & 0111) != 0;
		struct apf_file file;
		if (strncmp(path, "META-INF/", 9) == 0) {
			const char *name = path + 9;
			if (strcmp(name, "files") == 0 && !list) {
				if (!read_data(r, path, false, &file, &list, APF_MAX_META)) {
					goto done;
				}
			} else if (signature_count < APF_MAX_SIGNATURES &&
					signature_name(name, signature_ids[signature_count]) &&
					!repeated_id(signature_ids, signature_count)) {
				if (!read_data(r, path, false, &file, &signatures[signature_count],
						MAX_SIGNATURE_FILE)) {
					goto done;
				}
				signature_count++;
			} else {
				snprintf(r->error, r->error_size, "unexpected or repeated %s", path);
				goto done;
			}
			continue;
		}
		if (package->file_count == capacity) {
			capacity = capacity ? capacity * 2 : 64;
			void *grown = realloc(package->files, (size_t)capacity * sizeof(*package->files));
			if (!grown) {
				snprintf(r->error, r->error_size, "out of memory");
				goto done;
			}
			package->files = grown;
		}
		bool is_manifest = strcmp(path, "manifest.json") == 0;
		if (is_manifest && manifest) {
			snprintf(r->error, r->error_size, "repeated manifest.json");
			goto done;
		}
		if (!read_data(r, path, executable, &file, is_manifest ? &manifest : NULL, APF_MAX_META)) {
			goto done;
		}
		if (is_manifest) {
			manifest_size = file.size;
		}
		package->files[package->file_count++] = file;
	}
	if (status != ARCHIVE_EOF) {
		snprintf(r->error, r->error_size, "broken archive: %s", archive_error_string(r->archive));
		goto done;
	}
	if (!manifest || !list) {
		snprintf(r->error, r->error_size, "no %s", manifest ? "META-INF/files" : "manifest.json");
		goto done;
	}

	/* The content list must be exactly the files that are there. */
	qsort(package->files, (size_t)package->file_count, sizeof(*package->files), compare_files);
	for (int i = 1; i < package->file_count; i++) {
		if (strcmp(package->files[i - 1].path, package->files[i].path) == 0) {
			snprintf(r->error, r->error_size, "duplicate entry %s", package->files[i].path);
			goto done;
		}
	}
	size_t expected_size;
	char *expected = apf_content_list(package->files, package->file_count, &expected_size);
	bool same = expected && strlen(list) == expected_size && memcmp(list, expected, expected_size) == 0;
	free(expected);
	if (!same) {
		snprintf(r->error, r->error_size, "META-INF/files does not match the contents");
		goto done;
	}

	for (int i = 0; i < signature_count; i++) {
		char id[APF_KEY_ID_SIZE];
		if (!signature_check(signatures[i], list, strlen(list), id) ||
				strcmp(id, signature_ids[i]) != 0) {
			snprintf(r->error, r->error_size, "bad signature META-INF/%s.sig", signature_ids[i]);
			goto done;
		}
		memcpy(package->signers[package->signer_count++], id, APF_KEY_ID_SIZE);
	}
	if (package->signer_count == 0) {
		snprintf(r->error, r->error_size, "the package is not signed");
		goto done;
	}

	if (!manifest_parse(manifest, manifest_size, &package->manifest, r->error, r->error_size)) {
		goto done;
	}
	const struct apf_file *program = find_file(package, package->manifest.entry_path);
	if (!program) {
		snprintf(r->error, r->error_size, "entry %s is not in the package", package->manifest.entry_path);
		goto done;
	}
	if (strcmp(package->manifest.entry_type, "native") == 0 && !program->executable) {
		snprintf(r->error, r->error_size, "entry %s is not executable", program->path);
		goto done;
	}
	for (int i = 0; i < APF_ICON_STYLES; i++) {
		const char *icon = package->manifest.icons[i];
		if (icon[0] && !find_file(package, icon)) {
			snprintf(r->error, r->error_size, "icon %s is not in the package", icon);
			goto done;
		}
	}
	ok = true;
done:
	free(list);
	free(manifest);
	for (int i = 0; i < signature_count; i++) {
		free(signatures[i]);
	}
	return ok;
}

bool apf_read(const char *path, int dirfd, struct apf_package *package,
		char *error, size_t error_size) {
	memset(package, 0, sizeof(*package));
	struct reader reader = { .dirfd = dirfd, .error = error, .error_size = error_size };
	reader.archive = archive_read_new();
	/* The seekable reader trusts the central directory only. */
	archive_read_support_format_zip_seekable(reader.archive);
	bool ok = false;
	if (archive_read_open_filename(reader.archive, path, 65536) != ARCHIVE_OK) {
		snprintf(error, error_size, "%s: %s", path, archive_error_string(reader.archive));
	} else {
		ok = read_entries(&reader, package);
	}
	archive_read_free(reader.archive);
	if (!ok) {
		apf_package_free(package);
	}
	return ok;
}

void apf_package_free(struct apf_package *package) {
	manifest_free(&package->manifest);
	free(package->files);
	package->files = NULL;
	package->file_count = 0;
}
