/* SPDX-License-Identifier: MIT */
/* Building and signing packages. Output is reproducible: sorted entries, fixed times. */
#define _GNU_SOURCE
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "apf.h"

#define ENTRY_TIME 946684800 /* 2000-01-01, a valid zip timestamp everywhere */

static struct {
	const char *root;
	struct apf_file *files;
	int count, capacity;
	bool failed;
} walk;

static bool hash_file(const char *path, unsigned char digest[32]) {
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		return false;
	}
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	EVP_DigestInit_ex(hash, EVP_sha256(), NULL);
	char chunk[65536];
	ssize_t n;
	while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
		EVP_DigestUpdate(hash, chunk, (size_t)n);
	}
	EVP_DigestFinal_ex(hash, digest, NULL);
	EVP_MD_CTX_free(hash);
	close(fd);
	return n == 0;
}

static int visit(const char *path, const struct stat *info, int type, struct FTW *ftw) {
	if (ftw->level == 0) {
		return 0;
	}
	const char *relative = path + strlen(walk.root) + 1;
	if (strcmp(relative, "META-INF") == 0 || !apf_valid_path(relative)) {
		cosmic_say("%s: not allowed in a package\n", relative);
		walk.failed = true;
		return 1;
	}
	if (type == FTW_D) {
		return 0;
	}
	if (type != FTW_F || !S_ISREG(info->st_mode)) {
		cosmic_say("%s: only regular files and directories can be packed\n", relative);
		walk.failed = true;
		return 1;
	}
	if (walk.count == walk.capacity) {
		walk.capacity = walk.capacity ? walk.capacity * 2 : 64;
		void *grown = realloc(walk.files, (size_t)walk.capacity * sizeof(*walk.files));
		if (!grown || walk.count >= APF_MAX_ENTRIES) {
			cosmic_say("too many files\n");
			walk.failed = true;
			return 1;
		}
		walk.files = grown;
	}
	struct apf_file *file = &walk.files[walk.count++];
	snprintf(file->path, sizeof(file->path), "%s", relative);
	file->size = (uint64_t)info->st_size;
	file->executable = (info->st_mode & 0111) != 0;
	if (!hash_file(path, file->sha256)) {
		cosmic_say("%s: %s\n", relative, strerror(errno));
		walk.failed = true;
		return 1;
	}
	return 0;
}

static int compare_files(const void *a, const void *b) {
	return strcmp(((const struct apf_file *)a)->path, ((const struct apf_file *)b)->path);
}

static struct archive_entry *new_entry(const char *path, uint64_t size, bool executable) {
	struct archive_entry *entry = archive_entry_new();
	archive_entry_set_pathname(entry, path);
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_perm(entry, executable ? 0755 : 0644);
	archive_entry_set_size(entry, (la_int64_t)size);
	archive_entry_set_mtime(entry, ENTRY_TIME, 0);
	return entry;
}

static bool write_buffer(struct archive *out, const char *path, const char *data, size_t size) {
	struct archive_entry *entry = new_entry(path, size, false);
	bool ok = archive_write_header(out, entry) == ARCHIVE_OK &&
		(size == 0 || archive_write_data(out, data, size) == (la_ssize_t)size);
	archive_entry_free(entry);
	return ok;
}

static bool write_file(struct archive *out, const char *root, const struct apf_file *file) {
	char path[4096];
	snprintf(path, sizeof(path), "%s/%s", root, file->path);
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		return false;
	}
	struct archive_entry *entry = new_entry(file->path, file->size, file->executable);
	bool ok = archive_write_header(out, entry) == ARCHIVE_OK;
	archive_entry_free(entry);
	char chunk[65536];
	ssize_t n;
	uint64_t total = 0;
	while (ok && (n = read(fd, chunk, sizeof(chunk))) > 0) {
		ok = archive_write_data(out, chunk, (size_t)n) == n;
		total += (uint64_t)n;
	}
	close(fd);
	return ok && total == file->size; /* changed while packing otherwise */
}

static struct archive *open_output(const char *path) {
	struct archive *out = archive_write_new();
	archive_write_set_format_zip(out);
	archive_write_zip_set_compression_deflate(out);
	if (archive_write_open_filename(out, path) != ARCHIVE_OK) {
		cosmic_say("%s: %s\n", path, archive_error_string(out));
		archive_write_free(out);
		return NULL;
	}
	return out;
}

static bool write_signatures(struct archive *out, struct apf_key **keys, int key_count,
		const char *list, size_t length) {
	for (int i = 0; i < key_count; i++) {
		char *signature = signature_make(keys[i], list, length);
		char path[64];
		snprintf(path, sizeof(path), "META-INF/%s.sig", key_id(keys[i]));
		bool ok = signature && write_buffer(out, path, signature, strlen(signature));
		free(signature);
		if (!ok) {
			return false;
		}
	}
	return true;
}

/* Verifies the finished temporary file and moves it into place. */
static bool finish(const char *temporary, const char *output) {
	struct apf_package package;
	char error[512];
	if (!apf_read(temporary, -1, &package, error, sizeof(error))) {
		cosmic_say("%s\n", error);
		unlink(temporary);
		return false;
	}
	apf_package_free(&package);
	if (rename(temporary, output) < 0) {
		cosmic_say("%s: %s\n", output, strerror(errno));
		unlink(temporary);
		return false;
	}
	return true;
}

bool apf_pack(const char *directory, struct apf_key **keys, int key_count, const char *output) {
	char root[4096];
	snprintf(root, sizeof(root), "%s", directory);
	for (size_t length = strlen(root); length > 1 && root[length - 1] == '/'; length--) {
		root[length - 1] = 0;
	}
	walk.root = root;
	walk.count = 0;
	walk.failed = false;
	if (nftw(root, visit, 16, FTW_PHYS) != 0 || walk.failed) {
		if (!walk.failed) {
			cosmic_say("%s: %s\n", root, strerror(errno));
		}
		return false;
	}
	qsort(walk.files, (size_t)walk.count, sizeof(*walk.files), compare_files);
	size_t length;
	char *list = apf_content_list(walk.files, walk.count, &length);
	char temporary[4096];
	snprintf(temporary, sizeof(temporary), "%s.tmp", output);
	struct archive *out = list ? open_output(temporary) : NULL;
	bool ok = out && write_buffer(out, "META-INF/files", list, length) &&
		write_signatures(out, keys, key_count, list, length);
	/* The manifest first among the contents, so a reader finds it early. */
	for (int i = 0; ok && i < walk.count; i++) {
		if (strcmp(walk.files[i].path, "manifest.json") == 0) {
			ok = write_file(out, root, &walk.files[i]);
		}
	}
	for (int i = 0; ok && i < walk.count; i++) {
		if (strcmp(walk.files[i].path, "manifest.json") != 0) {
			ok = write_file(out, root, &walk.files[i]);
		}
	}
	if (out) {
		ok = archive_write_close(out) == ARCHIVE_OK && ok;
		archive_write_free(out);
	}
	free(list);
	free(walk.files);
	walk.files = NULL;
	walk.capacity = 0;
	if (!ok) {
		cosmic_say("cannot write %s\n", output);
		unlink(temporary);
		return false;
	}
	return finish(temporary, output);
}

bool apf_sign(const char *path, struct apf_key **keys, int key_count) {
	struct apf_package package;
	char error[512];
	if (!apf_read(path, -1, &package, error, sizeof(error))) {
		cosmic_say("%s\n", error);
		return false;
	}
	size_t length;
	char *list = apf_content_list(package.files, package.file_count, &length);
	apf_package_free(&package);

	char temporary[4096];
	snprintf(temporary, sizeof(temporary), "%s.tmp", path);
	struct archive *in = archive_read_new();
	archive_read_support_format_zip_seekable(in);
	struct archive *out = list ? open_output(temporary) : NULL;
	bool ok = out && archive_read_open_filename(in, path, 65536) == ARCHIVE_OK;
	struct archive_entry *entry;
	while (ok && archive_read_next_header(in, &entry) == ARCHIVE_OK) {
		const char *name = archive_entry_pathname(entry);
		bool replaced = false;
		for (int i = 0; i < key_count; i++) {
			char signature[64];
			snprintf(signature, sizeof(signature), "META-INF/%s.sig", key_id(keys[i]));
			replaced |= strcmp(name, signature) == 0;
		}
		if (replaced || archive_entry_filetype(entry) != AE_IFREG) {
			continue;
		}
		struct archive_entry *copy = new_entry(name, (uint64_t)archive_entry_size(entry),
			(archive_entry_perm(entry) & 0111) != 0);
		ok = archive_write_header(out, copy) == ARCHIVE_OK;
		archive_entry_free(copy);
		char chunk[65536];
		la_ssize_t n;
		while (ok && (n = archive_read_data(in, chunk, sizeof(chunk))) > 0) {
			ok = archive_write_data(out, chunk, (size_t)n) == n;
		}
	}
	ok = ok && write_signatures(out, keys, key_count, list, length);
	archive_read_free(in);
	if (out) {
		ok = archive_write_close(out) == ARCHIVE_OK && ok;
		archive_write_free(out);
	}
	free(list);
	if (!ok) {
		cosmic_say("cannot sign %s\n", path);
		unlink(temporary);
		return false;
	}
	return finish(temporary, path);
}
