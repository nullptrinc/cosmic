/* SPDX-License-Identifier: MIT */
/* Installing, updating and removing packages under /data/cosmic (SPEC.md). */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "apf.h"

#define FIRST_UID 10000
#define LAST_UID 19999

struct state {
	long uid;
	long build;
	bool platform;
	char signers[APF_MAX_SIGNATURES][APF_KEY_ID_SIZE];
	int signer_count;
};

static char root[PATH_MAX];

static const char *path_in(char *buffer, const char *format, ...) __attribute__((format(printf, 2, 3)));
static const char *path_in(char *buffer, const char *format, ...) {
	char tail[PATH_MAX];
	va_list args;
	va_start(args, format);
	vsnprintf(tail, sizeof(tail), format, args);
	va_end(args);
	snprintf(buffer, PATH_MAX, "%s/%s", root, tail);
	return buffer;
}

static bool make_directory(const char *path, mode_t mode) {
	return mkdir(path, mode) == 0 || errno == EEXIST;
}

/* Creates the layout and takes the cosmic lock; returns its descriptor. */
static int open_root(void) {
	const char *base = getenv("COSMIC_ROOT");
	snprintf(root, sizeof(root), "%s", base && base[0] ? base : "/data/cosmic");
	char path[PATH_MAX];
	if (!make_directory(root, 0755) || !make_directory(path_in(path, "apps"), 0755) ||
			!make_directory(path_in(path, "apps/.staging"), 0700) ||
			!make_directory(path_in(path, "data"), 0711) ||
			!make_directory(path_in(path, "state"), 0755) ||
			!make_directory(path_in(path, "state/apps"), 0755)) {
		cosmic_say("%s: %s\n", path, strerror(errno));
		return -1;
	}
	int lock = open(path_in(path, "state/lock"), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lock < 0 || flock(lock, LOCK_EX) < 0) {
		cosmic_say("%s: %s\n", path, strerror(errno));
		if (lock >= 0) {
			close(lock);
		}
		return -1;
	}
	return lock;
}

static int remove_entry(const char *path, const struct stat *info, int type, struct FTW *ftw) {
	return remove(path) < 0 && errno != ENOENT ? -1 : 0;
}

static bool remove_tree(const char *path) {
	struct stat info;
	if (lstat(path, &info) < 0) {
		return errno == ENOENT;
	}
	return nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT) == 0;
}

static bool read_state(const char *id, struct state *state) {
	char path[PATH_MAX];
	memset(state, 0, sizeof(*state));
	struct json_object *json = json_object_from_file(path_in(path, "state/apps/%s.json", id));
	if (!json) {
		return false;
	}
	struct json_object *value;
	if (json_object_object_get_ex(json, "uid", &value)) {
		state->uid = (long)json_object_get_int64(value);
	}
	if (json_object_object_get_ex(json, "build", &value)) {
		state->build = (long)json_object_get_int64(value);
	}
	if (json_object_object_get_ex(json, "platform", &value)) {
		state->platform = json_object_get_boolean(value);
	}
	if (json_object_object_get_ex(json, "signers", &value) &&
			json_object_is_type(value, json_type_array)) {
		for (size_t i = 0; i < json_object_array_length(value) &&
				state->signer_count < APF_MAX_SIGNATURES; i++) {
			snprintf(state->signers[state->signer_count++], APF_KEY_ID_SIZE, "%s",
				json_object_get_string(json_object_array_get_idx(value, i)));
		}
	}
	json_object_put(json);
	return state->uid >= FIRST_UID;
}

static bool write_state(const struct apf_package *package, const struct state *state) {
	struct json_object *json = json_object_new_object();
	json_object_object_add(json, "uid", json_object_new_int64(state->uid));
	json_object_object_add(json, "version", json_object_new_string(package->manifest.version));
	json_object_object_add(json, "build", json_object_new_int64(state->build));
	json_object_object_add(json, "platform", json_object_new_boolean(state->platform));
	json_object_object_add(json, "installed", json_object_new_int64((int64_t)time(NULL)));
	struct json_object *signers = json_object_new_array();
	for (int i = 0; i < state->signer_count; i++) {
		json_object_array_add(signers, json_object_new_string(state->signers[i]));
	}
	json_object_object_add(json, "signers", signers);
	char path[PATH_MAX], temporary[PATH_MAX];
	path_in(path, "state/apps/%s.json", package->manifest.id);
	snprintf(temporary, sizeof(temporary), "%s.tmp", path);
	bool ok = json_object_to_file_ext(temporary, json, JSON_C_TO_STRING_PRETTY) == 0 &&
		rename(temporary, path) == 0;
	json_object_put(json);
	return ok;
}

/* The app's uid: the one it had before, or the next free one. */
static long assign_uid(const char *id) {
	char path[PATH_MAX];
	FILE *file = fopen(path_in(path, "state/uids"), "a+");
	if (!file) {
		return -1;
	}
	rewind(file);
	char line_id[APF_ID_MAX + 2];
	long uid, highest = FIRST_UID - 1;
	while (fscanf(file, "%129s %ld", line_id, &uid) == 2) {
		if (strcmp(line_id, id) == 0) {
			fclose(file);
			return uid;
		}
		highest = uid > highest ? uid : highest;
	}
	uid = highest + 1;
	bool ok = uid <= LAST_UID && fprintf(file, "%s %ld\n", id, uid) > 0;
	ok = fclose(file) == 0 && ok;
	return ok ? uid : -1;
}

/* Whether a key in /etc/cosmic/keys ($COSMIC_KEYS overrides) signed the package. */
static bool platform_signed(const struct apf_package *package) {
	const char *directory = getenv("COSMIC_KEYS");
	directory = directory && directory[0] ? directory : "/etc/cosmic/keys";
	DIR *dir = opendir(directory);
	if (!dir) {
		return false;
	}
	bool found = false;
	for (struct dirent *entry; !found && (entry = readdir(dir));) {
		size_t length = strlen(entry->d_name);
		char path[PATH_MAX], id[APF_KEY_ID_SIZE];
		if (length < 5 || strcmp(entry->d_name + length - 4, ".pub") != 0) {
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
		if (!key_read_public_id(path, id)) {
			cosmic_say("ignoring unreadable key %s\n", path);
			continue;
		}
		for (int i = 0; i < package->signer_count; i++) {
			found |= strcmp(package->signers[i], id) == 0;
		}
	}
	closedir(dir);
	return found;
}

static bool shares_signer(const struct apf_package *package, const struct state *state) {
	for (int i = 0; i < package->signer_count; i++) {
		for (int j = 0; j < state->signer_count; j++) {
			if (strcmp(package->signers[i], state->signers[j]) == 0) {
				return true;
			}
		}
	}
	return false;
}

static bool install_locked(const char *file) {
	char staging[PATH_MAX], error[512];
	path_in(staging, "apps/.staging/XXXXXX");
	if (!mkdtemp(staging)) {
		cosmic_say("%s: %s\n", staging, strerror(errno));
		return false;
	}
	chmod(staging, 0755);
	int dirfd = open(staging, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	struct apf_package package;
	bool read = dirfd >= 0 && apf_read(file, dirfd, &package, error, sizeof(error));
	if (dirfd >= 0) {
		close(dirfd);
	}
	if (!read) {
		cosmic_say("%s: %s\n", file, dirfd >= 0 ? error : strerror(errno));
		remove_tree(staging);
		return false;
	}

	const struct apf_manifest *manifest = &package.manifest;
	struct state old, state = { 0 };
	bool update = read_state(manifest->id, &old);
	const char *problem = NULL;
	if (manifest->api > COSMIC_API) {
		problem = "needs a newer Starry (api)";
	} else if (update && manifest->build <= old.build) {
		problem = "is not newer than the installed build";
	} else if (update && !shares_signer(&package, &old)) {
		problem = "is not signed by the key of the installed app";
	}
	if (problem) {
		cosmic_say("%s %s %s\n", manifest->id, manifest->version, problem);
		apf_package_free(&package);
		remove_tree(staging);
		return false;
	}

	state.uid = update ? old.uid : assign_uid(manifest->id);
	state.build = manifest->build;
	state.platform = platform_signed(&package);
	/* Keep the original signers, so the first key stays valid for updates. */
	for (int i = 0; update && i < old.signer_count; i++) {
		memcpy(state.signers[state.signer_count++], old.signers[i], APF_KEY_ID_SIZE);
	}
	for (int i = 0; i < package.signer_count && state.signer_count < APF_MAX_SIGNATURES; i++) {
		bool known = false;
		for (int j = 0; j < state.signer_count; j++) {
			known |= strcmp(state.signers[j], package.signers[i]) == 0;
		}
		if (!known) {
			memcpy(state.signers[state.signer_count++], package.signers[i], APF_KEY_ID_SIZE);
		}
	}

	char target[PATH_MAX], data[PATH_MAX];
	path_in(target, "apps/%s", manifest->id);
	path_in(data, "data/%s", manifest->id);
	bool ok = state.uid >= FIRST_UID;
	if (!ok) {
		cosmic_say("no free uid\n");
	}
	if (ok && (make_directory(data, 0700) == false ||
			(geteuid() == 0 && chown(data, (uid_t)state.uid, (gid_t)state.uid) < 0))) {
		cosmic_say("%s: %s\n", data, strerror(errno));
		ok = false;
	}
	/* The new version takes the old one's place in one step. */
	struct stat info;
	bool exists = lstat(target, &info) == 0;
	if (ok && exists && renameat2(AT_FDCWD, staging, AT_FDCWD, target, RENAME_EXCHANGE) < 0) {
		cosmic_say("%s: %s\n", target, strerror(errno));
		ok = false;
	} else if (ok && !exists && rename(staging, target) < 0) {
		cosmic_say("%s: %s\n", target, strerror(errno));
		ok = false;
	}
	remove_tree(staging); /* the old version after a swap */
	if (ok && !write_state(&package, &state)) {
		cosmic_say("cannot record %s\n", manifest->id);
		ok = false;
	}
	if (ok) {
		printf("%s %s %s (build %ld), uid %ld%s\n", update ? "updated" : "installed",
			manifest->id, manifest->version, manifest->build, state.uid,
			state.platform ? ", platform" : "");
	}
	apf_package_free(&package);
	return ok;
}

bool cosmic_install(const char *file) {
	int lock = open_root();
	if (lock < 0) {
		return false;
	}
	bool ok = install_locked(file);
	close(lock);
	return ok;
}

bool cosmic_remove(const char *id) {
	if (!apf_valid_id(id)) {
		cosmic_say("%s: not an app id\n", id);
		return false;
	}
	int lock = open_root();
	if (lock < 0) {
		return false;
	}
	struct state state;
	char path[PATH_MAX];
	bool ok = read_state(id, &state);
	if (!ok) {
		cosmic_say("%s is not installed\n", id);
	} else {
		/* The uid stays assigned, so a reinstall never meets old files of another app. */
		ok = remove_tree(path_in(path, "apps/%s", id)) && remove_tree(path_in(path, "data/%s", id)) &&
			unlink(path_in(path, "state/apps/%s.json", id)) == 0;
		if (ok) {
			printf("removed %s\n", id);
		} else {
			cosmic_say("%s: %s\n", path, strerror(errno));
		}
	}
	close(lock);
	return ok;
}

bool cosmic_list(void) {
	int lock = open_root();
	if (lock < 0) {
		return false;
	}
	char path[PATH_MAX];
	DIR *dir = opendir(path_in(path, "state/apps"));
	const char *locale = getenv("LANG");
	for (struct dirent *entry; dir && (entry = readdir(dir));) {
		size_t length = strlen(entry->d_name);
		if (length < 6 || strcmp(entry->d_name + length - 5, ".json") != 0) {
			continue;
		}
		char id[APF_ID_MAX + 1];
		snprintf(id, sizeof(id), "%.*s", (int)(length - 5), entry->d_name);
		struct state state;
		char manifest_path[PATH_MAX];
		FILE *file = fopen(path_in(manifest_path, "apps/%s/manifest.json", id), "r");
		char text[65536];
		size_t size = file ? fread(text, 1, sizeof(text), file) : 0;
		if (file) {
			fclose(file);
		}
		struct apf_manifest manifest;
		char error[256];
		if (!read_state(id, &state) || !manifest_parse(text, size, &manifest, error, sizeof(error))) {
			printf("%-32s (damaged)\n", id);
			continue;
		}
		printf("%-32s %-10s build %-4ld uid %ld%s  %s\n", id, manifest.version, manifest.build,
			state.uid, state.platform ? " platform" : "", manifest_name(&manifest, locale));
		manifest_free(&manifest);
	}
	if (dir) {
		closedir(dir);
	}
	close(lock);
	return true;
}
