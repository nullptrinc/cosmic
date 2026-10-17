/* SPDX-License-Identifier: MIT */
/* APF packages (see SPEC.md) and the cosmic tools around them. */
#ifndef COSMIC_APF_H
#define COSMIC_APF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APF_FORMAT 1
#define COSMIC_API 1 /* the platform API level this Starry provides */
#define APF_MAX_ENTRIES 10000
#define APF_MAX_UNPACKED (1ULL << 30)
#define APF_MAX_META (4 << 20) /* META-INF/files and manifest.json */
#define APF_MAX_SIGNATURES 16
#define APF_PATH_MAX 256
#define APF_ID_MAX 128
#define APF_SIGN_DOMAIN "cosmic-apf-1\n"
#define APF_KEY_ID_SIZE 17 /* 16 hex digits and the terminator */

#define cosmic_say(...) fprintf(stderr, "cosmic: " __VA_ARGS__)

struct json_object;

struct apf_manifest {
	struct json_object *json;
	char id[APF_ID_MAX + 1];
	char version[64];
	long build;
	long api;
	char entry_type[8]; /* "qml" or "native" */
	char entry_path[APF_PATH_MAX];
	char icon[APF_PATH_MAX];
	char color[8];
};

struct apf_file {
	char path[APF_PATH_MAX];
	unsigned char sha256[32];
	uint64_t size;
	bool executable;
};

struct apf_package {
	struct apf_manifest manifest;
	struct apf_file *files; /* sorted by path */
	int file_count;
	char signers[APF_MAX_SIGNATURES][APF_KEY_ID_SIZE]; /* key ids with valid signatures */
	int signer_count;
};

/* paths.c */
bool apf_valid_path(const char *path);
bool apf_valid_id(const char *id);

/* manifest.c */
bool manifest_parse(const char *text, size_t length, struct apf_manifest *manifest,
	char *error, size_t error_size);
void manifest_free(struct apf_manifest *manifest);
/* The display name for a locale such as "ru_RU", falling back to "ru" and "en". */
const char *manifest_name(const struct apf_manifest *manifest, const char *locale);

/* keys.c */
struct apf_key;
/* Writes a private key to path and its public key to path.pub. */
bool key_generate(const char *path, char id[APF_KEY_ID_SIZE]);
struct apf_key *key_load_private(const char *path);
void key_free(struct apf_key *key);
const char *key_id(const struct apf_key *key);
/* Reads a "key ed25519 BASE64" public key file; fills its id. */
bool key_read_public_id(const char *path, char id[APF_KEY_ID_SIZE]);
/* The text of a .sig file for this content list; free() it. */
char *signature_make(const struct apf_key *key, const char *files, size_t length);
/* Checks a .sig file against the content list and gives the signer's key id. */
bool signature_check(const char *text, const char *files, size_t length, char id[APF_KEY_ID_SIZE]);
void sha256_hex(const unsigned char digest[32], char hex[65]);

/* read.c */
/* Reads and verifies a package, unpacking its files into the directory
 * dirfd when it is not -1. False with a message in error otherwise. */
bool apf_read(const char *path, int dirfd, struct apf_package *package,
	char *error, size_t error_size);
void apf_package_free(struct apf_package *package);
/* META-INF/files for sorted files; free() it. */
char *apf_content_list(const struct apf_file *files, int count, size_t *length);

/* write.c */
bool apf_pack(const char *directory, struct apf_key **keys, int key_count, const char *output);
/* Adds signatures to an existing package, replacing ones by the same keys. */
bool apf_sign(const char *path, struct apf_key **keys, int key_count);

/* install.c */
struct cosmic_state {
	long uid;
	long build;
	bool platform;
	char signers[APF_MAX_SIGNATURES][APF_KEY_ID_SIZE];
	int signer_count;
};
/* The install root, /data/cosmic unless $COSMIC_ROOT says otherwise. */
const char *cosmic_root(void);
bool cosmic_read_state(const char *id, struct cosmic_state *state);
bool cosmic_install(const char *path);
bool cosmic_remove(const char *id);
bool cosmic_list(void);

/* serve.c: publishes installed apps to Constellation, /blinks/apps/<id>. */
int cosmic_serve(void);

#endif
