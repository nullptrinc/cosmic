/* SPDX-License-Identifier: MIT */
/* Ed25519 keys and .sig files, through OpenSSL. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "apf.h"

struct apf_key {
	EVP_PKEY *pkey;
	unsigned char public_key[32];
	char id[APF_KEY_ID_SIZE];
};

void sha256_hex(const unsigned char digest[32], char hex[65]) {
	for (int i = 0; i < 32; i++) {
		sprintf(hex + i * 2, "%02x", digest[i]);
	}
}

static void id_of(const unsigned char public_key[32], char id[APF_KEY_ID_SIZE]) {
	unsigned char digest[32];
	char hex[65];
	EVP_Digest(public_key, 32, digest, NULL, EVP_sha256(), NULL);
	sha256_hex(digest, hex);
	memcpy(id, hex, APF_KEY_ID_SIZE - 1);
	id[APF_KEY_ID_SIZE - 1] = 0;
}

static void encode(const unsigned char *data, int length, char *out) {
	EVP_EncodeBlock((unsigned char *)out, data, length);
}

/* Decodes exactly length bytes from canonical, padded base64. */
static bool decode(const char *text, size_t text_length, unsigned char *out, int length) {
	int expected = (length + 2) / 3 * 4;
	if ((int)text_length != expected) {
		return false;
	}
	unsigned char buffer[128];
	if (expected / 4 * 3 > (int)sizeof(buffer)) {
		return false;
	}
	if (EVP_DecodeBlock(buffer, (const unsigned char *)text, expected) < 0) {
		return false;
	}
	/* Reject non-canonical encodings: re-encode and compare. */
	char check[180];
	encode(buffer, length, check);
	if (memcmp(check, text, (size_t)expected) != 0) {
		return false;
	}
	memcpy(out, buffer, (size_t)length);
	return true;
}

static struct apf_key *wrap(EVP_PKEY *pkey) {
	struct apf_key *key = calloc(1, sizeof(*key));
	size_t length = sizeof(key->public_key);
	if (!key || EVP_PKEY_get_raw_public_key(pkey, key->public_key, &length) != 1 || length != 32) {
		free(key);
		EVP_PKEY_free(pkey);
		return NULL;
	}
	key->pkey = pkey;
	id_of(key->public_key, key->id);
	return key;
}

static bool write_public(const char *path, const unsigned char public_key[32]) {
	char encoded[64];
	encode(public_key, 32, encoded);
	FILE *file = fopen(path, "w");
	if (!file) {
		return false;
	}
	fprintf(file, "key ed25519 %s\n", encoded);
	return fclose(file) == 0;
}

bool key_generate(const char *path, char id[APF_KEY_ID_SIZE]) {
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (!context || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_keygen(context, &pkey) != 1) {
		EVP_PKEY_CTX_free(context);
		return false;
	}
	EVP_PKEY_CTX_free(context);
	struct apf_key *key = wrap(pkey);
	if (!key) {
		return false;
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	FILE *file = fd >= 0 ? fdopen(fd, "w") : NULL;
	bool ok = file && PEM_write_PrivateKey(file, key->pkey, NULL, NULL, 0, NULL, NULL) == 1;
	if (file) {
		ok = fclose(file) == 0 && ok;
	} else if (fd >= 0) {
		close(fd);
	}
	char public_path[4096];
	snprintf(public_path, sizeof(public_path), "%s.pub", path);
	ok = ok && write_public(public_path, key->public_key);
	if (ok) {
		memcpy(id, key->id, APF_KEY_ID_SIZE);
	}
	key_free(key);
	return ok;
}

struct apf_key *key_load_private(const char *path) {
	FILE *file = fopen(path, "r");
	if (!file) {
		return NULL;
	}
	EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	fclose(file);
	if (!pkey || EVP_PKEY_get_id(pkey) != EVP_PKEY_ED25519) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return wrap(pkey);
}

void key_free(struct apf_key *key) {
	if (key) {
		EVP_PKEY_free(key->pkey);
		free(key);
	}
}

const char *key_id(const struct apf_key *key) {
	return key->id;
}

/* Parses "key ed25519 BASE64" from the start of text; returns the rest. */
static const char *parse_key_line(const char *text, unsigned char public_key[32]) {
	static const char prefix[] = "key ed25519 ";
	if (strncmp(text, prefix, sizeof(prefix) - 1) != 0) {
		return NULL;
	}
	const char *value = text + sizeof(prefix) - 1;
	size_t length = strcspn(value, "\n");
	if (value[length] != '\n' || !decode(value, length, public_key, 32)) {
		return NULL;
	}
	return value + length + 1;
}

bool key_read_public_id(const char *path, char id[APF_KEY_ID_SIZE]) {
	char text[256] = "";
	FILE *file = fopen(path, "r");
	if (!file) {
		return false;
	}
	size_t length = fread(text, 1, sizeof(text) - 1, file);
	fclose(file);
	text[length] = 0;
	unsigned char public_key[32];
	const char *rest = parse_key_line(text, public_key);
	if (!rest || *rest) {
		return false;
	}
	id_of(public_key, id);
	return true;
}

/* The signed message: the domain, then the content list. */
static unsigned char *message(const char *files, size_t length, size_t *size) {
	size_t domain = sizeof(APF_SIGN_DOMAIN) - 1;
	unsigned char *data = malloc(domain + length);
	if (data) {
		memcpy(data, APF_SIGN_DOMAIN, domain);
		memcpy(data + domain, files, length);
		*size = domain + length;
	}
	return data;
}

char *signature_make(const struct apf_key *key, const char *files, size_t length) {
	size_t size;
	unsigned char *data = message(files, length, &size);
	unsigned char signature[64];
	size_t signature_length = sizeof(signature);
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	bool ok = data && context &&
		EVP_DigestSignInit(context, NULL, NULL, NULL, key->pkey) == 1 &&
		EVP_DigestSign(context, signature, &signature_length, data, size) == 1 &&
		signature_length == 64;
	EVP_MD_CTX_free(context);
	free(data);
	if (!ok) {
		return NULL;
	}
	char public_text[64], signature_text[96];
	encode(key->public_key, 32, public_text);
	encode(signature, 64, signature_text);
	char *text;
	return asprintf(&text, "key ed25519 %s\nsig %s\n", public_text, signature_text) < 0 ? NULL : text;
}

bool signature_check(const char *text, const char *files, size_t length, char id[APF_KEY_ID_SIZE]) {
	unsigned char public_key[32], signature[64];
	const char *rest = parse_key_line(text, public_key);
	if (!rest || strncmp(rest, "sig ", 4) != 0) {
		return false;
	}
	rest += 4;
	size_t signature_length = strcspn(rest, "\n");
	if (rest[signature_length] != '\n' || rest[signature_length + 1] != 0 ||
			!decode(rest, signature_length, signature, 64)) {
		return false;
	}
	EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);
	size_t size;
	unsigned char *data = message(files, length, &size);
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	bool ok = pkey && data && context &&
		EVP_DigestVerifyInit(context, NULL, NULL, NULL, pkey) == 1 &&
		EVP_DigestVerify(context, signature, 64, data, size) == 1;
	EVP_MD_CTX_free(context);
	EVP_PKEY_free(pkey);
	free(data);
	if (ok) {
		id_of(public_key, id);
	}
	return ok;
}
