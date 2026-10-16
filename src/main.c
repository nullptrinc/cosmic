/* SPDX-License-Identifier: MIT */
/* cosmic: Starry's package manager for .apf applications. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apf.h"

static void usage(void) {
	fprintf(stderr,
		"usage: cosmic keygen KEY              new Ed25519 key in KEY and KEY.pub\n"
		"       cosmic pack DIR OUT.apf -k KEY...  build and sign a package\n"
		"       cosmic sign APP.apf -k KEY...      add signatures\n"
		"       cosmic verify APP.apf              check a package and show it\n"
		"       cosmic install APP.apf\n"
		"       cosmic remove ID\n"
		"       cosmic list\n");
	exit(2);
}

/* Loads the -k KEY arguments from argv[first] on. */
static int load_keys(int argc, char **argv, int first, struct apf_key **keys) {
	int count = 0;
	for (int i = first; i < argc; i++) {
		if (strcmp(argv[i], "-k") != 0 || i + 1 >= argc || count >= APF_MAX_SIGNATURES) {
			usage();
		}
		keys[count] = key_load_private(argv[++i]);
		if (!keys[count]) {
			cosmic_say("%s: not an Ed25519 private key\n", argv[i]);
			exit(1);
		}
		count++;
	}
	if (count == 0) {
		usage();
	}
	return count;
}

static int verify(const char *path) {
	struct apf_package package;
	char error[512];
	if (!apf_read(path, -1, &package, error, sizeof(error))) {
		cosmic_say("%s: %s\n", path, error);
		return 1;
	}
	const struct apf_manifest *m = &package.manifest;
	printf("%s %s (build %ld, api %ld)\n", m->id, m->version, m->build, m->api);
	printf("name: %s\n", manifest_name(m, getenv("LANG")));
	printf("entry: %s %s\n", m->entry_type, m->entry_path);
	printf("files: %d\n", package.file_count);
	for (int i = 0; i < package.signer_count; i++) {
		printf("signed by %s\n", package.signers[i]);
	}
	apf_package_free(&package);
	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage();
	}
	const char *command = argv[1];
	struct apf_key *keys[APF_MAX_SIGNATURES];
	if (strcmp(command, "keygen") == 0 && argc == 3) {
		char id[APF_KEY_ID_SIZE];
		if (!key_generate(argv[2], id)) {
			cosmic_say("cannot write %s (it must not exist yet)\n", argv[2]);
			return 1;
		}
		printf("%s\n", id);
		return 0;
	}
	if (strcmp(command, "pack") == 0 && argc >= 6) {
		int count = load_keys(argc, argv, 4, keys);
		bool ok = apf_pack(argv[2], keys, count, argv[3]);
		for (int i = 0; i < count; i++) {
			key_free(keys[i]);
		}
		return ok ? 0 : 1;
	}
	if (strcmp(command, "sign") == 0 && argc >= 5) {
		int count = load_keys(argc, argv, 3, keys);
		bool ok = apf_sign(argv[2], keys, count);
		for (int i = 0; i < count; i++) {
			key_free(keys[i]);
		}
		return ok ? 0 : 1;
	}
	if (strcmp(command, "verify") == 0 && argc == 3) {
		return verify(argv[2]);
	}
	if (strcmp(command, "install") == 0 && argc == 3) {
		return cosmic_install(argv[2]) ? 0 : 1;
	}
	if (strcmp(command, "remove") == 0 && argc == 3) {
		return cosmic_remove(argv[2]) ? 0 : 1;
	}
	if (strcmp(command, "list") == 0 && argc == 2) {
		return cosmic_list() ? 0 : 1;
	}
	usage();
}
