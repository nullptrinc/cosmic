/* SPDX-License-Identifier: MIT */
#include <ctype.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include "apf.h"

static const char *get_string(struct json_object *object, const char *key) {
	struct json_object *value;
	return json_object_object_get_ex(object, key, &value) &&
		json_object_is_type(value, json_type_string) ? json_object_get_string(value) : NULL;
}

static bool get_int(struct json_object *object, const char *key, long *out) {
	struct json_object *value;
	if (!json_object_object_get_ex(object, key, &value) || !json_object_is_type(value, json_type_int)) {
		return false;
	}
	*out = (long)json_object_get_int64(value);
	return true;
}

static bool copy(char *target, size_t size, const char *value) {
	if (!value || strlen(value) >= size) {
		return false;
	}
	memcpy(target, value, strlen(value) + 1);
	return true;
}

#define FAIL(...) do { snprintf(error, error_size, __VA_ARGS__); manifest_free(manifest); return false; } while (0)

bool manifest_parse(const char *text, size_t length, struct apf_manifest *manifest,
		char *error, size_t error_size) {
	memset(manifest, 0, sizeof(*manifest));
	struct json_tokener *tokener = json_tokener_new();
	manifest->json = json_tokener_parse_ex(tokener, text, (int)length);
	bool complete = json_tokener_get_error(tokener) == json_tokener_success &&
		json_tokener_get_parse_end(tokener) == length;
	json_tokener_free(tokener);
	struct json_object *json = manifest->json;
	if (!json || !complete || !json_object_is_type(json, json_type_object)) {
		FAIL("manifest.json is not a JSON object");
	}
	long format;
	if (!get_int(json, "format", &format) || format != APF_FORMAT) {
		FAIL("manifest format must be %d", APF_FORMAT);
	}
	if (!copy(manifest->id, sizeof(manifest->id), get_string(json, "id")) ||
			!apf_valid_id(manifest->id)) {
		FAIL("manifest id must be reverse-DNS, like org.example.app");
	}
	if (!copy(manifest->version, sizeof(manifest->version), get_string(json, "version")) ||
			!manifest->version[0]) {
		FAIL("manifest version is missing or too long");
	}
	if (!get_int(json, "build", &manifest->build) || manifest->build < 1) {
		FAIL("manifest build must be an integer of at least 1");
	}
	if (!get_int(json, "api", &manifest->api) || manifest->api < 1) {
		FAIL("manifest api must be an integer of at least 1");
	}
	struct json_object *names;
	if (!json_object_object_get_ex(json, "name", &names) ||
			!json_object_is_type(names, json_type_object) || !get_string(names, "en")) {
		FAIL("manifest name needs at least an \"en\" string");
	}
	json_object_object_foreach(names, locale, name) {
		if (!json_object_is_type(name, json_type_string) || strlen(locale) > 16) {
			FAIL("manifest name.%s must be a string", locale);
		}
	}
	struct json_object *entry;
	if (!json_object_object_get_ex(json, "entry", &entry) ||
			!copy(manifest->entry_type, sizeof(manifest->entry_type), get_string(entry, "type")) ||
			(strcmp(manifest->entry_type, "qml") != 0 && strcmp(manifest->entry_type, "native") != 0)) {
		FAIL("manifest entry.type must be \"qml\" or \"native\"");
	}
	if (!copy(manifest->entry_path, sizeof(manifest->entry_path), get_string(entry, "path")) ||
			!apf_valid_path(manifest->entry_path)) {
		FAIL("manifest entry.path must be a path in the package");
	}
	const char *icon = get_string(json, "icon");
	if (icon && (!copy(manifest->icon, sizeof(manifest->icon), icon) || !apf_valid_path(icon))) {
		FAIL("manifest icon must be a path in the package");
	}
	const char *color = get_string(json, "color");
	if (color) {
		bool ok = strlen(color) == 7 && color[0] == '#';
		for (int i = 1; ok && i < 7; i++) {
			ok = isxdigit((unsigned char)color[i]);
		}
		if (!ok) {
			FAIL("manifest color must be #RRGGBB");
		}
		copy(manifest->color, sizeof(manifest->color), color);
	}
	struct json_object *permissions;
	if (json_object_object_get_ex(json, "permissions", &permissions)) {
		if (!json_object_is_type(permissions, json_type_array)) {
			FAIL("manifest permissions must be an array of strings");
		}
		for (size_t i = 0; i < json_object_array_length(permissions); i++) {
			if (!json_object_is_type(json_object_array_get_idx(permissions, i), json_type_string)) {
				FAIL("manifest permissions must be an array of strings");
			}
		}
	}
	return true;
}

void manifest_free(struct apf_manifest *manifest) {
	if (manifest->json) {
		json_object_put(manifest->json);
		manifest->json = NULL;
	}
}

const char *manifest_name(const struct apf_manifest *manifest, const char *locale) {
	struct json_object *names;
	json_object_object_get_ex(manifest->json, "name", &names);
	char language[17] = "";
	if (locale) {
		/* "ru_RU.UTF-8" -> "ru_RU", then "ru". */
		snprintf(language, sizeof(language), "%.*s", (int)strcspn(locale, ".@"), locale);
		const char *name = get_string(names, language);
		if (name) {
			return name;
		}
		language[strcspn(language, "_")] = 0;
		name = get_string(names, language);
		if (name) {
			return name;
		}
	}
	return get_string(names, "en");
}
