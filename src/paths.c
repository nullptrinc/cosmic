/* SPDX-License-Identifier: MIT */
#include <string.h>
#include "apf.h"

static bool path_char(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-';
}

bool apf_valid_path(const char *path) {
	size_t length = strlen(path);
	if (length == 0 || length >= APF_PATH_MAX) {
		return false;
	}
	const char *component = path;
	for (const char *c = path;; c++) {
		if (*c == '/' || *c == 0) {
			size_t size = (size_t)(c - component);
			if (size == 0 || (size == 1 && component[0] == '.') ||
					(size == 2 && component[0] == '.' && component[1] == '.')) {
				return false;
			}
			if (*c == 0) {
				return true;
			}
			component = c + 1;
		} else if (!path_char(*c)) {
			return false;
		}
	}
}

bool apf_valid_id(const char *id) {
	size_t length = strlen(id);
	if (length == 0 || length > APF_ID_MAX) {
		return false;
	}
	int labels = 0;
	const char *label = id;
	for (const char *c = id;; c++) {
		if (*c == '.' || *c == 0) {
			if (c == label || !(label[0] >= 'a' && label[0] <= 'z') || c[-1] == '-') {
				return false;
			}
			labels++;
			if (*c == 0) {
				return labels >= 2;
			}
			label = c + 1;
		} else if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-')) {
			return false;
		}
	}
}
