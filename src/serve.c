/* SPDX-License-Identifier: MIT */
/*
 * cosmic serve: keeps the app registry in Constellation. Every installed
 * app is published as /blinks/apps/<id>:
 *
 *     name::Phone   name.ru::Телефон   color::#27AE60   icon::/data/cosmic/apps/<id>/...
 *     icon.dark::...  icon.tinted::...  icon.clear::...   (the appearances the app has)
 *     entry::qml    path::/data/cosmic/apps/<id>/qml/main.qml
 *     version::1.0  build:n:3          uid:n:10000      platform:b:false
 *
 * The broker lets only root write there; starboard shows these apps and
 * starry-launchd starts them from it. Installs and removals are noticed
 * through inotify on state/apps; a restarted broker gets everything again.
 *
 * Constellation's wire protocol is spoken directly (one SOCK_SEQPACKET
 * message per request, see constellationd.c), so cosmic needs no library.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "apf.h"

#define REGISTRY "/blinks/apps/"
#define MESSAGE_MAX 16384
#define VALUE_MAX 207 /* the broker's limit, without the terminator */
#define RETRY_MSEC 2000

/* What was last published for an app, to remove attributes that went away. */
struct published {
	char id[APF_ID_MAX + 1];
	char keys[1024]; /* "\n"-separated attribute names */
};

static int broker = -1;
static struct published *published;
static int published_count;
static volatile sig_atomic_t running = 1;

static int broker_connect(void) {
	const char *path = getenv("CONSTELLATION_SOCKET");
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	snprintf(address.sun_path, sizeof(address.sun_path), "%s",
		path && path[0] ? path : "/run/constellation.sock");
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd >= 0 && connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		close(fd);
		fd = -1;
	}
	return fd;
}

static void broker_lost(void) {
	if (broker >= 0) {
		close(broker);
		broker = -1;
	}
	published_count = 0;
}

/* Sends a request and returns its reply (starting with "="), or NULL. */
static const char *request(const char *text, size_t length) {
	static char reply[MESSAGE_MAX + 1];
	if (broker < 0 || send(broker, text, length, MSG_NOSIGNAL) != (ssize_t)length) {
		broker_lost();
		return NULL;
	}
	for (;;) {
		struct pollfd pfd = { .fd = broker, .events = POLLIN };
		if (poll(&pfd, 1, 2000) <= 0) {
			broker_lost();
			return NULL;
		}
		ssize_t received = recv(broker, reply, MESSAGE_MAX, 0);
		if (received <= 0) {
			broker_lost();
			return NULL;
		}
		reply[received] = 0;
		if (reply[0] == '=') {
			return reply;
		}
	}
}

/* Appends "name:type:value\n", the value cut to the broker's limit on a
 * character boundary and kept to one line. */
static void add_attr(char *text, size_t size, size_t *length, char *keys, size_t keys_size,
		const char *name, const char *type, const char *value) {
	char clean[VALUE_MAX + 1];
	size_t n = 0;
	for (const char *c = value; *c && n < VALUE_MAX; c++) {
		clean[n++] = *c == '\n' || *c == '\r' ? ' ' : *c;
	}
	while (n > 0 && value[n] && ((unsigned char)value[n] & 0xc0) == 0x80) {
		n--; /* do not end inside a UTF-8 sequence */
	}
	clean[n] = 0;
	*length += (size_t)snprintf(text + *length, size - *length, "%s:%s:%s\n", name, type, clean);
	size_t used = strlen(keys);
	snprintf(keys + used, keys_size - used, "%s\n", name);
}

static bool valid_locale(const char *locale) {
	size_t length = strlen(locale);
	return length > 0 && length <= 16 &&
		strspn(locale, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == length;
}

static struct published *find_published(const char *id, bool create) {
	for (int i = 0; i < published_count; i++) {
		if (strcmp(published[i].id, id) == 0) {
			return &published[i];
		}
	}
	if (!create) {
		return NULL;
	}
	struct published *grown = realloc(published, (size_t)(published_count + 1) * sizeof(*published));
	if (!grown) {
		return NULL;
	}
	published = grown;
	struct published *entry = &published[published_count++];
	snprintf(entry->id, sizeof(entry->id), "%s", id);
	entry->keys[0] = 0;
	return entry;
}

static void publish(const char *id) {
	char path[PATH_MAX], text[MESSAGE_MAX], keys[1024] = "", error[256];
	struct cosmic_state state;
	if (!apf_valid_id(id) || !cosmic_read_state(id, &state)) {
		return;
	}
	snprintf(path, sizeof(path), "%s/apps/%s/manifest.json", cosmic_root(), id);
	struct json_object *json = json_object_from_file(path);
	const char *serialized = json ? json_object_to_json_string(json) : NULL;
	struct apf_manifest manifest;
	if (!serialized || !manifest_parse(serialized, strlen(serialized), &manifest, error, sizeof(error))) {
		cosmic_say("%s: %s\n", id, serialized ? error : "no manifest");
		json_object_put(json);
		return;
	}
	json_object_put(json);

	size_t length = (size_t)snprintf(text, sizeof(text), "set " REGISTRY "%s\n", id);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "name", "", manifest_name(&manifest, NULL));
	struct json_object *names;
	if (json_object_object_get_ex(manifest.json, "name", &names)) {
		json_object_object_foreach(names, locale, value) {
			char key[48];
			if (valid_locale(locale) && strcmp(locale, "en") != 0) {
				snprintf(key, sizeof(key), "name.%s", locale);
				add_attr(text, sizeof(text), &length, keys, sizeof(keys), key, "",
					json_object_get_string(value));
			}
		}
	}
	if (manifest.color[0]) {
		add_attr(text, sizeof(text), &length, keys, sizeof(keys), "color", "", manifest.color);
	}
	for (int i = 0; i < APF_ICON_STYLES; i++) {
		if (manifest.icons[i][0]) {
			char key[32];
			if (i == 0) {
				snprintf(key, sizeof(key), "icon");
			} else {
				snprintf(key, sizeof(key), "icon.%s", apf_icon_styles[i]);
			}
			snprintf(path, sizeof(path), "%s/apps/%s/%s", cosmic_root(), id, manifest.icons[i]);
			add_attr(text, sizeof(text), &length, keys, sizeof(keys), key, "", path);
		}
	}
	snprintf(path, sizeof(path), "%s/apps/%s/%s", cosmic_root(), id, manifest.entry_path);
	if (strlen(path) > VALUE_MAX) {
		cosmic_say("%s: entry path too long for the registry\n", id);
		manifest_free(&manifest);
		return;
	}
	char number[32];
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "entry", "", manifest.entry_type);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "path", "", path);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "version", "", manifest.version);
	snprintf(number, sizeof(number), "%ld", manifest.build);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "build", "n", number);
	snprintf(number, sizeof(number), "%ld", state.uid);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "uid", "n", number);
	add_attr(text, sizeof(text), &length, keys, sizeof(keys), "platform", "b",
		state.platform ? "true" : "false");
	manifest_free(&manifest);

	/* Attributes the app no longer has, such as a dropped translation. */
	struct published *before = find_published(id, true);
	char current[sizeof(keys) + 1];
	snprintf(current, sizeof(current), "\n%s", keys);
	for (char *key = before ? before->keys : NULL; key && *key;) {
		char *end = strchr(key, '\n');
		char needle[64];
		snprintf(needle, sizeof(needle), "\n%.*s\n", (int)(end - key), key);
		if (!strstr(current, needle) && length + (size_t)(end - key) + 3 < sizeof(text)) {
			length += (size_t)snprintf(text + length, sizeof(text) - length, "-%.*s\n",
				(int)(end - key), key);
		}
		key = end + 1;
	}
	const char *reply = request(text, length);
	if (reply && strncmp(reply, "=ok", 3) == 0) {
		if (before) {
			snprintf(before->keys, sizeof(before->keys), "%s", keys);
		}
		printf("published %s\n", id);
	} else if (reply) {
		cosmic_say("broker refused %s: %s", id, reply + 1);
	}
	fflush(stdout);
}

static void unpublish(const char *id) {
	char text[256];
	int length = snprintf(text, sizeof(text), "del " REGISTRY "%s\n", id);
	if (request(text, (size_t)length)) {
		printf("removed %s\n", id);
		fflush(stdout);
	}
	struct published *entry = find_published(id, false);
	if (entry) {
		*entry = published[--published_count];
	}
}

/* "<id>.json" -> id, or false for anything else (temporary files included). */
static bool state_name(const char *name, char *id, size_t size) {
	size_t length = strlen(name);
	if (length < 6 || strcmp(name + length - 5, ".json") != 0 || length - 5 >= size) {
		return false;
	}
	snprintf(id, size, "%.*s", (int)(length - 5), name);
	return apf_valid_id(id);
}

/* Publishes every installed app and drops registry entries of removed ones. */
static void publish_all(const char *state_dir) {
	DIR *dir = opendir(state_dir);
	for (struct dirent *entry; dir && (entry = readdir(dir));) {
		char id[APF_ID_MAX + 1];
		if (state_name(entry->d_name, id, sizeof(id))) {
			publish(id);
		}
	}
	if (dir) {
		closedir(dir);
	}
	const char *reply = request("list " REGISTRY "\n", strlen("list " REGISTRY "\n"));
	if (!reply || strncmp(reply, "=list", 5) != 0) {
		return;
	}
	char listing[MESSAGE_MAX + 1];
	snprintf(listing, sizeof(listing), "%s", reply);
	for (char *line = strchr(listing, '\n'); line && line[1];) {
		char *path = line + 1;
		line = strchr(path, '\n');
		if (line) {
			*line = 0;
		}
		const char *id = path + strlen(REGISTRY);
		struct cosmic_state state;
		if (strncmp(path, REGISTRY, strlen(REGISTRY)) == 0 && !cosmic_read_state(id, &state)) {
			unpublish(id);
		}
		if (!line) {
			break;
		}
	}
}

static void on_signal(int number) {
	running = 0;
}

int cosmic_serve(void) {
	struct sigaction action = { .sa_handler = on_signal };
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	char state_dir[PATH_MAX];
	snprintf(state_dir, sizeof(state_dir), "%s/state/apps", cosmic_root());
	if (!cosmic_prepare()) { /* a fresh /data has no layout yet */
		return 1;
	}
	int notify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (notify < 0 || inotify_add_watch(notify, state_dir,
			IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE) < 0) {
		cosmic_say("cannot watch %s: %s\n", state_dir, strerror(errno));
		return 1;
	}
	while (running) {
		if (broker < 0 && (broker = broker_connect()) >= 0) {
			publish_all(state_dir);
		}
		struct pollfd fds[2] = {
			{ .fd = notify, .events = POLLIN },
			{ .fd = broker, .events = POLLIN }, /* -1 is skipped */
		};
		if (poll(fds, 2, broker < 0 ? RETRY_MSEC : -1) < 0) {
			continue;
		}
		if (fds[1].revents) {
			char ignored[MESSAGE_MAX];
			ssize_t received = recv(broker, ignored, sizeof(ignored), MSG_DONTWAIT);
			if (received == 0 || (received < 0 && errno != EAGAIN && errno != EINTR)) {
				broker_lost(); /* constellationd restarted; publish again */
			}
		}
		if (fds[0].revents & POLLIN) {
			char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
			ssize_t length;
			while ((length = read(notify, buffer, sizeof(buffer))) > 0) {
				for (char *p = buffer; p < buffer + length;) {
					struct inotify_event *event = (struct inotify_event *)p;
					char id[APF_ID_MAX + 1];
					if (event->len && state_name(event->name, id, sizeof(id))) {
						if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
							unpublish(id);
						} else {
							publish(id);
						}
					}
					p += sizeof(*event) + event->len;
				}
			}
		}
	}
	close(notify);
	broker_lost();
	return 0;
}
