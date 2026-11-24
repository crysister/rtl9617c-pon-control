// SPDX-License-Identifier: GPL-2.0-or-later
/* Aggregate the EPON OAM and ITU OMCI status documents plus the driver's
 * PLOAM/MPCP state into one stable JSON view for field scripts.  This tool
 * only reads published state; it never opens a PON provider or transacts
 * protocol messages. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pon-events.h"

#define PON_SYSFS "/sys/bus/platform/devices/4f5500000.pon/"
#define PON_OAM_STATE_DIR "/var/run/pon-oam"
#define PON_IDENTITY_STATUS "/var/run/pon-identity.json"
#define PON_OMCI_STATUS_JSON "/var/run/pon-omci.json"
#define PON_STATUS_DOCUMENT_BYTES 4096
#define PON_STATUS_LLIDS 32
#define PON_STATUS_EVENT_LINES 64

struct llid_document {
	unsigned int index;
	char path[320];
};

static ssize_t read_document(const char *path, char *output, size_t capacity)
{
	ssize_t length;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -errno;
	length = read(fd, output, capacity - 1);
	if (close(fd) && length >= 0)
		return -EIO;
	if (length < 0)
		return -errno;
	while (length && (output[length - 1] == '\n' || output[length - 1] == '\r'))
		output[--length] = '\0';
	output[length] = '\0';
	return length;
}

static bool read_attribute(const char *name, char *output, size_t capacity)
{
	char path[256];

	snprintf(path, sizeof(path), PON_SYSFS "%s", name);
	return read_document(path, output, capacity) >= 0;
}

static void read_mode(char *output, size_t capacity)
{
	char serdes[512], mode[32] = "unknown";

	output[0] = '\0';
	if (read_attribute("serdes", serdes, sizeof(serdes)))
		sscanf(serdes, "mode=%31s", mode);
	snprintf(output, capacity, "%s", mode);
}

static int compare_llid(const void *left, const void *right)
{
	const struct llid_document *a = left, *b = right;

	if (a->index < b->index)
		return -1;
	if (a->index > b->index)
		return 1;
	return 0;
}

static unsigned int collect_llids(struct llid_document *documents, unsigned int capacity)
{
	struct dirent *entry;
	DIR *directory = opendir(PON_OAM_STATE_DIR);
	unsigned int count = 0;

	if (!directory)
		return 0;
	while ((entry = readdir(directory)) && count < capacity) {
		unsigned int index;
		char tail;

		if (sscanf(entry->d_name, "llid-%u.json%c", &index, &tail) != 1)
			continue;
		documents[count].index = index;
		snprintf(documents[count].path, sizeof(documents[count].path),
			 "%s/%s", PON_OAM_STATE_DIR, entry->d_name);
		count++;
	}
	closedir(directory);
	qsort(documents, count, sizeof(*documents), compare_llid);
	return count;
}

/* Emit a document as a JSON value, or null when it is absent.  The producer
 * already writes JSON; this guard only prevents a truncated file from making
 * the aggregate document invalid. */
static void print_document(const char *text, ssize_t length)
{
	bool object = false;

	if (length <= 1) {
		fputs("null", stdout);
		return;
	}
	if (text[0] == '{') {
		if (text[length - 1] == '}')
			object = true;
		else if (text[length - 1] == '\n' && text[length - 2] == '}')
			object = true;
	}
	if (!object) {
		fputs("null", stdout);
		return;
	}
	fwrite(text, 1, (size_t)length, stdout);
}

static void print_llids(const struct llid_document *documents, unsigned int count)
{
	char data[PON_STATUS_DOCUMENT_BYTES] = {};
	unsigned int index;

	fputs("[", stdout);
	for (index = 0; index < count; index++) {
		ssize_t length = read_document(documents[index].path, data, sizeof(data));

		if (index)
			fputc(',', stdout);
		if (length <= 0) {
			printf("{\"llid_index\":%u,\"available\":false}", documents[index].index);
			continue;
		}
		print_document(data, length);
	}
	fputs("]", stdout);
}

static void print_json_string(const char *text)
{
	const unsigned char *cursor = (const unsigned char *)text;

	fputc(0x22, stdout);
	for (; *cursor; cursor++) {
		unsigned char value = *cursor;

		if (value == 0x22 || value == 0x5c) {
			fputc(0x5c, stdout);
			fputc(value, stdout);
		} else if (value == 0x0a) {
			fputc(0x5c, stdout);
			fputc('n', stdout);
		} else if (value == 0x0d) {
			fputc(0x5c, stdout);
			fputc('r', stdout);
		} else if (value == 0x09) {
			fputc(0x5c, stdout);
			fputc('t', stdout);
		} else if (value < 0x20) {
			printf("%c" "u%04x", 0x5c, value);
		} else {
			fputc(value, stdout);
		}
	}
	fputc(0x22, stdout);
}

static void print_string_or_null(const char *text)
{
	if (!text[0])
		fputs("null", stdout);
	else
		print_json_string(text);
}

static void print_events_array(void)
{
	char data[PON_EVENTS_MAX_BYTES], *line, *save = NULL;
	unsigned int count = 0;

	ssize_t length = pon_events_read(data, sizeof(data));

	fputs("[", stdout);
	if (length > 0) {
		for (line = strtok_r(data, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
			size_t line_length = strlen(line);

			if (line_length < 2 || line[0] != '{' || line[line_length - 1] != '}')
				continue;
			if (count++)
				fputc(',', stdout);
			fputs(line, stdout);
			if (count >= PON_STATUS_EVENT_LINES)
				break;
		}
	}
	fputs("]", stdout);
}

static bool token_value(const char *text, const char *key, char *output, size_t capacity)
{
	size_t key_length = strlen(key);
	const char *position = text;

	output[0] = '\0';
	while (position && *position) {
		const char *end;

		while (*position == ' ' || *position == '\n' || *position == '\t')
			position++;
		end = position;
		while (*end && *end != ' ' && *end != '\n' && *end != '\t')
			end++;
		if ((size_t)(end - position) > key_length &&
		    !strncmp(position, key, key_length) && position[key_length] == '=') {
			size_t length = (size_t)(end - position) - key_length - 1;

			if (length >= capacity)
				length = capacity - 1;
			memcpy(output, position + key_length + 1, length);
			output[length] = '\0';
			return true;
		}
		position = *end ? end + 1 : end;
	}
	return false;
}

static const char *json_value(const char *document, const char *key)
{
	char pattern[64];
	const char *position;

	snprintf(pattern, sizeof(pattern), "\"%s\":", key);
	position = strstr(document, pattern);
	if (!position)
		return NULL;
	position += strlen(pattern);
	while (*position == ' ')
		position++;
	return position;
}

static bool json_number(const char *document, const char *key, unsigned long long *value)
{
	const char *position = json_value(document, key);
	char *end;

	if (!position || !*position || *position == 'n')
		return false;
	*value = strtoull(position, &end, 10);
	return end != position;
}

static bool json_bool(const char *document, const char *key, bool *value)
{
	const char *position = json_value(document, key);

	if (!position)
		return false;
	if (!strncmp(position, "true", 4)) {
		*value = true;
		return true;
	}
	if (!strncmp(position, "false", 5)) {
		*value = false;
		return true;
	}
	return false;
}

static bool json_string(const char *document, const char *key, char *output, size_t capacity)
{
	const char *position = json_value(document, key);
	const char *end;
	size_t length;

	if (!position || *position != '"')
		return false;
	position++;
	end = strchr(position, '"');
	if (!end)
		return false;
	length = (size_t)(end - position);
	if (length >= capacity)
		length = capacity - 1;
	memcpy(output, position, length);
	output[length] = '\0';
	return true;
}

static void print_number_token(const char *text, const char *key)
{
	char value[64];

	if (token_value(text, key, value, sizeof(value)))
		fputs(value, stdout);
	else
		fputs("null", stdout);
}

static void print_json_number(const char *document, const char *key)
{
	unsigned long long value;

	if (json_number(document, key, &value))
		printf("%llu", value);
	else
		fputs("null", stdout);
}

static void print_json_bool(const char *document, const char *key)
{
	bool value;

	if (json_bool(document, key, &value))
		fputs(value ? "true" : "false", stdout);
	else
		fputs("null", stdout);
}

/* Stable top-level protocol fields: EPON fills mpcp_*, ITU fills ploam_* and
 * omci_*; fields that do not apply are null rather than a healthy-looking 0. */
static void print_summary(const char *mode, const char *mpcp, const char *mac,
			  const char *activation, const char *omci)
{
	char value[64];
	bool epon = !strncmp(mode, "epon", 4);

	fputs("{\"mpcp_registered\":", stdout);
	if (epon && token_value(mpcp, "registered", value, sizeof(value))) {
		print_json_string(value);
	} else {
		fputs("null", stdout);
	}
	fputs(",\"mpcp_enabled\":", stdout);
	if (epon)
		print_number_token(mpcp, "enabled");
	else
		fputs("null", stdout);
	fputs(",\"ploam_state\":", stdout);
	if (!epon && token_value(mac, "activation", value, sizeof(value)))
		print_json_string(value);
	else if (!epon && token_value(activation, "activation", value, sizeof(value)))
		print_json_string(value);
	else
		fputs("null", stdout);
	fputs(",\"onu_id\":", stdout);
	if (!epon && token_value(mac, "onu_id", value, sizeof(value)))
		fputs(value, stdout);
	else if (!epon && token_value(activation, "omcc_onu_id", value, sizeof(value)))
		fputs(value, stdout);
	else
		fputs("null", stdout);
	fputs(",\"omcc\":", stdout);
	if (!epon && token_value(mac, "omcc", value, sizeof(value)))
		fputs(value, stdout);
	else if (!epon && token_value(activation, "omcc", value, sizeof(value)))
		fputs(value, stdout);
	else
		fputs("null", stdout);
	fputs(",\"ploam_rx\":", stdout);
	if (!epon)
		print_number_token(mac, "rx");
	else
		fputs("null", stdout);
	fputs(",\"ploam_tx\":", stdout);
	if (!epon)
		print_number_token(mac, "tx");
	else
		fputs("null", stdout);
	fputs(",\"omci_rx\":", stdout);
	if (!epon)
		print_json_number(omci, "omci_rx");
	else
		fputs("null", stdout);
	fputs(",\"omci_tx\":", stdout);
	if (!epon)
		print_json_number(omci, "omci_tx");
	else
		fputs("null", stdout);
	fputs(",\"omci_invalid\":", stdout);
	if (!epon)
		print_json_number(omci, "omci_invalid");
	else
		fputs("null", stdout);
	fputs(",\"omci_last_error\":", stdout);
	if (!epon && json_string(omci, "last_error", value, sizeof(value)))
		print_json_string(value);
	else
		fputs("null", stdout);
	fputs(",\"pon_omci_link_up\":", stdout);
	if (!epon)
		print_json_bool(omci, "pon_omci_link_up");
	else
		fputs("null", stdout);
	fputc('}', stdout);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: pon-status [--json|--text] [--events] [--clear-events]\n"
		"       pon-status --event <name> [detail]\n");
}

int main(int argc, char **argv)
{
	struct llid_document documents[PON_STATUS_LLIDS];
	char mode[32] = "unknown", state[1024] = {}, led[512] = {}, serdes[512] = {};
	char mpcp[512] = {}, activation[512] = {}, mac[1024] = {};
	char identity[PON_STATUS_DOCUMENT_BYTES] = {}, omci[PON_STATUS_DOCUMENT_BYTES] = {};
	unsigned int llid_count;
	ssize_t identity_length, omci_length;
	bool text = false;

	if (argc >= 3 && !strcmp(argv[1], "--event")) {
		char event_mode[32];
		int ret;

		read_mode(event_mode, sizeof(event_mode));
		ret = pon_event_append(event_mode, argv[2], argc > 3 ? argv[3] : "");
		if (ret)
			return 1;
		printf("{\"logged\":true}\n");
		return 0;
	}
	for (int index = 1; index < argc; index++) {
		if (!strcmp(argv[index], "--json")) {
			text = false;
		} else if (!strcmp(argv[index], "--text")) {
			text = true;
		} else if (!strcmp(argv[index], "--events")) {
			char data[PON_EVENTS_MAX_BYTES];

			if (pon_events_read(data, sizeof(data)) > 0)
				fputs(data, stdout);
			return 0;
		} else if (!strcmp(argv[index], "--clear-events")) {
			if (pon_events_clear())
				return 1;
			printf("{\"cleared\":true}\n");
			return 0;
		} else {
			usage();
			return 2;
		}
	}
	read_mode(mode, sizeof(mode));
	read_attribute("state", state, sizeof(state));
	read_attribute("led_state", led, sizeof(led));
	read_attribute("serdes", serdes, sizeof(serdes));
	read_attribute("mpcp", mpcp, sizeof(mpcp));
	read_attribute("activation", activation, sizeof(activation));
	read_attribute("mac", mac, sizeof(mac));
	identity_length = read_document(PON_IDENTITY_STATUS, identity, sizeof(identity));
	omci_length = read_document(PON_OMCI_STATUS_JSON, omci, sizeof(omci));
	llid_count = collect_llids(documents, PON_STATUS_LLIDS);
	if (text) {
		printf("mode=%s\nstate=%s\nled_state=%s\nllid_count=%u\n",
		       mode, state, led, llid_count);
		printf("identity=%s\n", identity_length > 0 ? identity : "null");
		printf("omci=%s\n", omci_length > 0 ? omci : "null");
		return 0;
	}
	printf("{\"ts_ms\":%llu,\"mode\":\"%s\",\"driver\":{",
	       (unsigned long long)pon_wall_ms(), mode);
	fputs("\"state\":", stdout);
	print_string_or_null(state);
	fputs(",\"led_state\":", stdout);
	print_string_or_null(led);
	fputs(",\"serdes\":", stdout);
	print_string_or_null(serdes);
	fputs(",\"mpcp\":", stdout);
	print_string_or_null(mpcp);
	fputs(",\"activation\":", stdout);
	print_string_or_null(activation);
	fputs(",\"mac\":", stdout);
	print_string_or_null(mac);
	fputs("},", stdout);
	fputs("\"summary\":", stdout);
	print_summary(mode, mpcp, mac, activation, omci);
	fputs(",", stdout);
	if (!strncmp(mode, "epon", 4)) {
		printf("\"epon\":{\"llid_count\":%u,\"llids\":", llid_count);
		print_llids(documents, llid_count);
		fputs("},\"itu\":null,", stdout);
	} else {
		fputs("\"epon\":null,\"itu\":{\"identity\":", stdout);
		print_document(identity, identity_length);
		fputs(",\"omci\":", stdout);
		print_document(omci, omci_length);
		fputs("},", stdout);
	}
	fputs("\"events\":", stdout);
	print_events_array();
	printf(",\"events_path\":\"%s\"}\n", PON_EVENTS_PATH);
	return 0;
}