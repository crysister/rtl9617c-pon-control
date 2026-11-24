// SPDX-License-Identifier: GPL-2.0-only
/* OMCI transport and UCI identity for the native RTL9617C ITU backend. */
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "pon-config.h"
#include "pon-events.h"
#include "pon-omci.h"

#define PON_SYSFS "/sys/bus/platform/devices/4f5500000.pon/"
#define PON_OMCI_STATUS "/var/run/pon-omci"
#define PON_OMCI_STATUS_JSON "/var/run/pon-omci.json"
#define PON_OMCI_RESTARTS "/var/run/pon-omci.restarts"
#define PON_OMCI_INTERFACE "pon-omci"
#define PON_OMCI_POLL_MS 1000
#define PON_OMCI_TYPE_MASK 0x1f
#define PON_OMCI_TYPE_MIB_UPLOAD 0x0d
#define PON_OMCI_TYPE_MIB_UPLOAD_NEXT 0x0e
#define PON_OMCI_TYPE_AVC 0x11
#define PON_OMCI_BASELINE_HEADER_BYTES 4
#define PON_OMCI_EXTENDED_DEVICE_ID 0x0b
#define PON_OMCI_CLASS332_SET_TYPE 0x08
#define PON_OMCI_CLASS332_ID_HIGH 0x01
#define PON_OMCI_CLASS332_ID_LOW 0x4c
#define PON_OMCI_CLASS332_MASK_BASELINE 8
#define PON_OMCI_CLASS332_MASK_EXTENDED 10
#define PON_OMCI_BROADCAST_BYTES 18
#define PON_OMCI_PATHS_HEADER_BYTES 12
#define PON_OMCI_MSK_BYTES 16
#define PON_OMCI_MSK_HEX_BYTES (PON_OMCI_MSK_BYTES * 2)
#define PON_OMCI_MSK_TEXT_BYTES (PON_OMCI_MSK_HEX_BYTES + 1)
#define PON_OMCI_FRAME_MAX 2048
#define PON_OMCI_STATUS_DOCUMENT_BYTES 4096
#define PON_OMCI_PATH_BYTES 512
#define PON_OMCI_MAC_BYTES 1024
#define PON_OMCI_DETAIL_BYTES 96

#ifndef PON_FIRMWARE_VERSION
#error PON_FIRMWARE_VERSION must identify the built firmware
#endif
#define PON_OMCI_STARTTIME_BYTES 32
#define PATH_BYTES (12 + 248 * 50 + 248 * 5 * (32 + 32 * 16) + 31 * 12)

/* Per-message OMCI diagnostics are opt-in; state transitions stay logged. */
static volatile sig_atomic_t verbose;

static void toggle_verbose(int signal_number)
{
	(void)signal_number;
	verbose = !verbose;
}

static int put_file(const char *path, const void *data, size_t length)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC), result;
	ssize_t written;
	size_t offset = 0;

	if (fd < 0) return -errno;
	result = 0;
	while (offset < length) {
		written = write(fd, (const uint8_t *)data + offset, length - offset);
		if (written <= 0) { result = written < 0 ? -errno : -EIO; break; }
		offset += written;
	}
	close(fd);
	return result;
}

static void identity_field(struct pon_config *config, const char *name, const char *default_value,
	uint8_t *output, size_t width)
{
	const char *value = pon_config_option(config, name);

	if (!value || !value[0]) value = default_value;
	memcpy(output, value, strnlen(value, width));
}

/* Driver state is the authoritative PLOAM/OMCC source; the daemon must not
 * reimplement the ITU state machine.  These helpers only project the sysfs
 * attributes into a stable snake_case status document. */
struct omci_business {
	uint8_t applied[PATH_BYTES];
	int length, error;
};

struct omci_observation {
	unsigned long long mib_upload;
	unsigned long long mib_upload_next;
	unsigned long long avc;
	unsigned long long restarts;
	unsigned int last_rx_type;
	unsigned int last_tx_type;
	unsigned int last_rx_tid;
	unsigned int last_tx_tid;
	char last_error[64];
};

static void read_path(const char *path, char *output, size_t capacity)
{
	FILE *stream;
	size_t length;

	output[0] = '\0';
	stream = fopen(path, "r");
	if (!stream)
		return;
	length = fread(output, 1, capacity - 1, stream);
	fclose(stream);
	output[length] = '\0';
	while (length && (output[length - 1] == '\n' || output[length - 1] == '\r'))
		output[--length] = '\0';
}

static void read_attribute(const char *name, char *output, size_t capacity)
{
	char path[256];

	snprintf(path, sizeof(path), PON_SYSFS "%s", name);
	read_path(path, output, capacity);
}

/* Find "key=value" in a space-separated driver line.  Empty means absent;
 * callers emit null rather than a zero that could be mistaken for healthy. */
static bool attribute_token(const char *text, const char *key, char *output, size_t capacity)
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

static void current_protocol(char *output, size_t capacity)
{
	char mac[1024];

	read_attribute("mac", mac, sizeof(mac));
	if (!attribute_token(mac, "protocol", output, capacity))
		snprintf(output, capacity, "unknown");
}

static unsigned int omci_message_type(const uint8_t *frame, size_t length)
{
	if (length < PON_OMCI_BASELINE_HEADER_BYTES)
		return 0xff;
	return frame[2] & PON_OMCI_TYPE_MASK;
}

static unsigned int omci_transaction_id(const uint8_t *frame, size_t length)
{
	if (length < 2)
		return 0;
	return (unsigned int)frame[0] << 8 | frame[1];
}

/* Procd respawns this daemon after a transport failure; keep the count in a
 * side file because the status file is unlinked on exit. */
static unsigned long long omci_restarts(void)
{
	char value[32] = "0", *end;
	unsigned long long restarts;
	int fd = open(PON_OMCI_RESTARTS, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	ssize_t length;

	if (fd < 0)
		return 0;
	flock(fd, LOCK_EX);
	length = read(fd, value, sizeof(value) - 1);
	if (length > 0)
		value[length] = '\0';
	restarts = strtoull(value, &end, 10);
	if (end == value)
		restarts = 0;
	restarts++;
	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);
	length = snprintf(value, sizeof(value), "%llu\n", restarts);
	if (length <= 0 || write(fd, value, (size_t)length) != length)
		restarts = 0;
	flock(fd, LOCK_UN);
	if (close(fd))
		restarts = 0;
	return restarts;
}

static void publish_status_json(const struct omci_observation *observation, const char *starttime,
	unsigned long long received, unsigned long long transmitted, unsigned long long invalid,
	const struct omci_business *business, unsigned long long session, unsigned int auth)
{
	char activation[PON_OMCI_PATH_BYTES], mac[PON_OMCI_MAC_BYTES];
	char state[PON_OMCI_PATH_BYTES], data_path[PON_OMCI_PATH_BYTES];
	char protocol[32] = "unknown", ploam_state[32], onu_id[32], omcc[32];
	char omcc_onu_id[32], ploam_rx[32], ploam_tx[32], mic_errors[32];
	char operstate[PON_OMCI_STARTTIME_BYTES] = "unknown";
	char temporary[PON_OMCI_PATH_BYTES];
	bool link_up;
	struct timespec now;
	FILE *stream;
	int error = 0;

	read_attribute("activation", activation, sizeof(activation));
	read_attribute("mac", mac, sizeof(mac));
	read_attribute("state", state, sizeof(state));
	read_attribute("data_path", data_path, sizeof(data_path));
	attribute_token(mac, "protocol", protocol, sizeof(protocol));
	attribute_token(mac, "activation", ploam_state, sizeof(ploam_state));
	attribute_token(mac, "onu_id", onu_id, sizeof(onu_id));
	attribute_token(mac, "omcc", omcc, sizeof(omcc));
	attribute_token(mac, "omcc_onu_id", omcc_onu_id, sizeof(omcc_onu_id));
	/* XG-PON exposes OMCC identity in activation, GPON in mac.  Fall back
	 * so the same field is populated on both families. */
	if (!omcc[0])
		attribute_token(activation, "omcc", omcc, sizeof(omcc));
	if (!omcc_onu_id[0])
		attribute_token(activation, "omcc_onu_id", omcc_onu_id, sizeof(omcc_onu_id));
	if (!onu_id[0])
		attribute_token(activation, "omcc_onu_id", onu_id, sizeof(onu_id));
	attribute_token(mac, "rx", ploam_rx, sizeof(ploam_rx));
	attribute_token(mac, "tx", ploam_tx, sizeof(ploam_tx));
	attribute_token(mac, "mic_errors", mic_errors, sizeof(mic_errors));
	read_path("/sys/class/net/" PON_OMCI_INTERFACE "/operstate",
		   operstate, sizeof(operstate));
	link_up = if_nametoindex(PON_OMCI_INTERFACE) && strcmp(operstate, "down");
	clock_gettime(CLOCK_BOOTTIME, &now);
	snprintf(temporary, sizeof(temporary), "%s.%ld", PON_OMCI_STATUS_JSON, (long)getpid());
	stream = fopen(temporary, "w");
	if (!stream)
		return;
	if (fprintf(stream,
		"{\"pid\":%ld,\"process_start\":\"%s\",\"updated_ms\":%llu,"
		"\"mode\":\"%s\",\"onu_id\":%s,\"ploam_state\":%s,\"omcc\":%s,"
		"\"omcc_onu_id\":%s,\"ploam_rx\":%s,\"ploam_tx\":%s,"
		"\"ploam_mic_errors\":%s,\"pon_omci_link_up\":%s,"
		"\"omci_rx\":%llu,\"omci_tx\":%llu,\"omci_invalid\":%llu,"
		"\"last_rx_type\":%u,\"last_rx_tid\":%u,"
		"\"last_tx_type\":%u,\"last_tx_tid\":%u,\"last_error\":\"%s\","
		"\"mib_upload\":%llu,\"mib_upload_next\":%llu,\"avc\":%llu,"
		"\"restarts\":%llu,\"paths\":%u,\"paths_error\":%d,"
		"\"session\":%llu,\"auth\":%u,\"driver_state\":\"%s\","
		"\"driver_activation\":\"%s\",\"driver_mac\":\"%s\",\"data_path\":\"%s\"}\n",
		(long)getpid(), starttime,
		(unsigned long long)now.tv_sec * 1000 + now.tv_nsec / 1000000,
		protocol,
		onu_id[0] ? onu_id : "null", ploam_state[0] ? ploam_state : "null",
		omcc[0] ? omcc : "null", omcc_onu_id[0] ? omcc_onu_id : "null",
		ploam_rx[0] ? ploam_rx : "null", ploam_tx[0] ? ploam_tx : "null",
		mic_errors[0] ? mic_errors : "null", link_up ? "true" : "false",
		received, transmitted, invalid, observation->last_rx_type,
		observation->last_rx_tid, observation->last_tx_type, observation->last_tx_tid,
		observation->last_error[0] ? observation->last_error : "none",
		observation->mib_upload, observation->mib_upload_next, observation->avc,
		observation->restarts,
		business->length >= 12 ? business->applied[2] | (unsigned int)business->applied[3] << 8 : 0,
		business->error, session, auth, state, activation, mac, data_path) < 0)
		error = EIO;
	if (fclose(stream) && !error) error = errno;
	if (!error && rename(temporary, PON_OMCI_STATUS_JSON)) error = errno;
	if (error) unlink(temporary);
}

static int load_identity(struct omci_identity *identity)
{
	struct pon_config config = {};
	FILE *serial;
	unsigned int i;
	int result = pon_config_load(&config, "/etc/config");

	if (result) goto out;
	const char *version = pon_config_option(&config, "omcc_version");
	const char *disable_security = pon_config_option(&config, "disable_enhanced_security");
	identity->omcc_version = 0xb0;
	if (version && version[0]) {
		if (!strcmp(version, "0x86")) identity->omcc_version = 0x86;
		else if (strcmp(version, "0xb0")) { result = -EINVAL; goto out; }
	}
	if (disable_security && disable_security[0] && strcmp(disable_security, "0") && strcmp(disable_security, "1")) {
		result = -EINVAL; goto out;
	}
	identity->disable_enhanced_security = disable_security && !strcmp(disable_security, "1");
	serial = fopen(PON_SYSFS "active_serial_number", "r");
	if (!serial) { result = -errno; goto out; }
	for (i = 0; i < 8; i++)
		if (fscanf(serial, "%2hhx", &identity->serial[i]) != 1) { result = -EINVAL; break; }
	fclose(serial);
	identity_field(&config, "equipment_id", "", identity->equipment, sizeof(identity->equipment));
	identity_field(&config, "hardware_version", "RTL9617C", identity->hardware, sizeof(identity->hardware));
	identity_field(&config, "software_version", PON_FIRMWARE_VERSION, identity->software, sizeof(identity->software));
	identity_field(&config, "loid", "", identity->loid, sizeof(identity->loid));
	identity_field(&config, "loid_password", "", identity->password, sizeof(identity->password));
	identity_field(&config, "operator_id", "CTC", identity->operator_id, sizeof(identity->operator_id));
	const char *psk = pon_config_option(&config, "omci_psk");
	if (psk && psk[0]) {
		if (strlen(psk) != 32) { result = -EINVAL; goto out; }
		for (i = 0; i < 32; i++) if (!isxdigit((unsigned char)psk[i])) { result = -EINVAL; goto out; }
		for (i = 0; i < 16; i++)
			if (sscanf(psk + i * 2, "%2hhx", &identity->psk[i]) != 1) { result = -EINVAL; goto out; }
		identity->has_psk = 1;
	}
out:
	uci_free_context(config.context);
	return result;
}

static bool config_log_verbose(void)
{
	struct pon_config config = {};
	const char *value;
	bool enabled = false;

	if (!pon_config_load(&config, "/etc/config")) {
		value = pon_config_option(&config, "log_verbose");
		enabled = value && (!strcmp(value, "1") || !strcmp(value, "true") ||
				    !strcmp(value, "on") || !strcmp(value, "yes"));
	}
	uci_free_context(config.context);
	return enabled;
}

static unsigned int paths_configured(unsigned long long *session)
{
	FILE *status = fopen(PON_SYSFS "data_path", "r");
	unsigned int ready = 0, count;
	unsigned long long epoch;
	int error;

	if (!status) return 0;
	if (fscanf(status, "configured=%u error=%d epoch=%llu paths=%u session=%llu",
	    &ready, &error, &epoch, &count, session) != 5) ready = 0;
	fclose(status);
	return ready;
}

static int read_starttime(char output[32])
{
	char data[1024], *position, *token, *save = NULL;
	unsigned int field = 3;
	FILE *stream = fopen("/proc/self/stat", "r");

	if (!stream) return -errno;
	position = fgets(data, sizeof(data), stream) ? strrchr(data, ')') : NULL;
	fclose(stream);
	if (!position) return -EINVAL;
	for (token = strtok_r(position + 1, " \n", &save); token;
	     token = strtok_r(NULL, " \n", &save), field++) {
		if (field == 22) {
			snprintf(output, 32, "%s", token);
			return 0;
		}
	}
	return -EINVAL;
}

static int publish_status(const char *path, const char *starttime,
	unsigned long long received, unsigned long long transmitted, unsigned long long invalid,
	const struct omci_business *business, unsigned long long session, unsigned int auth)
{
	struct timespec now;
	char temporary[512];
	FILE *stream;
	int error = 0;

	clock_gettime(CLOCK_BOOTTIME, &now);
	snprintf(temporary, sizeof(temporary), "%s.%ld", path, (long)getpid());
	stream = fopen(temporary, "w");
	if (!stream) return -errno;
	if (fprintf(stream, "pid=%ld process_start=%s updated_ms=%llu rx=%llu tx=%llu invalid=%llu paths=%u error=%d session=%llu auth=%u\n",
	    (long)getpid(), starttime, (unsigned long long)now.tv_sec * 1000 + now.tv_nsec / 1000000,
	    received, transmitted, invalid,
	    business->length >= 12 ? business->applied[2] | (unsigned int)business->applied[3] << 8 : 0,
	    business->error, session, auth) < 0) error = errno;
	if (fclose(stream) && !error) error = errno;
	if (!error && rename(temporary, path)) error = errno;
	if (error) unlink(temporary);
	return -error;
}

static int apply_paths(void *context, const uint8_t *paths, size_t length)
{
	struct omci_business *business = context;
	unsigned long long session;
	unsigned int ready = paths_configured(&session);
	int result = 0;

	if (length != (size_t)business->length || memcmp(paths, business->applied, length) ||
	    ((paths[2] || paths[3]) && !ready)) {
		result = put_file(PON_SYSFS "itu_paths", paths, length);
		if (!result) {
			memcpy(business->applied, paths, length);
			business->length = length;
		} else if (result != -EAGAIN) fprintf(stderr, "OMCI business mapping: %s\n", strerror(-result));
	}
	business->error = result;
	return result;
}

int main(int argc, char **argv)
{
	struct omci_identity identity = {};
	struct omci_agent *agent;
	struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL)};
	uint8_t input[PON_OMCI_FRAME_MAX], output[PON_OMCI_FRAME_MAX];
	uint8_t key[PON_OMCI_MSK_BYTES];
	static uint8_t paths[PATH_BYTES];
	static struct omci_business business;
	struct omci_observation observation = {};
	unsigned long long session = 0, previous_session = 0, received = 0, transmitted = 0, invalid = 0;
	int fd, enabled = 1, result;
	struct pollfd pollfd;
	char starttime[PON_OMCI_STARTTIME_BYTES], mode[32] = "unknown";
	char detail[PON_OMCI_DETAIL_BYTES];
	bool verbose_option = false;

	if (argc == 2 && !strcmp(argv[1], "--verbose"))
		verbose_option = true;
	if (argc == 2 && !strcmp(argv[1], "--json")) {
		char data[PON_OMCI_STATUS_DOCUMENT_BYTES];
		FILE *stream = fopen(PON_OMCI_STATUS_JSON, "r");
		size_t length;

		if (!stream) {
			printf("{\"running\":false,\"mode\":null}\n");
			return 0;
		}
		length = fread(data, 1, sizeof(data) - 1, stream);
		fclose(stream);
		data[length] = '\0';
		fputs(data, stdout);
		return 0;
	}
	if (argc != 1 && !(argc == 2 && verbose_option)) {
		fprintf(stderr, "Usage: pon-omcid [--json|--verbose]\n");
		return 2;
	}
	openlog("pon-omcid", LOG_PID, LOG_DAEMON);
	signal(SIGUSR1, toggle_verbose);
	verbose = verbose_option || config_log_verbose();
	result = read_starttime(starttime);
	if (result) { fprintf(stderr, "OMCI process identity: %s\n", strerror(-result)); return 1; }
	current_protocol(mode, sizeof(mode));
	observation.restarts = omci_restarts();
	pon_event_append(mode, "omci_start", "daemon starting");
	result = load_identity(&identity);
	if (result) { fprintf(stderr, "OMCI identity: %s\n", strerror(-result)); return 1; }
	agent = rtl9617c_omci_new(&identity);
	if (!agent) {
		fprintf(stderr, "OMCI agent allocation failed\n");
		return 1;
	}
	memset(&identity, 0, sizeof(identity));
	fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (fd < 0) { perror("OMCI socket"); rtl9617c_omci_free(agent); return 1; }
	address.sll_ifindex = if_nametoindex(PON_OMCI_INTERFACE);
	if (!address.sll_ifindex) { perror(PON_OMCI_INTERFACE); close(fd); rtl9617c_omci_free(agent); return 1; }
	if (bind(fd, (struct sockaddr *)&address, sizeof(address))) {
		perror("OMCI bind"); close(fd); rtl9617c_omci_free(agent); return 1;
	}
	setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enabled, sizeof(enabled));
	pollfd = (struct pollfd){.fd = fd, .events = POLLIN};
	for (;;) {
		paths_configured(&session);
		int length;

		if (session != previous_session) {
			rtl9617c_omci_epoch(agent);
			snprintf(detail, sizeof(detail), "session=%llu", session);
			pon_event_append(mode, "omci_session", detail);
			previous_session = session;
		}
		length = rtl9617c_omci_paths(agent, paths, sizeof(paths));
		if (length < 0) {
			/* A rejected graph must not leave its previous business mapping active. */
			static const uint8_t empty[12] = {4, 0, 0, 0, 0, 0, 0, 0, 12};
			result = business.length ? apply_paths(&business, empty, sizeof(empty)) : 0;
			if (!result) business.length = 0;
			business.error = result ? result : length;
		} else if (length >= 12) apply_paths(&business, paths, length);
		result = publish_status(PON_OMCI_STATUS, starttime, received, transmitted, invalid,
			&business, session, rtl9617c_omci_led_auth(agent));
		if (result) syslog(LOG_ERR, "OMCI status publish failed: %s", strerror(-result));
		publish_status_json(&observation, starttime, received, transmitted, invalid,
			&business, session, rtl9617c_omci_led_auth(agent));
		result = poll(&pollfd, 1, PON_OMCI_POLL_MS);
		if (result < 0) { if (errno == EINTR) continue; break; }
		if (!result) continue;
		length = recv(fd, input, sizeof(input), 0);
		if (length < 0) { if (errno == EINTR || errno == ENETDOWN) continue; break; }
		received++;
		if (received == 1)
			pon_event_append(mode, "omci_rx_first", "first OMCI frame received");
		observation.last_rx_type = omci_message_type(input, (size_t)length);
		observation.last_rx_tid = omci_transaction_id(input, (size_t)length);
		if (verbose)
			syslog(LOG_INFO, "OMCI rx type=0x%02x tid=0x%04x len=%d",
			       observation.last_rx_type, observation.last_rx_tid, length);
		switch (observation.last_rx_type) {
		case PON_OMCI_TYPE_MIB_UPLOAD:
			observation.mib_upload++;
			break;
		case PON_OMCI_TYPE_MIB_UPLOAD_NEXT:
			observation.mib_upload_next++;
			break;
		case PON_OMCI_TYPE_AVC:
			observation.avc++;
			break;
		default:
			break;
		}
		uint8_t broadcast[PON_OMCI_BROADCAST_BYTES];
		bool security_set = length >= PON_OMCI_PATHS_HEADER_BYTES &&
			(input[2] & PON_OMCI_TYPE_MASK) == PON_OMCI_CLASS332_SET_TYPE &&
			input[4] == PON_OMCI_CLASS332_ID_HIGH &&
			input[5] == PON_OMCI_CLASS332_ID_LOW;
		unsigned int mask_offset = input[3] == PON_OMCI_EXTENDED_DEVICE_ID ?
			PON_OMCI_CLASS332_MASK_EXTENDED : PON_OMCI_CLASS332_MASK_BASELINE;
		struct timespec security_received, security_replied;
		int backend_result = 0;
		if (security_set) clock_gettime(CLOCK_MONOTONIC, &security_received);
		if (rtl9617c_omci_broadcast(agent, input, length, broadcast))
			backend_result = put_file(PON_SYSFS "omci_broadcast", broadcast, sizeof(broadcast));
		length = rtl9617c_omci_dispatch_apply(agent, input, length, output, &backend_result,
			apply_paths, &business);
		if (backend_result < 0) {
			business.error = backend_result;
			snprintf(observation.last_error, sizeof(observation.last_error),
				 "backend=%d", backend_result);
		}
		if (length < 0) {
			invalid++;
			snprintf(observation.last_error, sizeof(observation.last_error), "invalid");
			continue;
		}
		result = send(fd, output, length, 0);
		int send_error = result < 0 ? errno : 0;
		if (result >= 0) {
			observation.last_tx_type = omci_message_type(output, (size_t)length);
			observation.last_tx_tid = omci_transaction_id(output, (size_t)length);
			if (verbose)
				syslog(LOG_INFO, "OMCI tx type=0x%02x tid=0x%04x len=%d",
				       observation.last_tx_type, observation.last_tx_tid, length);
			if (observation.last_tx_type == PON_OMCI_TYPE_AVC)
				observation.avc++;
		} else {
			snprintf(observation.last_error, sizeof(observation.last_error),
				 "send=%d", send_error);
			pon_event_append(mode, "omci_send_error", observation.last_error);
		}
		if (security_set) {
			clock_gettime(CLOCK_MONOTONIC, &security_replied);
			syslog(LOG_INFO, "Class332 SET rx=%lld.%09ld tx=%lld.%09ld tid=%02x%02x mask=%02x%02x backend=%d response=%u sent=%d",
				(long long)security_received.tv_sec, security_received.tv_nsec,
				(long long)security_replied.tv_sec, security_replied.tv_nsec,
				input[0], input[1], input[mask_offset], input[mask_offset + 1],
				backend_result, output[output[3] == 0x0b ? 10 : 8], send_error ? -send_error : result);
		}
		if (result < 0) { if (send_error == ENETDOWN) continue; break; }
		transmitted++;
		/* The response uses the current IK; a completed Class332 exchange installs the next MSK. */
		if (rtl9617c_omci_session_key(agent, key)) {
			char text[PON_OMCI_MSK_TEXT_BYTES];
			for (unsigned int i = 0; i < 16; i++) snprintf(text + i * 2, 3, "%02x", key[i]);
			result = put_file(PON_SYSFS "omci_msk", text, 32);
			clock_gettime(CLOCK_MONOTONIC, &security_replied);
			syslog(LOG_INFO, "Class332 MSK time=%lld.%09ld result=%d",
				(long long)security_replied.tv_sec, security_replied.tv_nsec, result);
			rtl9617c_omci_key_complete(agent, !result);
			memset(key, 0, sizeof(key));
		}
		while ((length = rtl9617c_omci_notification(agent, output)) > 0) {
			if (send(fd, output, length, 0) < 0) break;
			transmitted++;
			observation.last_tx_type = omci_message_type(output, (size_t)length);
			observation.last_tx_tid = omci_transaction_id(output, (size_t)length);
			if (verbose)
				syslog(LOG_INFO, "OMCI tx type=0x%02x tid=0x%04x len=%d",
				       observation.last_tx_type, observation.last_tx_tid, length);
			if (observation.last_tx_type == PON_OMCI_TYPE_AVC)
				observation.avc++;
		}
	}
	perror("OMCI transport");
	if (close(fd))
		syslog(LOG_WARNING, "OMCI socket close: %s", strerror(errno));
	rtl9617c_omci_free(agent);
	unlink(PON_OMCI_STATUS);
	unlink(PON_OMCI_STATUS_JSON);
	return 1;
}
