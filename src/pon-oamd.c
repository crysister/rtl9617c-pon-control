// SPDX-License-Identifier: GPL-2.0-or-later
/* Native OpenWrt EPON OAM management; libuci configuration, AF_PACKET transport. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <uci.h>
#include <unistd.h>
#include "pon-oam.h"
#include "pon-backend.h"
#include "pon-config.h"
#include "pon-events.h"

#ifndef PON_FIRMWARE_VERSION
#error PON_FIRMWARE_VERSION must identify the built firmware
#endif

/* Set by the UCI log_verbose option or toggled by SIGUSR1. */
bool pon_oam_debug;

#define PON_OAM_MAX_LLID 32
#define PON_OAM_INFORMATION_INTERVAL_MS 1000
#define PON_OAM_STATUS_INTERVAL_MS 1000
#define PON_OAM_PEER_TIMEOUT_MS 5000
#define PON_OAM_SELECT_TIMEOUT_US 200000
#define PON_OAM_STATE_PATH_BYTES 512
#define PON_OAM_TEMPORARY_PATH_BYTES 544
#define PON_OAM_STARTTIME_BYTES 32
#define PON_OAM_STATUS_BUFFER_BYTES 4096
#define PON_OAM_DETAIL_BYTES 96

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t verbose_toggle;

static void stop(int signal_number)
{
	(void)signal_number;
	running = 0;
}

static void toggle_verbose(int signal_number)
{
	(void)signal_number;
	verbose_toggle = 1;
}

static const char *auth_name(enum pon_oam_auth auth)
{
	static const char *const names[] = {"waiting", "challenge", "accepted", "rejected"};

	return auth <= PON_AUTH_REJECTED ? names[auth] : "unknown";
}

static const char *discovery_name(const struct pon_oam_session *session)
{
	if (!session->have_peer)
		return "idle";
	if (pon_oam_discovery_complete(session))
		return "stable";
	return "evaluating";
}

/* The driver's serdes attribute is the authoritative live mode, including
 * before /etc/config/pon has been rewritten by the service. */
static void read_mode(char *output, size_t capacity)
{
	char data[512], mode[32] = "unknown";
	FILE *stream = fopen("/sys/bus/platform/devices/4f5500000.pon/serdes", "r");

	if (stream) {
		if (fgets(data, sizeof(data), stream) &&
		    sscanf(data, "mode=%31s", mode) != 1)
			snprintf(mode, sizeof(mode), "unknown");
		fclose(stream);
	}
	snprintf(output, capacity, "%s", mode);
}

static uint64_t boot_ms(void)
{
	struct timespec time;

	clock_gettime(CLOCK_BOOTTIME, &time);
	return (uint64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static int option_copy(struct pon_config *config,
		       const char *key, uint8_t *destination, size_t capacity)
{
	const char *value = pon_config_option(config, key);

	if (!value)
		return 0;
	if (strlen(value) > capacity)
		return -E2BIG;
	memcpy(destination, value, strlen(value));
	return 0;
}

static int identity_load(const char *directory, struct pon_oam_identity *identity)
{
	struct pon_config config = {};
	int ret = pon_config_load(&config, directory);
	unsigned int major, minor, patch;

	if (ret)
		goto done;
	if (sscanf(PON_FIRMWARE_VERSION, "%u.%u.%u", &major, &minor, &patch) != 3 ||
	    major > 255 || minor > 255 || patch > 255) {
		ret = -EINVAL;
		goto done;
	}
	identity->firmware[0] = major;
	identity->firmware[1] = minor;
	identity->firmware[2] = patch;
#define COPY_OPTION(key, member) do { ret = option_copy(&config, key, identity->member, sizeof(identity->member)); if (ret) goto done; } while (0)
	COPY_OPTION("loid", loid);
	COPY_OPTION("loid_password", password);
	COPY_OPTION("vendor_id", vendor);
	COPY_OPTION("oam_model", model);
	COPY_OPTION("equipment_id", equipment);
	COPY_OPTION("hardware_version", hardware);
	COPY_OPTION("software_version", software);
#undef COPY_OPTION
	identity->loid_configured = identity->loid[0] != 0;
done:
	uci_free_context(config.context);
	return ret;
}

static bool config_log_verbose(const char *directory)
{
	struct pon_config config = {};
	const char *value;
	bool enabled = false;

	if (!pon_config_load(&config, directory)) {
		value = pon_config_option(&config, "log_verbose");
		enabled = value && (!strcmp(value, "1") || !strcmp(value, "true") ||
				    !strcmp(value, "on") || !strcmp(value, "yes"));
	}
	uci_free_context(config.context);
	return enabled;
}

static int registered(const char *path, unsigned int llid, bool *online, uint64_t *epoch, bool *holdover)
{
	char data[2048], *token, *save = NULL;
	unsigned int bitmap = 0;
	bool enabled = false, have_bitmap = false, have_epoch = false;
	FILE *stream = fopen(path, "r");

	if (!stream)
		return -errno;
	if (!fgets(data, sizeof(data), stream)) {
		int ret = ferror(stream) ? -EIO : -ENODATA;

		fclose(stream);
		return ret;
	}
	fclose(stream);
	for (token = strtok_r(data, " \n", &save); token; token = strtok_r(NULL, " \n", &save)) {
		if (!strncmp(token, "registered=", 11)) {
			char *end;

			bitmap = strtoul(token + 11, &end, 16);
			have_bitmap = !*end;
		} else if (!strcmp(token, "enabled=1")) {
			enabled = true;
		} else if (!strncmp(token, "holdover=", 9)) {
			*holdover = !!(strtoul(token + 9, NULL, 16) & (1U << llid));
		} else if (!strncmp(token, "epochs=", 7)) {
			char *entry = token + 7, *end;
			unsigned int index;

			for (index = 0; index <= llid; index++) {
				uint64_t value = strtoull(entry, &end, 16);

				if (entry == end || (*end && *end != ','))
					break;
				if (index == llid) {
					*epoch = value;
					have_epoch = true;
					break;
				}
				if (*end != ',')
					break;
				entry = end + 1;
			}
		}
	}
	if (!have_bitmap || !have_epoch)
		return -EPROTO;
	*online = enabled && (bitmap & (1U << llid));
	return 0;
}

static int packet_socket(const char *interface, uint8_t mac[6])
{
	struct ifreq request = {};
	struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(0x8809)};
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x8809));
	int ignore = 1;

	if (fd < 0)
		return -errno;
	strncpy(request.ifr_name, interface, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &request))
		goto error;
	address.sll_ifindex = request.ifr_ifindex;
	if (ioctl(fd, SIOCGIFHWADDR, &request))
		goto error;
	memcpy(mac, request.ifr_hwaddr.sa_data, 6);
	if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore, sizeof(ignore)))
		goto error;
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)))
		goto error;
	return fd;
error:
	ignore = -errno;
	close(fd);
	return ignore;
}

struct oam_nl_frame {
	uint16_t type;
	uint16_t llid;
	uint32_t length;
	uint8_t data[];
} __attribute__((packed));

static int netlink_oam_socket(void)
{
	struct sockaddr_nl local = {.nl_family = AF_NETLINK};
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_USERSOCK);

	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local))) {
		int error = -errno;
		close(fd);
		return error;
	}
	return fd;
}

static int netlink_oam_send(int fd, unsigned int llid, const uint8_t *data, size_t length)
{
	struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
	struct oam_nl_frame *frame;
	struct nlmsghdr *header;
	struct iovec iov;
	struct msghdr message = {.msg_name = &kernel, .msg_namelen = sizeof(kernel)};
	size_t padded = length < 60 ? 60 : length;
	size_t total = NLMSG_HDRLEN + sizeof(*frame) + padded;
	uint8_t *buffer;

	if (fd < 0 || length > 1522)
		return -EINVAL;
	static unsigned int logged;
	if (logged < 3) {
		char dump[512];
		size_t i, used = 0;

		for (i = 0; i < length && used + 4 < sizeof(dump); i++)
			used += snprintf(dump + used, sizeof(dump) - used, "%02x ", data[i]);
		syslog(LOG_INFO, "OAM netlink tx llid=%u len=%zu data=%s", llid, length, dump);
		logged++;
	}
	buffer = calloc(1, total);
	if (!buffer)
		return -ENOMEM;
	header = (struct nlmsghdr *)buffer;
	header->nlmsg_len = total;
	frame = (struct oam_nl_frame *)NLMSG_DATA(header);
	frame->type = 2;
	frame->llid = llid;
	frame->length = padded;
	memcpy(frame->data, data, length);
	iov.iov_base = buffer;
	iov.iov_len = total;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	if (sendmsg(fd, &message, 0) != (ssize_t)total) {
		int error = -errno;
		free(buffer);
		return error;
	}
	free(buffer);
	return 0;
}

static void read_starttime(char output[32])
{
	char data[1024], *position, *token, *save = NULL;
	unsigned int field = 3;
	FILE *stream = fopen("/proc/self/stat", "r");

	if (!stream)
		return;
	position = fgets(data, sizeof(data), stream) ? strrchr(data, ')') : NULL;
	fclose(stream);
	if (!position)
		return;
	for (token = strtok_r(position + 1, " \n", &save); token; token = strtok_r(NULL, " \n", &save), field++)
		if (field == 22) {
			snprintf(output, 32, "%s", token);
			return;
		}
}

static int publish_status(const char *path, const struct pon_oam_session *session,
			 unsigned int llid, int link_error, bool online, unsigned int send_errors,
			 unsigned int receive_errors, bool loid_configured, uint64_t auth_result_ms,
			 const char *starttime, int management_error, const char *mode)
{
	static const char *const auth_sources[] = {"none", "ctc-result", "ctc-set-progress"};
	const char *discovery = discovery_name(session);
	uint64_t duration_ms = pon_oam_auth_duration_ms(session, boot_ms());
	char temporary[PON_OAM_TEMPORARY_PATH_BYTES];
	FILE *stream;
	int ret;

	snprintf(temporary, sizeof(temporary), "%s.%ld", path, (long)getpid());
	stream = fopen(temporary, "w");
	if (!stream)
		return -errno;
	ret = fprintf(stream,
		"{\"pid\":%ld,\"process_start\":\"%s\",\"updated_ms\":%llu,\"mode\":\"%s\","
		"\"llid_index\":%u,\"link_error\":%d,\"registered\":%s,\"have_peer\":%s,"
		"\"generation\":%u,\"discovery_stable\":%s,\"discovery_state\":\"%s\","
		"\"peer_flags\":\"0x%04x\",\"last_information_ms\":%llu,"
		"\"extension_oui\":\"%02x%02x%02x\",\"extension_version\":%u,"
		"\"extension_selected\":%s,\"extension_list_answered\":%s,"
		"\"extension_echo_answered\":%s,\"extension_quiet\":%s,"
		"\"extension_negotiated\":%s,\"loid_configured\":%s,"
		"\"auth_state\":\"%s\",\"auth_failure\":%u,\"auth_challenges\":%u,"
		"\"auth_results\":%u,\"auth_successes\":%u,\"auth_failures\":%u,"
		"\"last_auth_result_ms\":%llu,\"auth_succeeded\":%s,\"auth_success_ms\":%llu,"
		"\"auth_source\":\"%s\",\"auth_mode\":\"%s\",\"auth_set_attributes\":%u,\"auth_result_seen\":%s,"
		"\"auth_duration_ms\":%llu,\"auth_succ_time\":%llu,"
		"\"last_type5_code\":%u,\"last_type5_ms\":%llu,\"provisioning_seen\":%s,"
		"\"rx_frames\":%u,\"tx_frames\":%u,\"send_errors\":%u,"
		"\"receive_errors\":%u,\"management_error\":%d}\n",
		(long)getpid(), starttime, (unsigned long long)boot_ms(), mode,
		llid, link_error, online ? "true" : "false", session->have_peer ? "true" : "false",
		session->generation, pon_oam_discovery_complete(session) ? "true" : "false", discovery,
		(unsigned int)session->peer_flags, (unsigned long long)session->last_information_ms,
		session->extension_oui[0], session->extension_oui[1], session->extension_oui[2],
		(unsigned int)session->extension_version, session->extension_selected ? "true" : "false",
		session->extension_list_answered ? "true" : "false",
		session->extension_echo_answered ? "true" : "false",
		session->extension_quiet ? "true" : "false",
		session->extension_negotiated ? "true" : "false",
		loid_configured ? "true" : "false", auth_name(session->auth),
		session->auth_failure, session->auth_challenges, session->auth_results,
		session->auth_successes, session->auth_failures, (unsigned long long)auth_result_ms,
		session->auth_succeeded ? "true" : "false",
		(unsigned long long)session->auth_success_ms, auth_sources[session->auth_source],
		/* Stock FUN_00416560 + CLI case 0x22: pending/progress flag 0/3
		 * is MAC mode; the explicit-result flag 1 is LOID mode. */
		session->auth_result_seen ? "loid" : "mac",
		session->auth_set_attributes, session->auth_result_seen ? "true" : "false",
		(unsigned long long)duration_ms, (unsigned long long)(duration_ms / 1000),
		session->last_type5_code,
		(unsigned long long)session->last_type5_ms,
		session->provisioning_seen ? "true" : "false",
		session->rx_frames, session->tx_frames, send_errors, receive_errors, management_error);
	if (fclose(stream) || ret < 0) {
		unlink(temporary);
		return -EIO;
	}
	if (rename(temporary, path)) {
		ret = -errno;
		unlink(temporary);
		return ret;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *interface = "pon-oam0", *configuration = "/etc/config";
	const char *mpcp = "/sys/bus/platform/devices/4f5500000.pon/mpcp";
	const char *state_directory = "/var/run/pon-oam";
	struct pon_oam_identity identity = {};
	struct pon_oam_session session = {};
	struct pon_backend backend = {};
	unsigned int llid = 0, send_errors = 0, receive_errors = 0;
	bool online = false, check_config = false, json = false, verbose_option = false;
	bool session_valid = false;
	bool was_holdover = false;
	int fd, nl_fd, lock_fd, ret, option;
	char state_path[PON_OAM_STATE_PATH_BYTES], lock_path[PON_OAM_STATE_PATH_BYTES];
	char starttime[PON_OAM_STARTTIME_BYTES] = {};
	char mode[32] = "unknown";
	uint64_t next_information = 0, next_status = 0, auth_result_ms = 0;
	uint64_t last_received = 0;
	uint64_t line_epoch = 0;
	static const struct option options[] = {
		{"interface", required_argument, NULL, 'i'},
		{"llid-index", required_argument, NULL, 'n'},
		{"config-dir", required_argument, NULL, 'c'},
		{"mpcp-status", required_argument, NULL, 'm'},
		{"state-dir", required_argument, NULL, 's'},
		{"check-config", no_argument, NULL, 't'},
		{"json", no_argument, NULL, 'j'},
		{"verbose", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};

	while ((option = getopt_long(argc, argv, "i:n:c:m:s:tjv", options, NULL)) != -1) {
		switch (option) {
		case 'i': interface = optarg; break;
		case 'n': llid = strtoul(optarg, NULL, 10); break;
		case 'c': configuration = optarg; break;
		case 'm': mpcp = optarg; break;
		case 's': state_directory = optarg; break;
		case 't': check_config = true; break;
		case 'j': json = true; break;
		case 'v': verbose_option = true; break;
		default: return 2;
		}
	}
	if (llid >= PON_OAM_MAX_LLID)
		return 2;
	snprintf(state_path, sizeof(state_path), "%s/llid-%u.json", state_directory, llid);
	read_mode(mode, sizeof(mode));
	if (pon_backend_init(&backend, mpcp))
		return 2;
	backend.llid = llid;
	ret = identity_load(configuration, &identity);
	if (ret) {
		fprintf(stderr, "PON identity configuration failed: %s\n", strerror(-ret));
		return 1;
	}
	if (json) {
		char data[PON_OAM_STATUS_BUFFER_BYTES];
		FILE *stream = fopen(state_path, "r");
		size_t length;

		if (stream) {
			length = fread(data, 1, sizeof(data) - 1, stream);
			fclose(stream);
			data[length] = '\0';
			fputs(data, stdout);
		} else {
			printf("{\"llid_index\":%u,\"running\":false,\"mode\":\"%s\","
			       "\"loid_configured\":%s}\n", llid, mode,
			       identity.loid_configured ? "true" : "false");
		}
		return 0;
	}
	pon_oam_debug = verbose_option || config_log_verbose(configuration);
	if (check_config) {
		printf("{\"loid_configured\":%s,\"loid_bytes\":%zu,\"password_bytes\":%zu,\"hardware_bytes\":%zu,\"software_bytes\":%zu}\n",
			identity.loid_configured ? "true" : "false", strnlen((char *)identity.loid, 24),
			strnlen((char *)identity.password, 12), strnlen((char *)identity.hardware, 16),
			strnlen((char *)identity.software, 16));
		return 0;
	}
	umask(0077);
	if (mkdir(state_directory, 0700) && errno != EEXIST) {
		perror("state directory");
		return 1;
	}
	snprintf(lock_path, sizeof(lock_path), "%s/llid-%u.lock", state_directory, llid);
	lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
	if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB)) {
		perror("OAM instance lock");
		return 1;
	}
	fd = packet_socket(interface, identity.mac);
	if (fd < 0) {
		fprintf(stderr, "OAM interface %s: %s\n", interface, strerror(-fd));
		return 1;
	}
	nl_fd = netlink_oam_socket();
	if (nl_fd < 0)
		fprintf(stderr, "OAM netlink redirect: %s\n", strerror(-nl_fd));
	/* Captured stock OAM frames use the PON base MAC, not the WAN/PPPoE
	 * subinterface MAC or a fixed 00:13:25 endpoint. */
	read_starttime(starttime);
	pon_backend_bind(&identity, &backend);
	signal(SIGTERM, stop);
	signal(SIGINT, stop);
	signal(SIGUSR1, toggle_verbose);
	openlog("pon-oamd", LOG_PID, LOG_DAEMON);
	pon_oam_reset(&session);
	pon_event_append(mode, "oam_start", interface);
	syslog(LOG_NOTICE, "OAM start mode=%s llid=%u verbose=%u", mode, llid, pon_oam_debug);
	while (running) {
		uint8_t input[PON_OAM_FRAME_MAX], output[PON_OAM_FRAME_MAX];
		struct timeval timeout = {.tv_usec = PON_OAM_SELECT_TIMEOUT_US};
		fd_set readable;
		bool now_online = false;
		bool holdover = false;
		uint64_t now = boot_ms();
		uint64_t epoch = 0;
		int link_error = registered(mpcp, llid, &now_online, &epoch, &holdover);

		if (verbose_toggle) {
			verbose_toggle = 0;
			pon_oam_debug = !pon_oam_debug;
			syslog(LOG_NOTICE, "OAM verbose=%u", pon_oam_debug);
		}
		if (link_error)
			now_online = false;
		if (was_holdover && !holdover && now_online && epoch == line_epoch)
			last_received = now;
		was_holdover = holdover;
		if (now_online != online || epoch != line_epoch) {
			pon_oam_reset(&session);
			auth_result_ms = 0;
			session_valid = false;
			last_received = 0;
			online = now_online;
			line_epoch = epoch;
			backend.epoch = epoch;
			next_information = now;
			syslog(LOG_INFO, "LLID%u MPCP registered=%u generation=%u", llid, online, session.generation);
			pon_event_append(mode, "registration", online ? "online" : "offline");
		}
		if (online && !holdover && session_valid && now - last_received >= PON_OAM_PEER_TIMEOUT_MS) {
			pon_oam_reset(&session);
			auth_result_ms = 0;
			session_valid = false;
			syslog(LOG_INFO, "LLID%u OAM peer timeout generation=%u", llid, session.generation);
			pon_event_append(mode, "oam_timeout", "no Information for 5000 ms");
		}
		if (online && now >= next_information) {
			size_t size = pon_oam_information(&session, &identity, output);
			int sent;

			if (pon_oam_debug)
				syslog(LOG_INFO, "OAM send size=%zu peer=%d", size, session.have_peer);
			sent = nl_fd >= 0 ? netlink_oam_send(nl_fd, llid, output, size) : -1;

			if (sent == 0 ||
			    (nl_fd < 0 && send(fd, output, size, 0) == (ssize_t)size))
				pon_oam_information_sent(&session, output);
			else
				send_errors++;
			next_information = now + PON_OAM_INFORMATION_INTERVAL_MS;
		}
		if (now >= next_status) {
			ret = publish_status(state_path, &session, llid, link_error, online, send_errors,
				receive_errors, identity.loid_configured, auth_result_ms, starttime,
				backend.management_error, mode);
			if (ret)
				syslog(LOG_ERR, "LLID%u status publish failed: %s", llid, strerror(-ret));
			next_status = now + PON_OAM_STATUS_INTERVAL_MS;
		}
		FD_ZERO(&readable);
		FD_SET(fd, &readable);
		ret = select(fd + 1, &readable, NULL, NULL, &timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "OAM select failed: %s", strerror(errno));
			break;
		}
		if (ret && FD_ISSET(fd, &readable)) {
			ssize_t size = recv(fd, input, sizeof(input), MSG_DONTWAIT);
			unsigned int results_before = session.auth_results;
			bool peer_before = session.have_peer;
			bool list_before = session.extension_list_answered;
			bool echo_before = session.extension_echo_answered;
			bool provisioning_before = session.provisioning_seen;
			uint16_t peer_flags_before = session.peer_flags;
			enum pon_oam_auth auth_before = session.auth;
			char detail[PON_OAM_DETAIL_BYTES];

			if (size < 0) {
				receive_errors++;
				continue;
			}
			if (!online)
				continue;
			if (pon_oam_debug && size >= 18)
				syslog(LOG_INFO, "OAM rx size=%zd code=%02x flags=%02x%02x",
					size, input[17], input[15], input[16]);
			ret = pon_oam_receive(&session, &identity, input, size, output);
			if (pon_oam_debug && size >= 18 && input[17] == 0xfe)
				syslog(LOG_INFO, "OAM ctc result=%d ext=%d auth=%u",
					ret, session.extension_selected, session.auth);
			if (ret < 0) {
				receive_errors++;
				continue;
			}
			if (ret == PON_OAM_IGNORED)
				continue;
			last_received = boot_ms();
			session_valid = true;
			if (!peer_before && session.have_peer) {
				snprintf(detail, sizeof(detail), "flags=0x%04x",
					 (unsigned int)session.peer_flags);
				pon_event_append(mode, "information_peer", detail);
			} else if (session.peer_flags != peer_flags_before) {
				snprintf(detail, sizeof(detail), "flags=0x%04x",
					 (unsigned int)session.peer_flags);
				pon_event_append(mode, "information_flags", detail);
			}
			if (!list_before && session.extension_list_answered)
				pon_event_append(mode, "ctc_list_answered", "capability list sent once");
			if (!echo_before && session.extension_echo_answered) {
				snprintf(detail, sizeof(detail), "version=0x%02x",
					 (unsigned int)session.extension_version);
				pon_event_append(mode, "ctc_echo_answered", detail);
			}
			if (auth_before != session.auth)
				pon_event_append(mode, "auth_state", auth_name(session.auth));
			if (!provisioning_before && session.provisioning_seen)
				pon_event_append(mode, "provisioning_seen", "CTC GET/SET");
			if (ret > PON_OAM_HANDLED) {
				int sent = nl_fd >= 0 ? netlink_oam_send(nl_fd, llid, output, ret) : -1;

				if (sent == 0 ||
				    (nl_fd < 0 && send(fd, output, ret, 0) == ret))
					session.tx_frames++;
				else
					send_errors++;
			} else if (size >= 18 && input[17] == 0) {
				next_information = boot_ms();
			}
			if (session.auth_results != results_before) {
				auth_result_ms = boot_ms();
				syslog(LOG_INFO, "LLID%u subscriber_auth result=%u failure=%u generation=%u",
					llid, session.auth, session.auth_failure, session.generation);
			}
			next_status = 0;
		}
	}
	pon_oam_reset(&session);
	pon_event_append(mode, "oam_stop", "daemon exiting");
	unlink(state_path);
	if (close(fd))
		syslog(LOG_WARNING, "OAM socket close: %s", strerror(errno));
	if (close(lock_fd))
		syslog(LOG_WARNING, "OAM lock close: %s", strerror(errno));
	closelog();
	return running ? 1 : 0;
}
