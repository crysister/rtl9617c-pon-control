// SPDX-License-Identifier: GPL-2.0-or-later
/* Apply the selected ITU protocol's identity to its native MAC interface. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <uci.h>
#include "pon-config.h"
#include "pon-events.h"
#include "pon-sha256.h"

#define PON_SYSFS "/sys/bus/platform/devices/4f5500000.pon/"
#define PON_IDENTITY_STATUS "/var/run/pon-identity.json"
#define PON_IDENTITY_BYTES 44
#define PON_IDENTITY_SERIAL_BYTES 8
#define PON_IDENTITY_VENDOR_PREFIX_BYTES 4
#define PON_IDENTITY_VENDOR_SERIAL_BYTES 12
#define PON_IDENTITY_HEX_SERIAL_BYTES 16
#define PON_IDENTITY_GPON_PASSWORD_BYTES 10
#define PON_IDENTITY_XGPON_PASSWORD_BYTES 36

static int hex_digit(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

static int serial_decode(const char *text, uint8_t output[PON_IDENTITY_SERIAL_BYTES])
{
	size_t length = strlen(text), offset;
	unsigned int i;

	if (length != PON_IDENTITY_VENDOR_SERIAL_BYTES &&
	    length != PON_IDENTITY_HEX_SERIAL_BYTES)
		return -EINVAL;
	offset = length == PON_IDENTITY_VENDOR_SERIAL_BYTES ?
		PON_IDENTITY_VENDOR_PREFIX_BYTES : 0;
	if (offset) {
		for (i = 0; i < offset; i++)
			if ((unsigned char)text[i] < 0x20 || (unsigned char)text[i] > 0x7e)
				return -EINVAL;
		memcpy(output, text, offset);
	}
	for (i = offset; i < PON_IDENTITY_SERIAL_BYTES; i++) {
		int high = hex_digit(text[offset + (i - offset) * 2]);
		int low = hex_digit(text[offset + (i - offset) * 2 + 1]);

		if (high < 0 || low < 0)
			return -EINVAL;
		output[i] = high * 16 + low;
	}
	return 0;
}

static bool read_text(const char *path, char *output, size_t capacity)
{
	char *end;
	FILE *stream = fopen(path, "r");

	if (!stream)
		return false;
	if (!fgets(output, capacity, stream)) {
		fclose(stream);
		return false;
	}
	fclose(stream);
	end = strpbrk(output, "\r\n");
	if (end)
		*end = '\0';
	return true;
}

static void redact(const char *value, size_t length, char prefix[5], char digest[9])
{
	uint8_t bytes[4] = {};
	size_t copy = length < sizeof(bytes) ? length : sizeof(bytes);

	prefix[0] = '\0';
	digest[0] = '\0';
	if (!value || !length)
		return;
	memcpy(bytes, value, copy);
	snprintf(prefix, 5, "%02x%02x", bytes[0], bytes[1]);
	pon_sha256_prefix8(value, length, digest);
}

static void publish_status(const char *mode, const char *serial, size_t serial_length,
			   const char *serial_source, const char *password_field,
			   const char *password, size_t password_length, const char *password_source,
			   const char *identity_file, bool write_ok, const char *error, bool emit)
{
	char serial_prefix[5], serial_digest[9], password_prefix[5], password_digest[9];
	char temporary[256], json[2048];
	FILE *stream;
	int length;

	redact(serial, serial_length, serial_prefix, serial_digest);
	redact(password, password_length, password_prefix, password_digest);
	length = snprintf(json, sizeof(json),
		"{\"pid\":%ld,\"updated_ms\":%llu,\"mode\":\"%s\","
		"\"serial_len\":%zu,\"serial_prefix\":\"%s\",\"serial_sha256_8\":\"%s\","
		"\"serial_source\":\"%s\",\"password_field\":\"%s\",\"password_len\":%zu,"
		"\"password_prefix\":\"%s\",\"password_sha256_8\":\"%s\","
		"\"password_source\":\"%s\",\"identity_file\":\"%s\","
		"\"write_ok\":%s,\"error\":\"%s\"}\n",
		(long)getpid(), (unsigned long long)pon_wall_ms(), mode,
		serial_length, serial_prefix, serial_digest, serial_source,
		password_field, password_length, password_prefix, password_digest,
		password_source, identity_file, write_ok ? "true" : "false",
		error ? error : "");
	if (length < 0 || (size_t)length >= sizeof(json))
		return;
	if (emit)
		fputs(json, stdout);
	snprintf(temporary, sizeof(temporary), "%s.%ld", PON_IDENTITY_STATUS, (long)getpid());
	stream = fopen(temporary, "w");
	if (!stream)
		return;
	if (fwrite(json, 1, length, stream) != (size_t)length) {
		fclose(stream);
		unlink(temporary);
		return;
	}
	if (fclose(stream) || rename(temporary, PON_IDENTITY_STATUS))
		unlink(temporary);
}

int main(int argc, char **argv)
{
	struct pon_config config = {};
	uint8_t identity[PON_IDENTITY_BYTES] = {};
	char mode[32], factory_serial[64], detail[160];
	const char *password, *password_field, *serial_source = "argument";
	const char *uci_serial;
	size_t length, password_size = PON_IDENTITY_GPON_PASSWORD_BYTES;
	int fd, error, result = 1;
	bool emit = false, write_ok = false;
	const char *write_error = NULL;

	if (argc != 4 && !(argc == 5 && !strcmp(argv[4], "--json"))) {
		fprintf(stderr, "Usage: pon-identity <identity-file> <serial> <mode> [--json]\n");
		return 2;
	}
	emit = argc == 5;
	if (serial_decode(argv[2], identity)) {
		fprintf(stderr, "PON serial must be VVVVXXXXXXXX or 16 hex digits\n");
		return 2;
	}
	error = pon_config_load(&config, "/etc/config");
	if (error) {
		fprintf(stderr, "PON configuration load: %s\n", strerror(-error));
		goto out;
	}
	snprintf(mode, sizeof(mode), "%s", argv[3]);
	if (!strcmp(mode, "xgpon") || !strcmp(mode, "xgspon")) {
		password_size = PON_IDENTITY_XGPON_PASSWORD_BYTES;
		password_field = "registration_id";
	} else {
		password_field = "ploam_password";
	}
	password = pon_config_option(&config, password_field);
	length = password ? strlen(password) : 0;
	if (length > password_size) {
		write_error = "password too long";
		fprintf(stderr, "PON authentication value exceeds %zu bytes\n", password_size);
		publish_status(mode, argv[2], strlen(argv[2]), serial_source, password_field,
			       password, length, password && length ? "uci" : "none",
			       argv[1], false, write_error, emit);
		goto out;
	}
	/* Serial provenance is observable but the value itself is not: status
	 * only carries its length and a SHA-256 prefix. */
	uci_serial = pon_config_option(&config, "serial_number");
	if (uci_serial && uci_serial[0] && !strcmp(uci_serial, argv[2])) {
		serial_source = "uci";
	} else if (read_text(PON_SYSFS "factory_serial_number", factory_serial,
			     sizeof(factory_serial)) && !strcmp(factory_serial, argv[2])) {
		serial_source = "factory";
	}
	/* The serial argument is already the normalized 8-byte form: a 12-byte
	 * vendor string keeps its four ASCII bytes and the trailing eight hex
	 * digits; for example, TEST01020304 becomes 5445535401020304. */
	memcpy(identity + PON_IDENTITY_SERIAL_BYTES, password ? password : "", length);
	fd = open(argv[1], O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		write_error = "identity interface unavailable";
		perror("PON identity interface");
	} else if (write(fd, identity, PON_IDENTITY_SERIAL_BYTES + password_size) !=
		   (ssize_t)(PON_IDENTITY_SERIAL_BYTES + password_size)) {
		write_error = "identity write failed";
		perror("PON identity write");
		close(fd);
	} else if (close(fd)) {
		write_error = "identity close failed";
		perror("PON identity close");
	} else {
		result = 0;
		write_ok = true;
	}
	snprintf(detail, sizeof(detail), "serial_len=%zu source=%s password_len=%zu field=%s write=%s",
		 strlen(argv[2]), serial_source, length, password_field,
		 write_ok ? "ok" : "failed");
	pon_event_append(mode, "identity", detail);
	publish_status(mode, argv[2], strlen(argv[2]), serial_source, password_field,
		       password, length, password && length ? "uci" : "none",
		       argv[1], write_ok, write_error, emit);
out:
	uci_free_context(config.context);
	return result;
}