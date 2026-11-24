/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
#include "pon-events.h"

uint64_t pon_wall_ms(void)
{
	struct timespec time;

	clock_gettime(CLOCK_REALTIME, &time);
	return (uint64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static void pon_event_escape(const char *input, char *output, size_t capacity)
{
	size_t used = 0;

	if (!capacity)
		return;
	for (; input && *input && used + 1 < capacity; input++) {
		unsigned char value = (unsigned char)*input;

		if (value == '"' || value == '\\') {
			if (used + 2 >= capacity)
				break;
			output[used++] = '\\';
			output[used++] = value;
		} else if (value < 0x20) {
			if (used + 2 >= capacity)
				break;
			output[used++] = ' ';
		} else {
			output[used++] = value;
		}
	}
	output[used] = '\0';
}

/* Append one event.  detail is free text (no secrets) and may be empty. */
int pon_event_append(const char *mode, const char *event, const char *detail)
{
	char line[PON_EVENTS_LINE_BYTES];
	char old[PON_EVENTS_MAX_BYTES];
	char temporary[64];
	char escaped[PON_EVENTS_LINE_BYTES / 2];
	char escaped_mode[64];
	char escaped_event[64];
	ssize_t line_length, old_length, written;
	size_t kept = 0, offset = 0;
	unsigned int lines = 0;
	int lock_fd, fd, ret = 0;

	if (!mode)
		mode = "unknown";
	if (!event)
		event = "event";
	pon_event_escape(mode, escaped_mode, sizeof(escaped_mode));
	pon_event_escape(event, escaped_event, sizeof(escaped_event));
	pon_event_escape(detail ? detail : "", escaped, sizeof(escaped));
	line_length = snprintf(line, sizeof(line),
		"{\"ts_ms\":%llu,\"mode\":\"%s\",\"event\":\"%s\",\"detail\":\"%s\"}\n",
		(unsigned long long)pon_wall_ms(), escaped_mode, escaped_event, escaped);
	if (line_length < 0 || (size_t)line_length >= sizeof(line))
		return -E2BIG;
	lock_fd = open(PON_EVENTS_LOCK, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
	if (lock_fd >= 0)
		flock(lock_fd, LOCK_EX);
	old_length = 0;
	fd = open(PON_EVENTS_PATH, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		old_length = read(fd, old, sizeof(old));
		close(fd);
		if (old_length < 0)
			old_length = 0;
	}
	/* Keep at most MAX_LINES-1 previous lines and leave room for the new
	 * one; both limits are independent so one huge line cannot evict the
	 * whole history. */
	while (offset < (size_t)old_length && lines < PON_EVENTS_MAX_LINES - 1) {
		char *end = memchr(old + offset, '\n', (size_t)old_length - offset);

		if (!end)
			break;
		offset = (size_t)(end - old) + 1;
		lines++;
	}
	kept = offset;
	if (kept + (size_t)line_length > PON_EVENTS_MAX_BYTES)
		kept = PON_EVENTS_MAX_BYTES > (size_t)line_length ?
			PON_EVENTS_MAX_BYTES - (size_t)line_length : 0;
	while (kept && old[kept - 1] != '\n')
		kept--;
	snprintf(temporary, sizeof(temporary), PON_EVENTS_PATH ".%ld", (long)getpid());
	fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	written = write(fd, line, (size_t)line_length);
	if (written != line_length)
		ret = written < 0 ? -errno : -EIO;
	if (!ret && kept) {
		written = write(fd, old, kept);
		if (written != (ssize_t)kept)
			ret = written < 0 ? -errno : -EIO;
	}
	if (close(fd) && !ret)
		ret = -EIO;
	if (!ret && rename(temporary, PON_EVENTS_PATH))
		ret = -errno;
	if (ret)
		unlink(temporary);
out:
	if (lock_fd >= 0) {
		flock(lock_fd, LOCK_UN);
		if (close(lock_fd) && !ret)
			ret = -EIO;
	}
	return ret;
}

int pon_events_clear(void)
{
	int fd = open(PON_EVENTS_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (fd < 0)
		return -errno;
	if (close(fd))
		return -EIO;
	return 0;
}

ssize_t pon_events_read(char *output, size_t capacity)
{
	ssize_t length;
	int fd = open(PON_EVENTS_PATH, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;
	if (capacity < 2) {
		close(fd);
		return -EINVAL;
	}
	length = read(fd, output, capacity - 1);
	if (close(fd) && length >= 0)
		return -EIO;
	if (length < 0)
		return -errno;
	output[length] = '\0';
	return length;
}