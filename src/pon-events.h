/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_PON_EVENTS_H
#define RTL9617C_PON_EVENTS_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Fixed-size ring of the most recent protocol state transitions.  The file is
 * rewritten newest-first, so a field engineer only needs `cat` to reconstruct
 * the sequence without a syslog daemon.  Writers serialize on a side lock and
 * publish with rename(), so readers never observe a partial line. */
#define PON_EVENTS_PATH "/var/run/pon-events"
#define PON_EVENTS_LOCK "/var/run/pon-events.lock"
#define PON_EVENTS_MAX_LINES 64
#define PON_EVENTS_MAX_BYTES 16384
#define PON_EVENTS_LINE_BYTES 768

uint64_t pon_wall_ms(void);
int pon_event_append(const char *mode, const char *event, const char *detail);
int pon_events_clear(void);
ssize_t pon_events_read(char *output, size_t capacity);
#endif