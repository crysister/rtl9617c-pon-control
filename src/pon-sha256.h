/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_PON_SHA256_H
#define RTL9617C_PON_SHA256_H
#include <stddef.h>
#include <stdint.h>

/* Small self-contained SHA-256 for redacted status fields.  This is not used
 * for authentication; it only lets the field tooling compare a configured
 * serial/password without printing it. */
struct pon_sha256 {
	uint32_t state[8];
	uint64_t length;
	uint8_t block[64];
	size_t used;
};

void pon_sha256_init(struct pon_sha256 *sha);
void pon_sha256_update(struct pon_sha256 *sha, const void *data, size_t length);
void pon_sha256_final(struct pon_sha256 *sha, uint8_t digest[32]);
void pon_sha256(const void *data, size_t length, uint8_t digest[32]);
void pon_sha256_prefix8(const void *data, size_t length, char output[9]);
#endif