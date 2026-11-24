/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include "pon-sha256.h"

static uint32_t ror(uint32_t value, unsigned int bits)
{
	return (value >> bits) | (value << (32 - bits));
}

static void block(struct pon_sha256 *sha, const uint8_t *input)
{
	static const uint32_t constants[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	uint32_t word[64], a, b, c, d, e, f, g, h;
	unsigned int index;

	for (index = 0; index < 16; index++)
		word[index] = (uint32_t)input[index * 4] << 24 |
			      (uint32_t)input[index * 4 + 1] << 16 |
			      (uint32_t)input[index * 4 + 2] << 8 |
			      input[index * 4 + 3];
	for (; index < 64; index++) {
		uint32_t s0 = ror(word[index - 15], 7) ^
			      ror(word[index - 15], 18) ^ (word[index - 15] >> 3);
		uint32_t s1 = ror(word[index - 2], 17) ^
			      ror(word[index - 2], 19) ^ (word[index - 2] >> 10);

		word[index] = word[index - 16] + s0 + word[index - 7] + s1;
	}
	a = sha->state[0]; b = sha->state[1]; c = sha->state[2]; d = sha->state[3];
	e = sha->state[4]; f = sha->state[5]; g = sha->state[6]; h = sha->state[7];
	for (index = 0; index < 64; index++) {
		uint32_t s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
		uint32_t choose = (e & f) ^ (~e & g);
		uint32_t temp1 = h + s1 + choose + constants[index] + word[index];
		uint32_t s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = s0 + majority;

		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}
	sha->state[0] += a; sha->state[1] += b; sha->state[2] += c; sha->state[3] += d;
	sha->state[4] += e; sha->state[5] += f; sha->state[6] += g; sha->state[7] += h;
}

void pon_sha256_init(struct pon_sha256 *sha)
{
	static const uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memcpy(sha->state, initial, sizeof(initial));
	sha->length = 0;
	sha->used = 0;
}

void pon_sha256_update(struct pon_sha256 *sha, const void *data, size_t length)
{
	const uint8_t *bytes = data;

	sha->length += length;
	while (length) {
		size_t chunk = sizeof(sha->block) - sha->used;

		if (chunk > length)
			chunk = length;
		memcpy(sha->block + sha->used, bytes, chunk);
		sha->used += chunk;
		bytes += chunk;
		length -= chunk;
		if (sha->used == sizeof(sha->block)) {
			block(sha, sha->block);
			sha->used = 0;
		}
	}
}

void pon_sha256_final(struct pon_sha256 *sha, uint8_t digest[32])
{
	uint64_t bits = sha->length * 8;
	unsigned int index;

	sha->block[sha->used++] = 0x80;
	if (sha->used > 56) {
		memset(sha->block + sha->used, 0, sizeof(sha->block) - sha->used);
		block(sha, sha->block);
		sha->used = 0;
	}
	memset(sha->block + sha->used, 0, 56 - sha->used);
	for (index = 0; index < 8; index++)
		sha->block[56 + index] = bits >> (56 - index * 8);
	block(sha, sha->block);
	for (index = 0; index < 8; index++) {
		digest[index * 4] = sha->state[index] >> 24;
		digest[index * 4 + 1] = sha->state[index] >> 16;
		digest[index * 4 + 2] = sha->state[index] >> 8;
		digest[index * 4 + 3] = sha->state[index];
	}
}

void pon_sha256(const void *data, size_t length, uint8_t digest[32])
{
	struct pon_sha256 sha;

	pon_sha256_init(&sha);
	pon_sha256_update(&sha, data, length);
	pon_sha256_final(&sha, digest);
}

void pon_sha256_prefix8(const void *data, size_t length, char output[9])
{
	uint8_t digest[32];
	unsigned int index;

	pon_sha256(data, length, digest);
	for (index = 0; index < 4; index++)
		snprintf(output + index * 2, 3, "%02x", digest[index]);
}