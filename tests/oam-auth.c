// SPDX-License-Identifier: GPL-2.0-or-later
/* CTC auth regression fixture.
 *
 * These cases encode the OEM observations at eponoamd FUN_00419338 and
 * FUN_00419c5c: bounded SET attributes advance the implicit progress path
 * before callback lookup; selectors/GET do not; an explicit type-5 result
 * disables progress; challenge is activity, not a result state.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pon-oam.h"

bool pon_oam_debug;
static const struct pon_oam_identity identity = { .mac = { 2, 1, 2, 3, 4, 5 } };

static void frame(uint8_t *data, unsigned int type)
{
	memset(data, 0, PON_OAM_FRAME_MAX);
	memcpy(data, "\x01\x80\xc2\0\0\x02", 6);
	memcpy(data + 6, "\x00\x13\x25\0\0\0", 6);
	data[12] = 0x88;
	data[13] = 9;
	data[14] = 3;
	data[16] = 0x50;
	data[17] = 0xfe;
	memcpy(data + 18, "\x11\x11\x11", 3);
	data[21] = (uint8_t)type;
}

static int receive(struct pon_oam_session *session, const uint8_t *data, size_t length)
{
	uint8_t output[PON_OAM_FRAME_MAX];

	return pon_oam_receive(session, &identity, data, length, output);
}

static void reset_session(struct pon_oam_session *session)
{
	memset(session, 0, sizeof(*session));
	pon_oam_reset(session);
}

static size_t attribute(uint8_t *data, size_t position, unsigned int branch,
			unsigned int leaf)
{
	data[position++] = (uint8_t)branch;
	data[position++] = (uint8_t)(leaf >> 8);
	data[position++] = (uint8_t)leaf;
	data[position++] = 1;
	data[position++] = 0x42;
	return position;
}

static void send_one_set(struct pon_oam_session *session, unsigned int branch)
{
	uint8_t data[PON_OAM_FRAME_MAX];
	size_t length;

	frame(data, PON_OAM_CTC_TYPE_SET);
	length = attribute(data, 22, branch, 0x1234);
	assert(receive(session, data, length) > PON_OAM_HANDLED);
}

static int send_result(struct pon_oam_session *session, unsigned int code,
			unsigned int declared, unsigned int available)
{
	uint8_t data[PON_OAM_FRAME_MAX];
	uint8_t output[PON_OAM_FRAME_MAX];

	assert(available <= PON_OAM_FRAME_MAX - 25);
	frame(data, PON_OAM_CTC_TYPE_AUTH);
	data[22] = (uint8_t)code;
	data[23] = (uint8_t)(declared >> 8);
	data[24] = (uint8_t)declared;
	memset(data + 25, 2, available);
	return pon_oam_receive(session, &identity, data, 25 + available, output);
}

static int send_challenge(struct pon_oam_session *session, unsigned int length)
{
	uint8_t data[PON_OAM_FRAME_MAX];
	uint8_t output[PON_OAM_FRAME_MAX];

	frame(data, PON_OAM_CTC_TYPE_AUTH);
	data[22] = PON_OAM_CTC_AUTH_CHALLENGE;
	data[23] = 0;
	data[24] = 1;
	data[25] = PON_OAM_CTC_AUTH_TYPE_LOID;
	return pon_oam_receive(session, &identity, data, length, output);
}

static void test_three_set_progress(void)
{
	struct pon_oam_session session;
	uint8_t data[PON_OAM_FRAME_MAX];
	size_t length;

	reset_session(&session);
	assert(session.auth_source == PON_AUTH_SOURCE_NONE);
	send_one_set(&session, 7);
	assert(session.auth_set_attributes == 1);
	assert(!session.auth_succeeded);
	send_one_set(&session, 9);
	assert(session.auth_set_attributes == 2);
	assert(!session.auth_succeeded);
	send_one_set(&session, 0xc7);
	assert(session.auth_set_attributes == 3);
	assert(session.auth == PON_AUTH_ACCEPTED);
	assert(session.auth_succeeded);
	assert(session.auth_source == PON_AUTH_SOURCE_CTC_SET_PROGRESS);
	assert(!session.auth_result_seen);
	assert(session.auth_results == 0);
	assert(session.auth_successes == 1);

	/* The count is attributes, not SET PDU count. */
	reset_session(&session);
	frame(data, PON_OAM_CTC_TYPE_SET);
	length = attribute(data, 22, 7, 0x1234);
	length = attribute(data, length, 9, 0x1234);
	length = attribute(data, length, 0xc9, 0x1234);
	assert(receive(&session, data, length) > PON_OAM_HANDLED);
	assert(session.auth_set_attributes == 3);
	assert(session.auth_succeeded);
	assert(session.auth_successes == 1);

	/* A fourth qualifying attribute is saturated, not a second success. */
	send_one_set(&session, 7);
	assert(session.auth_set_attributes == 3);
	assert(session.auth_successes == 1);
}

static uint8_t failing_set(void *context, const struct pon_oam_request *request,
			const uint8_t *value, size_t size)
{
	unsigned int *calls = context;

	assert(request->branch == 0xc7);
	assert(size == 1 && value[0] == 0x42);
	(*calls)++;
	return 0x87;
}

static void test_progress_does_not_require_backend_success(void)
{
	struct pon_oam_session session;
	struct pon_oam_identity backend_identity = identity;
	uint8_t data[PON_OAM_FRAME_MAX], output[PON_OAM_FRAME_MAX];
	unsigned int calls = 0;
	size_t length;

	reset_session(&session);
	backend_identity.backend_context = &calls;
	backend_identity.set_parameter = failing_set;
	frame(data, PON_OAM_CTC_TYPE_SET);
	length = attribute(data, 22, 0xc7, 0x1234);
	length = attribute(data, length, 0xc7, 0x1235);
	length = attribute(data, length, 0xc7, 0x1236);
	assert(pon_oam_receive(&session, &backend_identity, data, length, output) > PON_OAM_HANDLED);
	assert(calls == 3);
	assert(session.auth_succeeded);
	assert(session.auth_source == PON_AUTH_SOURCE_CTC_SET_PROGRESS);
	assert(session.auth_results == 0);
	assert(output[25] == 0x87 && output[29] == 0x87 && output[33] == 0x87);
}

static void test_selectors_get_and_bad_width_do_not_count(void)
{
	struct pon_oam_session session;
	uint8_t data[PON_OAM_FRAME_MAX];
	size_t length;

	reset_session(&session);
	frame(data, PON_OAM_CTC_TYPE_GET);
	memcpy(data + 22, "\xc7\0\x01", 3);
	assert(receive(&session, data, 25) > PON_OAM_HANDLED);
	assert(session.auth_set_attributes == 0);

	reset_session(&session);
	frame(data, PON_OAM_CTC_TYPE_SET);
	memcpy(data + 22, "\x36\0\x01\x01\x01\x37\0\x01\x04\x01\0\0\x01", 13);
	assert(receive(&session, data, 35) == PON_OAM_IGNORED);
	assert(session.auth_set_attributes == 0);

	frame(data, PON_OAM_CTC_TYPE_SET);
	length = attribute(data, 22, 0x42, 1);
	(void)receive(&session, data, length);
	assert(session.auth_set_attributes == 0);

	/* Truncated qualifying attributes never advance progress. */
	send_one_set(&session, 7);
	send_one_set(&session, 9);
	frame(data, PON_OAM_CTC_TYPE_SET);
	memcpy(data + 22, "\xc7\x12\x34\x02\x42", 5);
	assert(receive(&session, data, 27) < 0);
	assert(session.auth_set_attributes == 2);
	assert(!session.auth_succeeded);
}

static void test_explicit_results_are_bounded_and_gate_progress(void)
{
	struct pon_oam_session session;
	unsigned int declared;

	for (declared = 0; declared <= 3; declared++) {
		reset_session(&session);
		assert(send_result(&session, PON_OAM_CTC_AUTH_ACCEPT, declared, declared + 4) == PON_OAM_HANDLED);
		assert(session.auth == PON_AUTH_ACCEPTED);
		assert(session.auth_succeeded);
		assert(session.auth_result_seen);
		assert(session.auth_source == PON_AUTH_SOURCE_CTC_RESULT);
		assert(session.auth_results == 1 && session.auth_successes == 1);
	}

	reset_session(&session);
	assert(send_result(&session, PON_OAM_CTC_AUTH_ACCEPT, 2, 1) < 0);
	assert(!session.auth_result_seen && session.auth_results == 0);
	assert(send_result(&session, PON_OAM_CTC_AUTH_REJECT, 0, 0) < 0);
	assert(!session.auth_result_seen && session.auth_results == 0);
	assert(send_result(&session, PON_OAM_CTC_AUTH_REJECT, 2, 2) == PON_OAM_HANDLED);
	assert(session.auth == PON_AUTH_REJECTED && session.auth_failure == 2);
	assert(session.auth_result_seen);
	assert(session.auth_source == PON_AUTH_SOURCE_CTC_RESULT);

	/* Explicit result disables implicit three-SET progress. */
	send_one_set(&session, 7);
	send_one_set(&session, 9);
	send_one_set(&session, 0xc7);
	assert(session.auth == PON_AUTH_REJECTED);
	assert(!session.auth_succeeded);
	assert(session.auth_results == 1 && session.auth_successes == 0);

	/* Explicit success clears the old rejection reason. */
	assert(send_result(&session, PON_OAM_CTC_AUTH_ACCEPT, 1, 1) == PON_OAM_HANDLED);
	assert(session.auth == PON_AUTH_ACCEPTED && session.auth_succeeded);
	assert(session.auth_failure == 0);
	assert(session.auth_results == 2 && session.auth_successes == 1);
}

static void test_challenge_does_not_revoke_result(void)
{
	struct pon_oam_session session;

	reset_session(&session);
	assert(send_result(&session, PON_OAM_CTC_AUTH_ACCEPT, 0, 0) == PON_OAM_HANDLED);
	session.auth_success_boot_ms = 1000;
	session.auth_success_ms = 1794656000000ULL;
	assert(send_challenge(&session, 26) == 63);
	assert(session.auth == PON_AUTH_ACCEPTED);
	assert(session.auth_succeeded);
	assert(session.auth_success_boot_ms == 1000);
	assert(session.auth_success_ms == 1794656000000ULL);
	assert(session.auth_challenges == 1 && session.auth_results == 1);

	reset_session(&session);
	assert(send_result(&session, PON_OAM_CTC_AUTH_REJECT, 1, 1) == PON_OAM_HANDLED);
	assert(session.auth_failure == 2);
	assert(send_challenge(&session, 26) == 63);
	assert(session.auth == PON_AUTH_REJECTED);
	assert(!session.auth_succeeded && session.auth_failure == 2);
	assert(session.auth_results == 1 && session.auth_failures == 1);
}

static void test_duration_and_reset(void)
{
	struct pon_oam_session session;

	reset_session(&session);
	assert(pon_oam_auth_duration_ms(&session, 5000) == 0);
	assert(send_result(&session, PON_OAM_CTC_AUTH_ACCEPT, 0, 0) == PON_OAM_HANDLED);
	session.auth_success_boot_ms = 1000;
	session.auth_success_ms = 1794656000000ULL;
	assert(pon_oam_auth_duration_ms(&session, 4999) == 3999);
	/* Wall clock corrections do not alter duration. */
	session.auth_success_ms = 1;
	assert(pon_oam_auth_duration_ms(&session, 5000) == 4000);
	assert(pon_oam_auth_duration_ms(&session, 999) == 0);

	assert(send_result(&session, PON_OAM_CTC_AUTH_REJECT, 1, 1) == PON_OAM_HANDLED);
	assert(!session.auth_succeeded);
	assert(session.auth_success_ms == 0 && session.auth_success_boot_ms == 0);
	assert(pon_oam_auth_duration_ms(&session, 10000) == 0);
	pon_oam_reset(&session);
	assert(session.auth == PON_AUTH_WAITING);
	assert(session.auth_source == PON_AUTH_SOURCE_NONE);
	assert(!session.auth_result_seen && session.auth_set_attributes == 0);
	assert(!session.auth_succeeded && session.auth_failure == 0);
	assert(session.auth_success_ms == 0 && session.auth_success_boot_ms == 0);
}

static void test_flags_regression_not_reintroduced(void)
{
	static const unsigned int peer_flags[] = {0, 8, 16, 32, 64, 0xffff};
	struct pon_oam_session session;
	uint8_t output[PON_OAM_FRAME_MAX];
	unsigned int present, index;

	for (present = 0; present < 2; present++) {
		for (index = 0; index < sizeof(peer_flags) / sizeof(peer_flags[0]); index++) {
			unsigned int expected = present ? 0x10 : 8;
			unsigned int actual;

			reset_session(&session);
			session.have_peer = present;
			session.peer_flags = peer_flags[index];
			pon_oam_information(&session, &identity, output);
			actual = ((unsigned int)output[15] << 8) | output[16];
			expected |= (peer_flags[index] & 16) ? 64 : (peer_flags[index] & 8) ? 32 : 0;
			assert(actual == expected && !(actual & 7));
			assert(!memcmp(output + 6, identity.mac, 6));
			assert(!memcmp(output + 27, identity.mac, 6));
		}
	}
}

int main(void)
{
	test_three_set_progress();
	test_progress_does_not_require_backend_success();
	test_selectors_get_and_bad_width_do_not_count();
	test_explicit_results_are_bounded_and_gate_progress();
	test_challenge_does_not_revoke_result();
	test_duration_and_reset();
	test_flags_regression_not_reintroduced();
	puts("PASS: OEM SET progress/result gates, bounded auth, challenge persistence, duration/reset, flags");
	return 0;
}
