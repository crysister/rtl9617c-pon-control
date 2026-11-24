/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RTL9617C_PON_OAM_H
#define RTL9617C_PON_OAM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-frame OAM diagnostics.  pon-oamd enables this through the UCI
 * "log_verbose" option or SIGUSR1; the default keeps the log quiet. */
extern bool pon_oam_debug;

#define PON_OAM_FRAME_MAX 1514
/* The OAM TLV length field includes the two-byte type/length header, so a
 * Local/Remote Information TLV carries 14 bytes of value. */
#define PON_OAM_INFO_TLV_LEN 16
#define PON_OAM_INFO_VALUE_LEN (PON_OAM_INFO_TLV_LEN - 2)

/* CTC organization-specific PDU identifiers, offsets and widths.  These are
 * protocol values from the captured stock ONU frames, not tunables. */
#define PON_OAM_CTC_TYPE_GET 1
#define PON_OAM_CTC_TYPE_SET 3
#define PON_OAM_CTC_TYPE_AUTH 5
#define PON_OAM_CTC_TYPE_CHURNING 9
#define PON_OAM_CTC_AUTH_CHALLENGE 1
#define PON_OAM_CTC_AUTH_ACCEPT 3
#define PON_OAM_CTC_AUTH_REJECT 4
#define PON_OAM_CTC_AUTH_TYPE_LOID 1
#define PON_OAM_CTC_LOID_BYTES 24
#define PON_OAM_CTC_PASSWORD_BYTES 12
#define PON_OAM_CTC_AUTH_BODY_BYTES 37
#define PON_OAM_CTC_AUTH_IMPLICIT_TYPE1 0x0101
#define PON_OAM_CTC_AUTH_REPLY_ACTION 2
#define PON_OAM_CTC_AUTH_METHOD_NON_LOID 2
#define PON_OAM_CTC_AUTH_NON_LOID_BYTES 2
#define PON_OAM_CTC_AUTH_NON_LOID_REPLY_BYTES 27
#define PON_OAM_CTC_AUTH_LOID_OFFSET 26
#define PON_OAM_CTC_AUTH_PASSWORD_OFFSET 50
#define PON_OAM_CTC_AUTH_REPLY_BYTES 63
#define PON_OAM_CTC_EXT_TLV_ECHO_BYTES 7
#define PON_OAM_CTC_EXT_TLV_LIST_BYTES 27
#define PON_OAM_CTC_EXT_VERSION_DEFAULT 0x30
#define PON_OAM_CTC_EXT_VERSION_MAX 0x30

/* pon_oam_receive() return contract:
 *   negative errno        invalid frame
 *   PON_OAM_IGNORED (0)   not a handled PDU
 *   PON_OAM_HANDLED (1)   handled, no reply (all Information PDUs)
 *   > PON_OAM_HANDLED     validated reply length; the caller sends exactly
 *                         that many bytes (CTC GET/SET/auth/churning)
 * Only handled PDUs update session liveness. */
enum pon_oam_receive_result {
	PON_OAM_IGNORED,
	PON_OAM_HANDLED,
};

struct pon_oam_request {
	uint8_t version;
	uint8_t branch;
	uint16_t leaf;
	const uint8_t *object;
	size_t object_size;
	const uint8_t *parameters;
	size_t parameter_size;
};

struct pon_oam_identity {
	uint8_t mac[6];
	uint8_t loid[24];
	uint8_t password[12];
	uint8_t vendor[4];
	uint8_t model[4];
	uint8_t equipment[20];
	uint8_t hardware[16];
	uint8_t software[16];
	uint8_t firmware[3];
	bool loid_configured;
	void *backend_context;
	int (*get_parameter)(void *context, const struct pon_oam_request *request,
		uint8_t *value, size_t capacity);
	uint8_t (*set_parameter)(void *context, const struct pon_oam_request *request,
		const uint8_t *value, size_t size);
	int (*churning_key)(void *context, uint8_t index, uint8_t key[9], size_t length);
};

enum pon_oam_auth {
	PON_AUTH_WAITING,
	PON_AUTH_CHALLENGE,
	PON_AUTH_ACCEPTED,
	PON_AUTH_REJECTED,
};

enum pon_oam_auth_source {
	PON_AUTH_SOURCE_NONE,
	PON_AUTH_SOURCE_CTC_RESULT,
	PON_AUTH_SOURCE_CTC_SET_PROGRESS,
};

struct pon_oam_session {
	uint8_t peer_local[PON_OAM_INFO_VALUE_LEN];
	uint8_t last_local[PON_OAM_INFO_VALUE_LEN];
	uint8_t extension_oui[3];
	uint8_t extension_version;
	uint16_t peer_flags;
	bool have_peer;
	bool have_sent;
	bool local_echoed;
	bool extension_selected;
	bool extension_advertised;
	/* The stock eponoamd runs a three-valued CTC discovery state per LLID
	 * (0x48b3f0[idx]): 1 = answer the capability list, 2 = answer the
	 * selection echo once, 3 = answer nothing more.  The two flags below
	 * are the wire-visible half of that state; extension_quiet is the
	 * terminal state in which no further extension TLV is emitted. */
	bool extension_list_answered;
	bool extension_echo_answered;
	bool extension_quiet;
	/* Information OUI/version/ExtSupport match.  This is extension
	 * negotiation only and never subscriber authentication. */
	bool extension_negotiated;
	uint64_t last_information_ms;
	/* Stock ctc_oam.c also accepts three eligible SET attributes while
	 * no explicit verdict is present (FUN_00419338 @0x41968c).
	 * Keep that local decision distinct from a type-5 OLT result. */
	bool auth_succeeded;
	bool auth_result_seen;
	enum pon_oam_auth_source auth_source;
	unsigned int auth_set_attributes;
	uint64_t auth_success_ms; /* wall-clock success timestamp */
	uint64_t auth_success_boot_ms; /* origin of stock authSuccTime */
	uint64_t last_type5_ms;
	uint8_t last_type5_code;
	bool provisioning_seen;
	uint8_t key[9];
	uint8_t key_length;
	uint8_t key_index;
	enum pon_oam_auth auth;
	uint8_t auth_failure;
	unsigned int generation;
	unsigned int rx_frames;
	unsigned int tx_frames;
	unsigned int auth_challenges;
	unsigned int auth_results;
	unsigned int auth_successes;
	unsigned int auth_failures;
};

void pon_oam_reset(struct pon_oam_session *session);
bool pon_oam_discovery_complete(const struct pon_oam_session *session);
uint16_t pon_oam_flags(const struct pon_oam_session *session);
uint64_t pon_oam_auth_duration_ms(const struct pon_oam_session *session, uint64_t now_ms);
size_t pon_oam_information(struct pon_oam_session *session, const struct pon_oam_identity *identity,
			   uint8_t output[PON_OAM_FRAME_MAX]);
void pon_oam_information_sent(struct pon_oam_session *session, const uint8_t *frame);
int pon_oam_receive(struct pon_oam_session *session, const struct pon_oam_identity *identity,
		    const uint8_t *input, size_t length, uint8_t output[PON_OAM_FRAME_MAX]);
#endif
