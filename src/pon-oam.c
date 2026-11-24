// SPDX-License-Identifier: GPL-2.0-or-later
/* Native IEEE802.3ah discovery and CTC LOID/identity codec.
 * Protocol layouts cross-checked with CTC interoperability traces and RTL9617C OAM DAL.
 * Input/output are ordinary Ethernet frames; each Linux interface owns one LLID.
 */
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include "pon-oam.h"

#define LOCAL_EVAL 0x0008
#define LOCAL_STABLE 0x0010
#define REMOTE_EVAL 0x0020
#define REMOTE_STABLE 0x0040

/* Per-frame diagnostics are gated; state transitions stay unconditional. */
#define oam_dbg(fmt, ...) do { \
	if (pon_oam_debug) \
		syslog(LOG_INFO, fmt, ##__VA_ARGS__); \
} while (0)

static uint64_t oam_ms(void)
{
	struct timespec time;

	clock_gettime(CLOCK_REALTIME, &time);
	return (uint64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static uint64_t oam_boot_ms(void)
{
	struct timespec time;

	clock_gettime(CLOCK_BOOTTIME, &time);
	return (uint64_t)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static uint16_t be16(const uint8_t *data)
{
	return (uint16_t)data[0] << 8 | data[1];
}

static void set_be16(uint8_t *data, uint16_t value)
{
	data[0] = value >> 8;
	data[1] = value;
}

static bool ctc_oui(const uint8_t *oui)
{
	return !memcmp(oui, "\x11\x11\x11", 3) || !memcmp(oui, "\x00\x0d\xb6", 3);
}

/* CTC extension versions the stock ONU accepts, from the capability tables
 * at 0x4575a0 (A, five entries) and 0x4575b8 (B, ten entries) compared by
 * FUN_00417d9c.  Every entry is OUI 11:11:11 plus one of these version
 * bytes; the match checks no MAC and no LOID, so it only establishes the
 * extension tuple, never subscriber authorisation. */
static bool ctc_version_supported(uint8_t version)
{
	switch (version) {
	case 0x01: case 0x13: case 0x20: case 0x21: case 0x30:
	case 0xc1: case 0xc2: case 0xc3: case 0xc4: case 0xc5:
		return true;
	default:
		return false;
	}
}

void pon_oam_reset(struct pon_oam_session *session)
{
	session->have_peer = false;
	session->have_sent = false;
	session->local_echoed = false;
	session->extension_selected = false;
	/* The captured stock ONU does not advertise CTC OAM before the OLT
	 * selects an extension. Keep IEEE discovery clean first. */
	session->extension_advertised = false;
	session->extension_list_answered = false;
	session->extension_echo_answered = false;
	session->extension_quiet = false;
	session->extension_negotiated = false;
	session->last_information_ms = 0;
	session->extension_version = PON_OAM_CTC_EXT_VERSION_DEFAULT;
	memset(session->key, 0, sizeof(session->key));
	session->key_length = 0;
	session->extension_oui[0] = 0x00;
	session->extension_oui[1] = 0x0d;
	session->extension_oui[2] = 0xb6;
	session->peer_flags = 0;
	session->auth = PON_AUTH_WAITING;
	session->auth_failure = 0;
	session->auth_succeeded = false;
	session->auth_result_seen = false;
	session->auth_source = PON_AUTH_SOURCE_NONE;
	session->auth_set_attributes = 0;
	session->auth_success_ms = 0;
	session->auth_success_boot_ms = 0;
	session->last_type5_ms = 0;
	session->last_type5_code = 0;
	session->provisioning_seen = false;
	session->generation++;
}

bool pon_oam_discovery_complete(const struct pon_oam_session *session)
{
	return session->have_peer && session->local_echoed && (session->peer_flags & LOCAL_STABLE);
}

uint16_t pon_oam_flags(const struct pon_oam_session *session)
{
	/* IEEE 802.3 clause 57 discovery flags only. Bit 1 is Dying Gasp;
	 * it is not a response marker. Normal stock Information frames
	 * (ref_tx_dump.txt:69,77,79,145) use 0x0050 after discovery. */
	uint16_t flags = session->have_peer ? LOCAL_STABLE : LOCAL_EVAL;

	if (session->peer_flags & LOCAL_STABLE)
		flags |= REMOTE_STABLE;
	else if (session->peer_flags & LOCAL_EVAL)
		flags |= REMOTE_EVAL;
	return flags;
}

static void local_information(const struct pon_oam_session *session,
			      const struct pon_oam_identity *identity, uint8_t *local)
{
	(void)session;
	/* IEEE 802.3 clause 57 Local Information TLV value (14 bytes), laid out
	 * the way both the Beijing Unicom OLT and the captured stock ONU do:
	 *   [0]     version/state   0x01
	 *   [1]     revision        0x00
	 *   [2..3]  PDU config      0x0001
	 *   [4]     OAM identification (0x14 on the stock unit, 0x0f on the OLT)
	 *   [5]     OUI byte 0x05
	 *   [6]     OUI byte 0xee
	 *   [7..12] vendor information: the ONU's own MAC address
	 *   [13]    trailing zero
	 *
	 * A previous revision hard-coded the captured stock constant, which
	 * embedded another unit's MAC.  The OLT echoed that
	 * address back in its Remote Information TLV, never matched it to the
	 * registered ONU, and kept sending deregister frames on its own timer.
	 * Build the vendor block from the live identity instead. */
	local[0] = 0x01;
	local[1] = 0x00;
	local[2] = 0x01;
	local[3] = 0x00;
	local[4] = 0x14;
	local[5] = 0x05;
	local[6] = 0xee;
	memcpy(local + 7, identity->mac, 6);
	local[13] = 0x00;
}

static void ethernet_header(const struct pon_oam_session *session, const struct pon_oam_identity *identity,
			    uint8_t *output, uint8_t code)
{
	static const uint8_t destination[6] = {1, 0x80, 0xc2, 0, 0, 2};

	memset(output, 0, PON_OAM_FRAME_MAX);
	memcpy(output, destination, 6);
	memcpy(output + 6, identity->mac, 6);
	output[12] = 0x88;
	output[13] = 9;
	output[14] = 3;
	/* CTC organization/auth responses use the stable flag set, matching
	 * ponwrt and the OLT's own CTC PDUs, not the IEEE discovery 0x0032. */
	set_be16(output + 15, code == 0xfe ? 0x0050 : pon_oam_flags(session));
	output[17] = code;
}

size_t pon_oam_information(struct pon_oam_session *session, const struct pon_oam_identity *identity,
			   uint8_t output[PON_OAM_FRAME_MAX])
{
	size_t offset = 18;

	ethernet_header(session, identity, output, 0);
	output[offset++] = 1;
	output[offset++] = PON_OAM_INFO_TLV_LEN;
	local_information(session, identity, output + offset);
	offset += PON_OAM_INFO_VALUE_LEN;
	if (session->have_peer) {
		oam_dbg("OAM info peer branch offset=%zu", offset);
		output[offset++] = 2;
		output[offset++] = PON_OAM_INFO_TLV_LEN;
		memcpy(output + offset, session->peer_local, PON_OAM_INFO_VALUE_LEN);
		offset += PON_OAM_INFO_VALUE_LEN;
	}
	if (session->extension_selected && !session->extension_echo_answered) {
		/* Stock frame 009 (ref_tx_dump.txt): fe 07 11 11 11 01 30 =
		 * OUI, fixed 0x01, the version the OLT selected.  The stock
		 * daemon answers the selection exactly once and then stops
		 * carrying the extension TLV: of 242 captured frames the TLV
		 * appeared in only the capability list and this echo.  Its
		 * discovery state machine reaches state 3 (0x48b3f0[idx]) and
		 * state 3 answers nothing; repeating the echo every second kept
		 * the OLT's CTC negotiation from ever settling. */
		output[offset++] = 0xfe;
		output[offset++] = PON_OAM_CTC_EXT_TLV_ECHO_BYTES;
		memcpy(output + offset, session->extension_oui, 3);
		output[offset + 3] = 1;
		output[offset + 4] = session->extension_version;
		offset += 5;
	} else if (session->extension_advertised && !session->extension_list_answered) {
		/* Stock frame 008: when the OLT lists its CTC versions, the ONU
		 * answers with its own list before the OLT selects one:
		 * fe 1b OUI 01 00 then OUI+{01,13,20,21,30}.  Skipping this step
		 * leaves the OLT's CTC negotiation unanswered and it drops the
		 * LLID when its ~97 s negotiation retry gives up. */
		static const uint8_t versions[] = {0x01, 0x13, 0x20, 0x21, 0x30};
		size_t i;

		output[offset++] = 0xfe;
		output[offset++] = PON_OAM_CTC_EXT_TLV_LIST_BYTES;
		memcpy(output + offset, session->extension_oui, 3);
		output[offset + 3] = 1;
		output[offset + 4] = 0;
		offset += 5;
		for (i = 0; i < sizeof(versions); i++) {
			memcpy(output + offset, session->extension_oui, 3);
			output[offset + 3] = versions[i];
			offset += 4;
		}
	}
	offset += 2; /* end TLV and zero Ethernet padding */
	return offset < 60 ? 60 : offset;
}

void pon_oam_information_sent(struct pon_oam_session *session, const uint8_t *frame)
{
	memcpy(session->last_local, frame + 20, PON_OAM_INFO_VALUE_LEN);
	session->have_sent = true;
	session->tx_frames++;
	/* The capability list and the selection echo are each answered once.
	 * Only the echo retires the extension TLV: after the list the OLT still
	 * has to select a version, and the stock ONU carried the TLV in exactly
	 * two frames (the list and the echo) before its discovery state reached
	 * 3.  Retiring on the list instead suppressed the echo entirely. */
	if (session->extension_selected && !session->extension_echo_answered) {
		session->extension_list_answered = true;
		session->extension_echo_answered = true;
		session->extension_quiet = true;
		session->extension_advertised = false;
	} else if (session->extension_advertised && !session->extension_list_answered) {
		session->extension_list_answered = true;
		session->extension_advertised = false;
	}
}

static int receive_information(struct pon_oam_session *session, const uint8_t *input, size_t length)
{
	const uint8_t *local = NULL, *remote = NULL, *extension = NULL;
	size_t offset;
	bool echoed, revision_only;

	for (offset = 18; offset < length;) {
		uint8_t type = input[offset], size;

		if (!type)
			break;
		if (offset + 2 > length)
			return -EMSGSIZE;
		size = input[offset + 1];
		if (size < 2 || offset + size > length)
			return -EMSGSIZE;
		if (type == 1 || type == 2) {
			if (size != PON_OAM_INFO_TLV_LEN || (type == 1 && local) || (type == 2 && remote))
				return -EPROTO;
			if (type == 1)
				local = input + offset + 2;
			else
				remote = input + offset + 2;
		} else if (type == 0xfe && size >= 7 && ctc_oui(input + offset + 2)) {
			if ((size - PON_OAM_CTC_EXT_TLV_ECHO_BYTES) % 4)
				return -EPROTO;
			extension = input + offset;
		}
		offset += size;
	}
	if (!local)
		return -EPROTO;
	session->last_information_ms = oam_ms();
	/* A missing/mismatched Remote echo ends the established discovery session,
	 * even when the peer's Local TLV has not changed. Require a new revision
	 * echo before accepting authentication for the next session. */
	echoed = remote && session->have_sent && !memcmp(remote, session->last_local, PON_OAM_INFO_VALUE_LEN);
	/* OLTs may rewrite the vendor-specific tail of the Local TLV while the
	 * discovery state stays stable.  Only the version/revision/state/config
	 * fields define a new session; comparing the whole value made every such
	 * update reset the OAM session before it could send Remote echo. */
	revision_only = session->have_peer && echoed && (be16(input + 15) & LOCAL_STABLE) &&
		!memcmp(local, session->peer_local, 4);
	if ((session->have_peer && memcmp(session->peer_local, local, 4) && !revision_only) ||
	    (session->local_echoed && (!remote || !session->have_sent ||
				     memcmp(remote, session->last_local, PON_OAM_INFO_VALUE_LEN))))
		pon_oam_reset(session);
	memcpy(session->peer_local, local, PON_OAM_INFO_VALUE_LEN);
	session->have_peer = true;
	session->local_echoed = remote && session->have_sent && !memcmp(remote, session->last_local, PON_OAM_INFO_VALUE_LEN);
	session->peer_flags = be16(input + 15);
	if (extension && (extension[1] > PON_OAM_CTC_EXT_TLV_ECHO_BYTES || session->local_echoed)) {
		unsigned int version = 0;
		/* OLT advertisements contain any number of OUI/version tuples. */
		for (offset = 7; offset + 4 <= extension[1]; offset += 4)
			if (ctc_oui(extension + offset) && extension[offset + 3] <= PON_OAM_CTC_EXT_VERSION_MAX &&
			    extension[offset + 3] > version)
				version = extension[offset + 3];
		if (extension[1] == PON_OAM_CTC_EXT_TLV_ECHO_BYTES)
			version = extension[6];
		if (version) {
			oam_dbg("CTC info ext size=%u version=%u selected=%u echoed=%u",
				extension[1], version, extension[1] == 7, session->local_echoed);
			memcpy(session->extension_oui, extension + 2, 3);
			session->extension_selected = extension[1] == 7;
			session->extension_advertised = extension[1] > PON_OAM_CTC_EXT_TLV_ECHO_BYTES;
			/* FUN_00417d9c/FUN_0041c29c establish an extension tuple,
			 * not subscriber authorisation.  Keep the negotiation
			 * result separate from the type-5 auth result. */
			session->extension_negotiated = ctc_oui(extension + 2) &&
				extension[5] == 1 && ctc_version_supported(extension[6]);
			/* A fresh OLT advertisement (size > 7) restarts the
			 * negotiation, so the one-shot list/echo answers become
			 * pending again.  This mirrors the stock transition from
			 * state 3 back to state 1 when the TLV chain starts with
			 * 0x01 at 0x41c5c0. */
			if (session->extension_advertised) {
				session->extension_list_answered = false;
				session->extension_echo_answered = false;
				session->extension_quiet = false;
			}
			session->extension_version = version;
		}
	}
	return 0;
}

static void identity_field(uint8_t *output, size_t width, const uint8_t *value, size_t capacity)
{
	size_t length = strnlen((const char *)value, capacity);

	if (length > width)
		length = width;
	memset(output, 0, width - length);
	memcpy(output + width - length, value, length);
}

uint64_t pon_oam_auth_duration_ms(const struct pon_oam_session *session, uint64_t now_ms)
{
	if (!session->auth_succeeded || session->auth != PON_AUTH_ACCEPTED ||
	    now_ms < session->auth_success_boot_ms)
		return 0;
	return now_ms - session->auth_success_boot_ms;
}

static void auth_accept(struct pon_oam_session *session, enum pon_oam_auth_source source)
{
	session->auth = PON_AUTH_ACCEPTED;
	session->auth_failure = 0;
	session->auth_succeeded = true;
	session->auth_source = source;
	/* eponoamd FUN_00416460/0041649c stores CLOCK_BOOTTIME and exposes
	 * elapsed time, not the wall-clock time at which success happened. */
	session->auth_success_boot_ms = oam_boot_ms();
	session->auth_success_ms = oam_ms();
	session->auth_successes++;
}

static void auth_set_progress(struct pon_oam_session *session, uint8_t branch)
{
	/* Stock FUN_00419338 @0x41968c..0x419790: selector branches 36/37
	 * do not count. Three bounded attributes from 07/09/c7/c9 complete
	 * the pending state before handler lookup, even for unsupported leaves.
	 * FUN_0041651c disables this path after an explicit accept/reject. */
	if (session->auth_result_seen || session->auth_source == PON_AUTH_SOURCE_CTC_SET_PROGRESS ||
	    (branch != 7 && branch != 9 && branch != 0xc7 && branch != 0xc9))
		return;
	if (++session->auth_set_attributes == 3)
		auth_accept(session, PON_AUTH_SOURCE_CTC_SET_PROGRESS);
}

static int receive_auth(struct pon_oam_session *session, const struct pon_oam_identity *identity,
			const uint8_t *input, size_t length, uint8_t *output)
{
	uint8_t code;
	uint8_t auth_type;
	uint16_t size;

	if (length < 25)
		return -EMSGSIZE;
	code = input[22];
	size = be16(input + 23);
	/* CTC field interoperability: 0101 encodes an implicit type1 challenge. */
	if (!(code == PON_OAM_CTC_AUTH_CHALLENGE && size == PON_OAM_CTC_AUTH_IMPLICIT_TYPE1) &&
	    size > length - 25)
		return -EMSGSIZE;
	if (code == PON_OAM_CTC_AUTH_ACCEPT) {
		/* Stock FUN_00419c5c accepts any bounded code-3 body. */
		session->auth_result_seen = true;
		session->auth_set_attributes = 0;
		auth_accept(session, PON_AUTH_SOURCE_CTC_RESULT);
		session->last_type5_code = PON_OAM_CTC_AUTH_ACCEPT;
		session->last_type5_ms = oam_ms();
		session->auth_results++;
		return PON_OAM_HANDLED;
	}
	if (code == PON_OAM_CTC_AUTH_REJECT) {
		if (size < 1)
			return -EPROTO;
		session->auth_result_seen = true;
		session->auth_source = PON_AUTH_SOURCE_CTC_RESULT;
		session->auth_set_attributes = 0;
		session->auth = PON_AUTH_REJECTED;
		session->auth_succeeded = false;
		session->auth_success_ms = 0;
		session->auth_success_boot_ms = 0;
		session->last_type5_code = PON_OAM_CTC_AUTH_REJECT;
		session->last_type5_ms = oam_ms();
		session->auth_failure = input[25];
		session->auth_results++;
		session->auth_failures++;
		return PON_OAM_HANDLED;
	}
	if (code != PON_OAM_CTC_AUTH_CHALLENGE ||
	    (size != 1 && size != PON_OAM_CTC_AUTH_IMPLICIT_TYPE1))
		return -EPROTO;
	auth_type = size == PON_OAM_CTC_AUTH_IMPLICIT_TYPE1 ? PON_OAM_CTC_AUTH_TYPE_LOID : input[25];
	/* Stock challenge handling sends a reply without overwriting the
	 * last authentication result. Keep a pending challenge observable. */
	if (!session->auth_result_seen && !session->auth_succeeded) {
		session->auth = PON_AUTH_CHALLENGE;
		session->auth_failure = 0;
	}
	session->auth_challenges++;
	session->last_type5_code = PON_OAM_CTC_AUTH_CHALLENGE;
	session->last_type5_ms = oam_ms();
	output[21] = PON_OAM_CTC_TYPE_AUTH;
	output[22] = PON_OAM_CTC_AUTH_REPLY_ACTION;
	if (auth_type == PON_OAM_CTC_AUTH_TYPE_LOID) {
		/* The reference ONU always answers the CTC challenge, even with
		 * nothing provisioned, using the factory LOID "user" and password
		 * "password" (ref_tx_dump.txt frames 19-21 carry 05 02 00 25 01,
		 * 24-byte LOID right-aligned to "user", 12-byte password to
		 * "password").  Staying silent instead leaves the OLT retrying
		 * the challenge until it reclaims the LLID on its own timer
		 * (~97 s on Beijing Unicom), so use the factory pair when none
		 * is configured. */
		static const char factory_loid[] = "user";
		static const char factory_password[] = "password";
		const char *loid = identity->loid_configured ? (const char *)identity->loid : factory_loid;
		const char *password = identity->loid_configured ? (const char *)identity->password
								: factory_password;

		oam_dbg("CTC auth reply method=1 configured=%u", identity->loid_configured);
		/* Reference wire format (captured from the stock ONU):
		 * 05 02 | size 0x25 | method 1 | LOID 24 right-aligned |
		 * password 12 right-aligned | one trailing zero = 63 bytes. */
		set_be16(output + 23, PON_OAM_CTC_AUTH_BODY_BYTES);
		output[25] = PON_OAM_CTC_AUTH_TYPE_LOID;
		identity_field(output + PON_OAM_CTC_AUTH_LOID_OFFSET, PON_OAM_CTC_LOID_BYTES, (const uint8_t *)loid,
			       identity->loid_configured ? sizeof(identity->loid) : sizeof(factory_loid) - 1);
		identity_field(output + PON_OAM_CTC_AUTH_PASSWORD_OFFSET, PON_OAM_CTC_PASSWORD_BYTES, (const uint8_t *)password,
			       identity->loid_configured ? sizeof(identity->password) : sizeof(factory_password) - 1);
		output[PON_OAM_CTC_AUTH_REPLY_BYTES - 1] = 0;
		return PON_OAM_CTC_AUTH_REPLY_BYTES;
	}
	/* Non-LOID challenge method (method 2).  The reference capture only
	 * contains method-1 LOID replies (ref_tx_dump.txt frames 19-21), and
	 * no stock disassembly of this 27-byte shape was located.  This branch
	 * is an inferred protocol-completeness fallback inherited from the
	 * earlier upstream implementation; it is NOT capture-verified. */
	set_be16(output + 23, PON_OAM_CTC_AUTH_NON_LOID_BYTES);
	output[25] = PON_OAM_CTC_AUTH_METHOD_NON_LOID;
	output[26] = 1; /* trailing method-specific byte; unverified */
	return PON_OAM_CTC_AUTH_NON_LOID_REPLY_BYTES;
}

/* A zero width encodes 128 data bytes. Longer values repeat the descriptor,
 * as in the board's eponoamd:0x4162ec; the high bit denotes an indication. */
static int variable_reply(uint8_t *output, size_t offset, uint8_t branch,
			 uint16_t leaf, const uint8_t *data, size_t size, uint8_t indication)
{
	size_t count;
	size_t position = 0;

	if (!data)
		size = 0;
	count = data && size ? (size + 127) / 128 : 1;
	if (offset + count * 4 + size > PON_OAM_FRAME_MAX)
		return -EMSGSIZE;
	do {
		size_t chunk = size - position > 128 ? 128 : size - position;

		output[offset++] = branch;
		set_be16(output + offset, leaf);
		offset += 2;
		output[offset++] = data ? (chunk == 128 ? 0 : chunk) : indication;
		if (data) {
			memcpy(output + offset, data + position, chunk);
			offset += chunk;
			position += chunk;
		}
	} while (position < size);
	return offset;
}

static int receive_variables(struct pon_oam_session *session,
	const struct pon_oam_identity *identity, const uint8_t *input,
	size_t length, uint8_t *output, bool set)
{
	uint8_t onu[54] = {}, value[PON_OAM_FRAME_MAX];
	struct pon_oam_request request = {.version = session->extension_version};
	size_t position = 22, offset = 22;
	bool variables = false;

	memcpy(onu, identity->vendor, 4);
	memcpy(onu + 4, identity->model, 4);
	memcpy(onu + 8, identity->mac, 6);
	identity_field(onu + 14, 8, identity->hardware, sizeof(identity->hardware));
	identity_field(onu + 22, 16, identity->software, sizeof(identity->software));
	identity_field(onu + 38, 16, identity->equipment, sizeof(identity->equipment));
	output[21] = set ? 4 : 2;
	while (position < length && input[position]) {
		const uint8_t *data = NULL;
		size_t size = 0;
		uint8_t indication = 0x87;
		int result;

		if (position + 3 > length)
			return -EMSGSIZE;
		request.branch = input[position];
		request.leaf = be16(input + position + 1);
		oam_dbg("CTC %s branch=%02x leaf=%04x",
			set ? "set" : "get", request.branch, request.leaf);
		if (request.branch == 0x36 || request.branch == 0x37) {
			size_t width = request.branch == 0x36 ? 5 : 8;

			if (position + width > length || input[position + 3] != width - 4)
				return -EPROTO;
			if (offset + width > PON_OAM_FRAME_MAX)
				return -EMSGSIZE;
			memcpy(output + offset, input + position, width);
			request.object = input + position;
			request.object_size = width;
			offset += width;
			position += width;
			continue;
		}
		position += 3;
		request.parameters = NULL;
		request.parameter_size = 0;
		if (set) {
			/* These two actions have no width or data in the stock table. */
			bool no_data = (request.branch == 0xc9 && request.leaf == 1) ||
				(request.branch == 9 && request.leaf == 0xb);
			if (!no_data) {
				for (;;) {
					size_t chunk;

					if (position == length || input[position] & 0x80)
						return -EPROTO;
					chunk = input[position++] ? input[position - 1] : 128;
					if (position + chunk > length || size + chunk > sizeof(value))
						return -EMSGSIZE;
					memcpy(value + size, input + position, chunk);
					size += chunk;
					position += chunk;
					if (chunk != 128 || position + 3 >= length ||
					    input[position] != request.branch ||
					    be16(input + position + 1) != request.leaf)
						break;
					position += 3;
				}
			}
			auth_set_progress(session, request.branch);
			if (identity->set_parameter) {
				indication = identity->set_parameter(identity->backend_context, &request, value, size);
				oam_dbg("CTC set branch=%02x leaf=%04x size=%zu indication=%02x",
					request.branch, request.leaf, size, indication);
			}
		} else {
			/* AlarmThreshold Get carries its two-byte alarm ID, not another
			 * variable descriptor (stock eponoamd:0x417ba0). */
			if (request.branch == 0xc7 && request.leaf == 0x82) {
				if (position + 3 > length || input[position] != 2)
					return -EPROTO;
				request.parameters = input + position + 1;
				request.parameter_size = 2;
				position += 3;
			}
			if (request.branch == 0xc7 && request.leaf == 1) {
				data = onu;
				size = session->extension_version == 0x30 ? sizeof(onu) : 38;
			} else if (request.branch == 0xc7 && request.leaf == 3) {
				/* Stock chipset descriptor: vendor 0x0479, RTL9607 family
				 * 0x960701, CTC revision bytes 09/08, silicon revision 0. */
				static const uint8_t chipset[8] = {0x04, 0x79, 0x96, 0x07, 0x01, 0x09, 0x08, 0x00};

				data = chipset;
				size = sizeof(chipset);
			} else if (request.branch == 0xc7 && request.leaf == 2) {
				/* FirmwareVer is three version octets; the software identity
				 * string belongs to ONU SN (stock eponoamd:0x41e518). */
				data = identity->firmware;
				size = sizeof(identity->firmware);
			} else if (identity->get_parameter) {
				result = identity->get_parameter(identity->backend_context, &request, value, sizeof(value));
				if (result >= 0 && (size_t)result <= sizeof(value)) {
					data = value;
					size = result;
				} else if (result == -EOPNOTSUPP) {
					indication = 0x86;
				}
			}
		}
		result = variable_reply(output, offset, request.branch, request.leaf, data, size, indication);
		if (result < 0)
			return result;
		offset = result;
		variables = true;
	}
	if (!variables)
		return PON_OAM_IGNORED;
	/* CTC GET/SET responses end with a zero terminator (ponwrt ctc.rs). */
	if (offset >= PON_OAM_FRAME_MAX)
		return -EMSGSIZE;
	output[offset++] = 0;
	return offset < 60 ? 60 : offset;
}

static int receive_churning(struct pon_oam_session *session, const struct pon_oam_identity *identity,
	const uint8_t *input, size_t length, uint8_t *output)
{
	int size;

	if (length < 24 || input[22] != 0 || input[23] > 1)
		return -EPROTO;
	if (!identity->churning_key)
		return -EOPNOTSUPP;
	if (session->key_index != input[23])
		session->key_length = 0;
	size = identity->churning_key(identity->backend_context, input[23] ^ 1,
		session->key, session->key_length);
	if (size < 0)
		return size;
	session->key_index = input[23];
	session->key_length = size;
	output[21] = 9;
	output[22] = 1;
	output[23] = input[23] ^ 1;
	memcpy(output + 24, session->key, size);
	return 60;
}

int pon_oam_receive(struct pon_oam_session *session, const struct pon_oam_identity *identity,
		    const uint8_t *input, size_t length, uint8_t output[PON_OAM_FRAME_MAX])
{
	int ret;

	if (length < 18 || length > PON_OAM_FRAME_MAX || input[12] != 0x88 || input[13] != 9 || input[14] != 3)
		return -EPROTO;
	session->rx_frames++;
	if (!input[17]) {
		ret = receive_information(session, input, length);
		return ret < 0 ? ret : PON_OAM_HANDLED;
	}
	if (input[17] != 0xfe)
		return PON_OAM_IGNORED;
	if (length < 22)
		return -EMSGSIZE;
	if (!ctc_oui(input + 18) ||
	    (input[21] != PON_OAM_CTC_TYPE_GET && input[21] != PON_OAM_CTC_TYPE_SET &&
	     input[21] != PON_OAM_CTC_TYPE_AUTH && input[21] != PON_OAM_CTC_TYPE_CHURNING))
		return PON_OAM_IGNORED;
	/* OLT may issue CTC variable/auth requests while the IEEE discovery
	 * session is still settling; responding keeps the CTC session alive. */
	ethernet_header(session, identity, output, 0xfe);
	memcpy(output + 18, input + 18, 3);
	if (input[21] == PON_OAM_CTC_TYPE_AUTH)
		ret = receive_auth(session, identity, input, length, output);
	else if (input[21] == PON_OAM_CTC_TYPE_CHURNING)
		ret = receive_churning(session, identity, input, length, output);
	else if (input[21] == PON_OAM_CTC_TYPE_GET)
		ret = receive_variables(session, identity, input, length, output, false);
	else
		ret = receive_variables(session, identity, input, length, output, true);
	if (ret > PON_OAM_IGNORED) {
		session->extension_selected = true;
		memcpy(session->extension_oui, input + 18, 3);
	}
	/* GET/SET traffic is provisioning evidence only.  Information
	 * OUI/version negotiation is separate; only an explicit type-5
	 * confirmation updates the authentication result.  Neither proves
	 * end-to-end PPPoE authorisation or an OLT policy. */
	if (ret > PON_OAM_IGNORED && (input[21] == PON_OAM_CTC_TYPE_GET ||
					      input[21] == PON_OAM_CTC_TYPE_SET))
		session->provisioning_seen = true;
	return ret;
}
