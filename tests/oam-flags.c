// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "pon-oam.h"
bool pon_oam_debug;
int main(void)
{
    static const unsigned int peers[] = {0, 8, 16, 32, 64, 0xffff};
    struct pon_oam_session session = {0};
    struct pon_oam_identity identity = {.mac = {2, 1, 2, 3, 4, 5}};
    unsigned char frame[PON_OAM_FRAME_MAX];
    unsigned int present, i;
    for (present = 0; present < 2; present++) {
        for (i = 0; i < sizeof(peers) / sizeof(peers[0]); i++) {
            pon_oam_reset(&session);
            session.have_peer = present;
            session.peer_flags = peers[i];
            pon_oam_information(&session, &identity, frame);
            unsigned int flags = (frame[15] << 8) | frame[16];
            unsigned int expected = present ? 0x10 : 8;
            expected |= (peers[i] & 16) ? 64 : (peers[i] & 8) ? 32 : 0;
            assert(flags == expected);
            assert(!(flags & 7));
            assert(!memcmp(frame + 6, identity.mac, 6));
            assert(!memcmp(frame + 27, identity.mac, 6));
            assert(!pon_oam_discovery_complete(&session));
            session.local_echoed = true;
            assert(pon_oam_discovery_complete(&session) == (present && (peers[i] & 0x10)));
        }
    }
    puts("12 normal Information states: no fault/Dying Gasp flags; MAC preserved");
    return 0;
}
