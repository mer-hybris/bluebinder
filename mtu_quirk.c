/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "mtu_quirk.h"

#include <string.h>

#define LE_LINK 1
#define RECEIVED_ACL 2
#define SENT_MTU 4

static unsigned int read_le16(const uint8_t *p)
{
    return p[0] | ((unsigned int)p[1] << 8);
}

void mtu_quirk_reset(struct mtu_quirk *quirk)
{
    memset(quirk, 0, sizeof(*quirk));
}

/* Complete H4 ACL packet containing exactly one ATT MTU exchange PDU. */
static bool is_mtu(const uint8_t *packet, size_t len, uint8_t opcode)
{
    return len == 12 && packet[0] == 2 &&
        read_le16(packet + 3) == 7 && read_le16(packet + 5) == 3 &&
        read_le16(packet + 7) == 4 && packet[9] == opcode &&
        read_le16(packet + 10) >= 23 && read_le16(packet + 10) <= 517;
}

void mtu_quirk_tx(struct mtu_quirk *quirk, const uint8_t *packet, size_t len)
{
    if (is_mtu(packet, len, 2)) {
        const unsigned int flags = read_le16(packet + 1);
        const unsigned int handle = flags & 0x0fff;
        /* Only a start packet, without broadcast flags, on a fresh LE link. */
        if (((flags >> 12) == 0 || (flags >> 12) == 2) &&
            quirk->links[handle] == LE_LINK) {
            quirk->links[handle] |= SENT_MTU;
        }
    }
}

bool mtu_quirk_rx(struct mtu_quirk *quirk, uint8_t *packet, size_t len)
{
    if (len >= 3 && packet[0] == 4 && len == (size_t)packet[2] + 3) {
        if (packet[1] == 0x3e &&
            ((len == 22 && packet[3] == 1) ||
             (len == 34 && packet[3] == 0x0a)) && packet[4] == 0) {
            const unsigned int handle = read_le16(packet + 5);
            if (handle < 4096)
                quirk->links[handle] = LE_LINK;
        } else if (((packet[1] == 5 && len == 7) ||
                    (packet[1] == 3 && len == 14)) && packet[3] == 0) {
            const unsigned int handle = read_le16(packet + 4);
            if (handle < 4096)
                quirk->links[handle] = 0;
        } else if (packet[1] == 0x0e && len == 7 &&
                   read_le16(packet + 4) == 0x0c03 && packet[6] == 0) {
            mtu_quirk_reset(quirk);
        }
    } else if (len >= 5 && packet[0] == 2) {
        const unsigned int flags = read_le16(packet + 1);
        const unsigned int handle = flags & 0x0fff;
        const uint8_t state = quirk->links[handle];
        /* Any earlier fragment disqualifies repair, including truncated data. */
        quirk->links[handle] = (state | RECEIVED_ACL) & ~SENT_MTU;
        if (state == (LE_LINK | SENT_MTU) && (flags >> 12) == 1 &&
            is_mtu(packet, len, 3)) {
            /* Some controllers mislabel the first complete MTU response as a
             * continuation. With no previous RX fragment on this LE link,
             * and a matching MTU request, only this header can be repaired.
             * Keep the controller's actual MTU and all other bytes unchanged.
             */
            packet[2] = (packet[2] & 0x0f) | 0x20;
            return true;
        }
    }
    return false;
}
