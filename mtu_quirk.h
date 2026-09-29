/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef BLUEBINDER_MTU_QUIRK_H
#define BLUEBINDER_MTU_QUIRK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-handle startup state. No payload reassembly or general flag repair. */
struct mtu_quirk {
    uint8_t links[4096];
};

void mtu_quirk_reset(struct mtu_quirk *quirk);
void mtu_quirk_tx(struct mtu_quirk *quirk, const uint8_t *packet, size_t len);
bool mtu_quirk_rx(struct mtu_quirk *quirk, uint8_t *packet, size_t len);

#endif
