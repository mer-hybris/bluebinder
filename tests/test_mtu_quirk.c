/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "mtu_quirk.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t connection[] = {
    4, 0x3e, 19, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t request[] = {2,0,2,7,0,3,0,4,0,2,5,2};
static const uint8_t response[] = {2,0,0x12,7,0,3,0,4,0,3,23,0};

static void start(struct mtu_quirk *q)
{
    uint8_t event[sizeof(connection)];
    memcpy(event, connection, sizeof(event));
    mtu_quirk_reset(q);
    assert(!mtu_quirk_rx(q, event, sizeof(event)));
    mtu_quirk_tx(q, request, sizeof(request));
}

static void unchanged(struct mtu_quirk *q, const uint8_t *input, size_t len)
{
    uint8_t packet[64];
    memcpy(packet, input, len);
    assert(!mtu_quirk_rx(q, packet, len));
    assert(!memcmp(packet, input, len));
}

int main(void)
{
    struct mtu_quirk q;
    uint8_t p[64], event[34] = {4,0x3e,31,0x0a,0,0,2};
    unsigned int i;
    start(&q);
    memcpy(p,response,sizeof(response));
    assert(mtu_quirk_rx(&q,p,sizeof(response)));
    assert(p[2]==0x22);
    p[2]=0x12;
    assert(!memcmp(p,response,sizeof(response)));
    unchanged(&q,response,sizeof(response)); /* one repair per connection */

    mtu_quirk_reset(&q);
    assert(!mtu_quirk_rx(&q,event,sizeof(event)));
    mtu_quirk_tx(&q,request,sizeof(request));
    memcpy(p,response,sizeof(response));
    assert(mtu_quirk_rx(&q,p,sizeof(response))); /* enhanced connection event */

    mtu_quirk_reset(&q);
    mtu_quirk_tx(&q,request,sizeof(request));
    unchanged(&q,response,sizeof(response)); /* unknown / classic handle */
    start(&q);
    memcpy(p,connection,sizeof(connection));
    assert(!mtu_quirk_rx(&q,p,sizeof(connection)));
    unchanged(&q,response,sizeof(response)); /* new connection needs new request */

    for(i=0;i<sizeof(response);i++) {
        start(&q);
        unchanged(&q,response,i); /* every truncation */
    }
    for(i=0;i<sizeof(response);i++) {
        if(i==10) continue; /* This mutation is another valid MTU. */
        start(&q);
        memcpy(p,response,sizeof(response));
        p[i]^=0x80;
        unchanged(&q,p,sizeof(response)); /* invalid fields, other handle/MTU */
    }
    start(&q);
    memcpy(p,response,sizeof(response));p[2]=0x22;
    unchanged(&q,p,sizeof(response)); /* valid response */
    start(&q);
    memcpy(p,response,sizeof(response));p[2]=0x02;
    unchanged(&q,p,sizeof(response)); /* non-flushable start */
    start(&q);
    memcpy(p,response,sizeof(response));p[10]=151;
    assert(mtu_quirk_rx(&q,p,sizeof(response)) && p[10]==151);
    start(&q);
    memcpy(p,response,sizeof(response));p[10]=22;
    unchanged(&q,p,sizeof(response)); /* invalid MTU */

    start(&q);
    memcpy(p,response,sizeof(response));p[2]=0x22;p[3]=4;
    unchanged(&q,p,9); /* start of a fragmented response */
    unchanged(&q,response,sizeof(response)); /* must not rewrite continuation */
    start(&q);
    memcpy(p,response,sizeof(response));p[9]=0x1b;
    unchanged(&q,p,sizeof(response)); /* unrelated first ATT packet */
    unchanged(&q,response,sizeof(response));

    start(&q);
    { uint8_t disconnect[] = {4,5,4,0,0,2,0x13};
      unchanged(&q,disconnect,sizeof(disconnect)); }
    unchanged(&q,response,sizeof(response));
    start(&q);
    { uint8_t reset[] = {4,0x0e,4,1,3,0x0c,0};
      unchanged(&q,reset,sizeof(reset)); }
    unchanged(&q,response,sizeof(response));
    start(&q);
    mtu_quirk_reset(&q); /* HAL power-cycle */
    unchanged(&q,response,sizeof(response));
    start(&q);
    { uint8_t classic[] = {4,3,11,0,0,2,0,0,0,0,0,0,1,0};
      unchanged(&q,classic,sizeof(classic)); }
    unchanged(&q,response,sizeof(response));
    puts("MTU boundary regression cases passed");
    return 0;
}
