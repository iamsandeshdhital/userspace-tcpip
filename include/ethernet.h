/*
 * ethernet.h -- IEEE 802.3 / DIX Ethernet II framing (link layer).
 */
#ifndef USSTACK_ETHERNET_H
#define USSTACK_ETHERNET_H

#include "common.h"

#define ETH_HDR_LEN 14
#define ETH_MIN_FRAME 60

typedef struct PACKED {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;          /* network byte order */
} eth_hdr_t;

extern const uint8_t ETH_BROADCAST[6];

bool     eth_is_broadcast(const uint8_t dst[6]);
bool     eth_is_ours(const uint8_t dst[6], const uint8_t our_mac[6]);
void     eth_fmt_mac(const uint8_t mac[6], char *buf, size_t buflen);

#endif /* USSTACK_ETHERNET_H */