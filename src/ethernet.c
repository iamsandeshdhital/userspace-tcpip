#include "ethernet.h"

#include <stdio.h>

const uint8_t ETH_BROADCAST[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

bool eth_is_broadcast(const uint8_t dst[6])
{
    return memcmp(dst, ETH_BROADCAST, 6) == 0;
}

bool eth_is_ours(const uint8_t dst[6], const uint8_t our_mac[6])
{
    if (eth_is_broadcast(dst))
        return true;

    /*
     * Accept our unicast address.  Promiscuous/multicast delivery is not
     * implemented: a TUN/TAP device only sees frames addressed to it anyway.
     */
    return memcmp(dst, our_mac, 6) == 0;
}

void eth_fmt_mac(const uint8_t mac[6], char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}