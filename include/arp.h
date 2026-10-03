/*
 * arp.h -- Address Resolution Protocol (RFC 826).
 *
 * With a TAP device the stack is a real Ethernet endpoint, so before it can
 * hand an IP packet to the NIC it must know the link-layer address of the
 * next hop.  This is a small, ageing cache plus request/reply handling.
 */
#ifndef USSTACK_ARP_H
#define USSTACK_ARP_H

#include "common.h"
#include "ethernet.h"

#define ARP_TABLE_SIZE   32
#define ARP_ENTRY_TIMEOUT_MS 60000

#define ARP_HDR_LEN 28

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_HTYPE_ETHER 1

typedef struct PACKED {
    uint16_t htype;      /* hardware type, e.g. 1 for Ethernet */
    uint16_t ptype;      /* protocol type, e.g. 0x0800 for IPv4 */
    uint8_t  hlen;       /* hardware address length (6) */
    uint8_t  plen;       /* protocol address length (4) */
    uint16_t opcode;
    uint8_t  sha[6];     /* sender hardware address */
    uint8_t  spa[4];     /* sender protocol address */
    uint8_t  tha[6];     /* target hardware address */
    uint8_t  tpa[4];     /* target protocol address */
} arp_pkt_t;

typedef struct {
    uint32_t ip;         /* network byte order */
    uint8_t  mac[6];
    uint64_t updated_ms;
    bool     valid;
} arp_entry_t;

typedef struct {
    arp_entry_t table[ARP_TABLE_SIZE];
    uint64_t    lookups, hits, misses;
} arp_cache_t;

void     arp_init(arp_cache_t *c);
void     arp_flush(arp_cache_t *c);
void     arp_insert(arp_cache_t *c, uint32_t ip, const uint8_t mac[6]);
/* Look up an address.  Expired entries are treated as absent. */
bool     arp_lookup(arp_cache_t *c, uint32_t ip, uint8_t mac_out[6]);
size_t   arp_count(const arp_cache_t *c);
const arp_entry_t *arp_get(const arp_cache_t *c, size_t idx);

#endif /* USSTACK_ARP_H */