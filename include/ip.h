/*
 * ip.h -- IPv4 (RFC 791) header, parsing and emission.
 */
#ifndef USSTACK_IP_H
#define USSTACK_IP_H

#include "common.h"

#define IP_HDR_MIN_LEN 20

#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1FFF

typedef struct PACKED {
    uint8_t  ver_ihl;      /* version (4) | header length in 32-bit words */
    uint8_t  tos;
    uint16_t total_len;    /* header + payload, network byte order */
    uint16_t id;
    uint16_t frag_off;     /* flags | fragment offset */
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src_ip;       /* network byte order */
    uint32_t dst_ip;
} ip_hdr_t;

static inline uint8_t ip_ihl(const ip_hdr_t *h) { return h->ver_ihl & 0x0F; }
static inline uint8_t ip_version(const ip_hdr_t *h) { return h->ver_ihl >> 4; }
static inline uint16_t ip_hdr_bytes(const ip_hdr_t *h) { return (uint16_t)(ip_ihl(h) * 4); }

/* Options follow the fixed header when IHL > 5. */
#define IP_MAX_OPTIONS 40

/* Parse-time result of a full validation pass over an IPv4 header. */
typedef enum {
    IP_OK = 0,
    IP_ERR_SHORT,          /* not enough bytes for the fixed header */
    IP_ERR_VERSION,        /* not IPv4 */
    IP_ERR_IHL,            /* header length < 5 or larger than the packet */
    IP_ERR_LENGTH,         /* total_len inconsistent with the buffer */
    IP_ERR_CHECKSUM,
    IP_ERR_FRAGMENT,       /* fragmented: we do not reassemble */
} ip_parse_status_t;

ip_parse_status_t ip_validate(const void *buf, size_t buf_len);
const char       *ip_parse_strerror(ip_parse_status_t st);

/*
 * Fill in a 20-byte IPv4 header (no options), leaving total_len and checksum
 * for ip_finalize() so the caller can add payload afterwards.
 */
void ip_build(ip_hdr_t *h, uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
              uint16_t ip_id, uint16_t payload_len, uint8_t ttl);

/* Set total_len and compute the header checksum. */
void ip_finalize(ip_hdr_t *h, uint16_t payload_len);

/*
 * Classify an IPv4 packet's destination against our address/mask.
 * Returns the local address to use as the source for replies, or 0 if the
 * packet is not for us and must be forwarded or dropped.
 */
uint32_t ip_dst_is_local(uint32_t dst_ip, uint32_t our_ip, uint32_t netmask);

/* Our subnet broadcast address. */
uint32_t ip_broadcast(uint32_t ip, uint32_t netmask);

#endif /* USSTACK_IP_H */