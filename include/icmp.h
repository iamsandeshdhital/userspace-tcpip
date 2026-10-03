/*
 * icmp.h -- ICMPv4 (RFC 792) and the ICMP extensions we actually need.
 *
 * Used for two things in this stack:
 *   - Echo request/reply, which is how `ping` is implemented at L3.
 *   - Destination Unreachable (port unreachable), which a listening TCP socket
 *     must emit when a segment arrives for a connection that does not exist.
 *     This is the standard way a host learns that a connection was refused.
 */
#ifndef USSTACK_ICMP_H
#define USSTACK_ICMP_H

#include "common.h"
#include "ip.h"

#define ICMP_HDR_LEN 4

/* Types */
#define ICMP_ECHOREPLY      0
#define ICMP_UNREACH        3
#define ICMP_SOURCEQUENCH   4
#define ICMP_REDIRECT       5
#define ICMP_ECHO           8
#define ICMP_TIMXCEED      11
#define ICMP_PARAMPROB     12

/* Codes for ICMP_UNREACH */
#define ICMP_UNREACH_NET       0
#define ICMP_UNREACH_HOST      1
#define ICMP_UNREACH_PROTO     2
#define ICMP_UNREACH_PORT      3
#define ICMP_UNREACH_NEEDFRAG  4

/* Codes for ICMP_TIMXCEED */
#define ICMP_TIMXCEED_INTRANS  0
#define ICMP_TIMXCEED_REASS    1

/* Everything from the ICMP header up to and including the 8 original bytes
 * that triggered the error (RFC 792). */
#define ICMP_QUOTE_LEN (ICMP_HDR_LEN + IP_HDR_MIN_LEN + 8)

typedef struct PACKED {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    /* Rest of the ICMP body varies by type. */
} icmp_hdr_t;

typedef struct PACKED {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_echo_t;

typedef struct PACKED {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t unused;
} icmp_err_t;

/* Combined echo round-trip bookkeeping, used by the CLI's ping. */
typedef struct {
    bool     outstanding;
    uint16_t id;
    uint16_t seq;
    uint64_t sent_ms;
} icmp_ping_t;

/* Compute/recompute the ICMP checksum over the first `len` bytes. */
void icmp_finalize(void *buf, size_t len);

#endif /* USSTACK_ICMP_H */