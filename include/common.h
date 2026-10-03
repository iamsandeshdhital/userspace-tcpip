/*
 * common.h -- shared types, byte-order helpers and small utilities.
 *
 * Design note: every 16/32-bit protocol field on the wire is in network byte
 * order.  We keep IP addresses and TCP sequence numbers as uint32_t values
 * *already* in network byte order everywhere in the stack, so no htonl()/ntohl()
 * dance is needed.  Port numbers are stored in host byte order internally and
 * converted only when a header is written or read.
 */
#ifndef USSTACK_COMMON_H
#define USSTACK_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>   /* inet_pton, inet_ntop, htons, ntohs */

/*
 * Packed structs let us address fields directly in buffers that arrive from
 * the TUN device.  Those buffers have no alignment guarantees, so a plain
 * struct with natural alignment would be undefined behaviour on strict-align
 * targets.  __attribute__((packed)) makes the compiler emit byte-wise or
 * unaligned-safe accesses instead.
 */
#if defined(__GNUC__) || defined(__clang__)
#  define PACKED   __attribute__((packed))
#  define UNUSED   __attribute__((unused))
#else
#  define PACKED
#  define UNUSED
#endif

#define USSTACK_VERSION "1.0.0"

/* ------------------------------------------------------------------ */
/* Serial number arithmetic (RFC 1982).                                */
/*                                                                     */
/* Plain `<` / `>` on 32-bit sequence numbers breaks at wraparound, so  */
/* every comparison goes through a signed difference.  Works for       */
/* distances < 2^31, which is guaranteed by RFC 1982 as long as the   */
/* window never exceeds 2^31 bytes.                                    */
/* ------------------------------------------------------------------ */
#define SEQ_LT(a, b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <  0)
#define SEQ_LEQ(a, b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a, b)   ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >  0)
#define SEQ_GEQ(a, b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/* Bounds used throughout the stack. */
#define USSTACK_MTU_DEFAULT      1500
#define USSTACK_TTL_DEFAULT        64
#define USSTACK_MSS_DEFAULT      1460   /* 1500 - 20 (IP) - 20 (TCP) */

/* Per-socket buffer sizes.  These define the advertised receive window. */
#define TCP_RXBUF_SIZE        (64 * 1024)
#define TCP_TXBUF_SIZE        (64 * 1024)

/* Retransmission timer bounds (milliseconds), RFC 6298. */
#define TCP_RTO_MIN_MS            200
#define TCP_RTO_MAX_MS         60000
#define TCP_RTO_INITIAL_MS      1000
#define TCP_DELAYED_ACK_MS       100
#define TCP_TIME_WAIT_MS       120000   /* 2 * MSL, MSL = 60s */
#define TCP_MAX_RETRANSMITS         12   /* -> RST, connection torn down */

/* Sequence-space control flags. */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806

/* Network-byte-order (big-endian) load/store helpers. */
static inline uint16_t rd16_be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void     wr16_be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline uint32_t rd32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static inline void wr32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

#endif /* USSTACK_COMMON_H */