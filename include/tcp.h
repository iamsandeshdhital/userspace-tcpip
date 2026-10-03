/*
 * tcp.h -- TCP segment format and the parsed-segment view handed to the
 * protocol engine.
 *
 * The header layout is fixed at 20 bytes plus options; the high nibble of the
 * offset byte counts 32-bit words, so hdr_len = (offset & 0xF) * 4.
 */
#ifndef USSTACK_TCP_H
#define USSTACK_TCP_H

#include "common.h"

#define TCP_HDR_MIN_LEN 20
#define TCP_MAX_OPTIONS 40

typedef struct PACKED {
    uint16_t src_port;      /* network byte order */
    uint16_t dst_port;      /* network byte order */
    uint32_t seq;           /* network byte order */
    uint32_t ack;           /* network byte order */
    uint8_t  offset_flags;  /* data offset (4b) | reserved (3b) | NS (1b) */
    uint8_t  flags;         /* FIN SYN RST PSH ACK URG ECE CWR */
    uint16_t window;        /* network byte order */
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_hdr_t;

static inline uint16_t tcp_hdr_bytes(const tcp_hdr_t *h)
{
    return (uint16_t)((h->offset_flags >> 4) * 4);
}
static inline uint8_t tcp_ns(const tcp_hdr_t *h) { return h->offset_flags & 0x01; }

/* TCP option kinds */
#define TCPOPT_EOL          0
#define TCPOPT_NOP          1
#define TCPOPT_MSS          2
#define TCPOPT_WINDOW_SCALE 3
#define TCPOPT_SACK_PERMIT  4
#define TCPOPT_SACK         5
#define TCPOPT_TIMESTAMP    8

/*
 * A segment after parsing.  `payload` aliases the receive buffer -- it is not
 * owned and must not be freed by the caller.
 */
typedef struct {
    uint16_t src_port;      /* host byte order */
    uint16_t dst_port;      /* host byte order */
    uint32_t seq;           /* network byte order */
    uint32_t ack;           /* network byte order */
    uint8_t  flags;
    uint16_t window;        /* raw advertised window, host byte order */
    uint16_t hdr_len;       /* bytes consumed by header + options */
    const uint8_t *payload;
    uint32_t payload_len;

    /* Parsed options. */
    uint16_t mss;           /* 0 if absent */
    uint8_t  wscale;        /* 0xFF if absent (illegal) */
    bool     sack_permitted;
    uint32_t ts_val, ts_ecr;/* 0 if absent */
    bool     ts_valid;

    uint32_t src_ip, dst_ip; /* network byte order, for the pseudo-header */
} tcp_seg_t;

/*
 * Parse a segment.  On success `hdr_len` is the header length including
 * options and the struct is filled in.  Returns false on malformed input.
 * `seg_len` is the full segment length (header + payload) as it will appear on
 * the wire, used for the checksum pseudo-header.
 */
bool tcp_parse(const uint8_t *buf, size_t len, size_t seg_len, tcp_seg_t *seg);

/*
 * Serialise options into `buf` (must have room for `max_len` bytes).
 * Returns the number of bytes written.  Window scale is omitted when 0
 * because scaling of 0 is equivalent to no scaling and it saves two bytes.
 */
size_t tcp_build_options(uint8_t *buf, size_t max_len, uint16_t mss,
                         uint8_t wscale, bool sack_permitted,
                         uint32_t ts_val, bool ts_present);

/* Walk an option block, invoking cb for each option. */
typedef void (*tcp_opt_cb)(uint8_t kind, uint8_t len, const uint8_t *val, void *ctx);
void tcp_parse_options(const uint8_t *opts, size_t len, tcp_opt_cb cb, void *ctx);

/* Human-readable "SYN,ACK" style flag string into a caller buffer. */
const char *tcp_flags_str(uint8_t flags, char *buf, size_t buflen);

#endif /* USSTACK_TCP_H */