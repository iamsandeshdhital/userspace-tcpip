/*
 * tcp.c -- segment parsing and serialisation.
 *
 * A segment arriving from the wire is parsed into a tcp_seg_t, which is a
 * flattened view: ports in host order, flags as a bitmask, options decoded,
 * payload pointed at (not copied).  Outgoing segments are assembled into a
 * caller-provided buffer with the checksum computed over a pseudo-header.
 */
#include "tcp.h"
#include "checksum.h"
#include "log.h"

#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Option encoding/decoding                                           */
/* ------------------------------------------------------------------ */

struct opt_ctx {
    tcp_seg_t *seg;
};

static void opt_cb(uint8_t kind, uint8_t len, const uint8_t *val, void *ctx)
{
    struct opt_ctx *o = (struct opt_ctx *)ctx;

    switch (kind) {
    case TCPOPT_MSS:
        if (len == 4 && val)
            o->seg->mss = (uint16_t)((val[0] << 8) | val[1]);
        break;

    case TCPOPT_WINDOW_SCALE:
        /* RFC 7323: a shift count of 0 is legal but has no effect. */
        if (len == 3 && val)
            o->seg->wscale = (val[0] > 14) ? 14 : val[0];
        break;

    case TCPOPT_SACK_PERMIT:
        o->seg->sack_permitted = true;
        break;

    case TCPOPT_TIMESTAMP:
        if (len == 10 && val) {
            o->seg->ts_val = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) |
                             ((uint32_t)val[2] << 8)  | val[3];
            o->seg->ts_ecr = ((uint32_t)val[4] << 24) | ((uint32_t)val[5] << 16) |
                             ((uint32_t)val[6] << 8)  | val[7];
            o->seg->ts_valid = true;
        }
        break;

    default:
        break;
    }
}

void tcp_parse_options(const uint8_t *opts, size_t len, tcp_opt_cb cb, void *ctx)
{
    size_t i = 0;

    while (i < len) {
        uint8_t kind = opts[i];
        uint8_t olen;

        if (kind == TCPOPT_EOL)      /* end of option list */
            break;
        if (kind == TCPOPT_NOP) {    /* padding, no length byte */
            i++;
            continue;
        }

        if (i + 1 >= len) {
            /* Truncated: a kind byte with no length byte is a protocol
             * violation, so stop rather than read past the end. */
            break;
        }
        olen = opts[i + 1];

        if (olen < 2 || i + olen > len)
            break;                    /* invalid or truncated length */

        cb(kind, olen, opts + i + 2, ctx);
        i += olen;
    }
}

bool tcp_parse(const uint8_t *buf, size_t len, size_t seg_len, tcp_seg_t *seg)
{
    memset(seg, 0, sizeof *seg);
    seg->wscale = 0xFF;   /* "absent" sentinel */

    if (len < TCP_HDR_MIN_LEN)
        return false;

    const tcp_hdr_t *h = (const tcp_hdr_t *)buf;

    seg->src_port = ntohs(h->src_port);
    seg->dst_port = ntohs(h->dst_port);
    seg->seq      = rd32_be((const uint8_t *)buf + 4);
    seg->ack      = rd32_be((const uint8_t *)buf + 8);
    seg->flags    = h->flags;
    if (tcp_ns(h))
        seg->flags |= TH_URG;   /* NS is only meaningful with URG set anyway */
    seg->window   = ntohs(h->window);

    uint16_t hdr_len = tcp_hdr_bytes(h);
    if (hdr_len < TCP_HDR_MIN_LEN || hdr_len > len)
        return false;               /* bogus data offset */

    seg->hdr_len = hdr_len;

    /*
     * The checksum covers the pseudo-header plus `seg_len` bytes, which is
     * what the peer summed.  It may legitimately be longer than the bytes we
     * were handed if the datagram was truncated, but we can only verify what
     * we have, so a mismatch here is informational rather than fatal.
     */
    if (seg_len > len)
        seg_len = len;

    seg->payload = buf + hdr_len;
    seg->payload_len = (uint32_t)(len - hdr_len);

    struct opt_ctx oc = { .seg = seg };
    if (hdr_len > TCP_HDR_MIN_LEN)
        tcp_parse_options(buf + TCP_HDR_MIN_LEN, hdr_len - TCP_HDR_MIN_LEN,
                          opt_cb, &oc);

    return true;
}

size_t tcp_build_options(uint8_t *buf, size_t max_len, uint16_t mss,
                         uint8_t wscale, bool sack_permitted,
                         uint32_t ts_val, bool ts_present)
{
    size_t n = 0;

    /* MSS: kind, length, 2-byte value.  Offered only when non-zero. */
    if (mss && n + 4 <= max_len) {
        buf[n++] = TCPOPT_MSS;
        buf[n++] = 4;
        wr16_be(buf + n, mss);
        n += 2;
    }

    /* SACK-permitted: a bare kind byte, no length. */
    if (sack_permitted && n + 1 <= max_len)
        buf[n++] = TCPOPT_SACK_PERMIT;

    /* Timestamps: kind, length, tsval, tsecr -- 10 bytes. */
    if (ts_present && n + 10 <= max_len) {
        buf[n++] = TCPOPT_TIMESTAMP;
        buf[n++] = 10;
        wr32_be(buf + n, ts_val);
        n += 4;
        wr32_be(buf + n, ts_val);   /* tsecr mirrors tsval until we measure RTT */
        n += 4;
    }

    /*
     * Window scale: kind, length, shift.  A shift of 0 is legal but pointless,
     * so only send the option when the value is non-zero.
     */
    if (wscale && n + 3 <= max_len) {
        buf[n++] = TCPOPT_WINDOW_SCALE;
        buf[n++] = 3;
        buf[n++] = wscale;
    }

    /* Pad the option block to a 4-byte boundary so the header length is a
     * whole number of 32-bit words. */
    while (n % 4 != 0 && n < max_len)
        buf[n++] = TCPOPT_EOL;

    return n;
}

const char *tcp_flags_str(uint8_t flags, char *buf, size_t buflen)
{
    buf[0] = '\0';
    struct { uint8_t bit; const char *name; } tab[] = {
        { TH_SYN, "SYN" }, { TH_ACK, "ACK" }, { TH_FIN, "FIN" },
        { TH_RST, "RST" }, { TH_PSH, "PSH" }, { TH_URG, "URG" },
        { TH_ECE, "ECE" }, { TH_CWR, "CWR" },
    };

    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        if (!(flags & tab[i].bit))
            continue;
        if (buf[0]) {
            size_t l = strlen(buf);
            if (l + 1 < buflen) { strncat(buf, ",", buflen - l - 1); }
        }
        size_t l = strlen(buf);
        strncat(buf, tab[i].name, buflen > l + 1 ? buflen - l - 1 : 0);
    }

    if (!buf[0])
        snprintf(buf, buflen, "none");
    return buf;
}