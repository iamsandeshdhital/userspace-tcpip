/*
 * test_tcp_header.c -- segment parsing and option encoding.
 */
#include "harness.h"
#include "tcp.h"
#include "checksum.h"

static void opt_collect(uint8_t kind, uint8_t len, const uint8_t *val, void *ctx)
{
    int *count = (int *)ctx;
    (void)kind; (void)len; (void)val;
    (*count)++;
}

void test_tcp_header(void)
{
    /* ---- option encoding: all four options fit in the 40-byte budget ---- */
    {
        uint8_t opts[TCP_MAX_OPTIONS];
        size_t n = tcp_build_options(opts, sizeof opts, 1460, 7, true,
                                    0x11223344, true);

        /* The block must be padded to a whole number of 32-bit words. */
        CHECK_EQ_INT(n % 4, 0);
        CHECK(n <= TCP_MAX_OPTIONS);

        /* MSS */
        CHECK_EQ_INT(opts[0], TCPOPT_MSS);
        CHECK_EQ_INT(opts[1], 4);
        CHECK_EQ_INT(rd16_be(opts + 2), 1460);

        /* SACK-permitted is a bare kind byte with no length. */
        CHECK_EQ_INT(opts[4], TCPOPT_SACK_PERMIT);

        /* Timestamps */
        CHECK_EQ_INT(opts[5], TCPOPT_TIMESTAMP);
        CHECK_EQ_INT(opts[6], 10);
        CHECK_EQ_HEX(rd32_be(opts + 7), 0x11223344);
        CHECK_EQ_HEX(rd32_be(opts + 11), 0x11223344);

        /* Window scale follows the timestamp */
        int idx = 19;
        CHECK_EQ_INT(opts[idx], TCPOPT_WINDOW_SCALE);
        CHECK_EQ_INT(opts[idx + 1], 3);
        CHECK_EQ_INT(opts[idx + 2], 7);

        /* No options means no block at all. */
        size_t m = tcp_build_options(opts, sizeof opts, 0, 0, false, 0, false);
        CHECK_EQ_INT(m, 0);
    }

    /* A window scale of zero is pointless and must be omitted. */
    {
        uint8_t opts[TCP_MAX_OPTIONS];
        size_t n = tcp_build_options(opts, sizeof opts, 1460, 0, false, 0,
                                    false);
        CHECK_EQ_INT(n % 4, 0);
        CHECK_EQ_INT(n, 4);
        CHECK_EQ_INT(opts[0], TCPOPT_MSS);
    }

    /* ---- option decoding through a full parse ---- */
    {
        uint8_t seg[128];
        uint8_t opts[TCP_MAX_OPTIONS];
        size_t opt_len = tcp_build_options(opts, sizeof opts, 1400, 5, true,
                                           0xAABBCCDD, true);
        size_t hdr_len = TCP_HDR_MIN_LEN + opt_len;

        memset(seg, 0, sizeof seg);
        wr16_be(seg + 0, 1234);
        wr16_be(seg + 2, 80);
        wr32_be(seg + 4, 0x11223344);
        wr32_be(seg + 8, 0x55667788);
        seg[12] = (uint8_t)((hdr_len / 4) << 4);
        seg[13] = TH_SYN | TH_ACK;
        wr16_be(seg + 14, 8192);
        memcpy(seg + TCP_HDR_MIN_LEN, opts, opt_len);

        tcp_seg_t s;
        CHECK(tcp_parse(seg, hdr_len, hdr_len, &s));

        CHECK_EQ_INT(s.src_port, 1234);
        CHECK_EQ_INT(s.dst_port, 80);
        CHECK_EQ_HEX(s.seq, 0x11223344);
        CHECK_EQ_HEX(s.ack, 0x55667788);
        CHECK_EQ_INT(s.flags, TH_SYN | TH_ACK);
        CHECK_EQ_INT(s.window, 8192);
        CHECK_EQ_INT(s.hdr_len, hdr_len);
        CHECK_EQ_INT(s.payload_len, 0);
        CHECK_EQ_INT(s.mss, 1400);
        CHECK_EQ_INT(s.wscale, 5);
        CHECK(s.sack_permitted);
        CHECK(s.ts_valid);
        CHECK_EQ_HEX(s.ts_val, 0xAABBCCDD);
    }

    /* ---- payload is located, not copied ---- */
    {
        uint8_t seg[64];
        memset(seg, 0, sizeof seg);
        seg[12] = (TCP_HDR_MIN_LEN / 4) << 4;
        seg[13] = TH_ACK | TH_PSH;
        memset(seg + TCP_HDR_MIN_LEN, 0x5A, 10);

        tcp_seg_t s;
        CHECK(tcp_parse(seg, 30, 30, &s));
        CHECK_EQ_INT(s.hdr_len, 20);
        CHECK_EQ_INT(s.payload_len, 10);
        CHECK_EQ_INT(s.payload[0], 0x5A);
        CHECK_EQ_INT(s.payload[9], 0x5A);

        /* Absent options must leave the defaults in place. */
        CHECK_EQ_INT(s.mss, 0);
        CHECK_EQ_INT(s.wscale, 0xFF);
        CHECK(!s.ts_valid);
    }

    /* ---- malformed headers are rejected ---- */
    {
        tcp_seg_t s;

        /* Too short for a header at all. */
        uint8_t tiny[10] = { 0 };
        CHECK(!tcp_parse(tiny, sizeof tiny, sizeof tiny, &s));

        /* Data offset below the 5-word minimum. */
        uint8_t seg[64];
        memset(seg, 0, sizeof seg);
        seg[12] = 0x40;                   /* 4 words */
        CHECK(!tcp_parse(seg, 40, 40, &s));

        /* Data offset beyond the bytes available. */
        memset(seg, 0, sizeof seg);
        seg[12] = 0xF0;                   /* 15 words = 60 bytes, only 40 given */
        CHECK(!tcp_parse(seg, 40, 40, &s));
    }

    /* ---- option edge cases ---- */
    {
        uint8_t seg[64];
        tcp_seg_t s;

        /* End-of-options terminates the list: an MSS after it is ignored. */
        uint8_t opts[8];
        memset(opts, 0, sizeof opts);
        opts[0] = TCPOPT_EOL;
        opts[1] = TCPOPT_MSS;
        opts[2] = 4;
        wr16_be(opts + 3, 1460);

        memset(seg, 0, sizeof seg);
        size_t hdr_len = TCP_HDR_MIN_LEN + 8;
        seg[12] = (uint8_t)((hdr_len / 4) << 4);
        memcpy(seg + TCP_HDR_MIN_LEN, opts, 8);

        CHECK(tcp_parse(seg, hdr_len, hdr_len, &s));
        CHECK_EQ_INT(s.mss, 0);

        /* A length byte that overruns the block must stop the walk. */
        memset(opts, 0, sizeof opts);
        opts[0] = TCPOPT_MSS;
        opts[1] = 40;                     /* claims 40 bytes, only 8 exist */
        wr16_be(opts + 2, 1460);
        memcpy(seg + TCP_HDR_MIN_LEN, opts, 8);

        CHECK(tcp_parse(seg, hdr_len, hdr_len, &s));
        CHECK_EQ_INT(s.mss, 0);

        /* No padding is emitted, so the count callback sees exactly the
         * options that carry meaning. */
        memset(opts, 0, sizeof opts);
        opts[0] = TCPOPT_NOP;
        opts[1] = TCPOPT_NOP;
        opts[2] = TCPOPT_SACK_PERMIT;
        int n = 0;
        tcp_parse_options(opts, 3, opt_collect, &n);
        CHECK_EQ_INT(n, 1);
    }

    /* ---- an excessive window scale is clamped (RFC 7323 allows 0..14) ---- */
    {
        uint8_t seg[64];
        memset(seg, 0, sizeof seg);

        uint8_t opts[4];
        opts[0] = TCPOPT_WINDOW_SCALE;
        opts[1] = 3;
        opts[2] = 40;                     /* out of range */

        size_t hdr_len = TCP_HDR_MIN_LEN + 4;
        seg[12] = (uint8_t)((hdr_len / 4) << 4);
        memcpy(seg + TCP_HDR_MIN_LEN, opts, 4);

        tcp_seg_t s;
        CHECK(tcp_parse(seg, hdr_len, hdr_len, &s));
        CHECK_EQ_INT(s.wscale, 14);
    }

    /* ---- flag rendering ---- */
    {
        char buf[32];

        tcp_flags_str(TH_SYN | TH_ACK, buf, sizeof buf);
        CHECK_STR(buf, "SYN,ACK");

        tcp_flags_str(TH_FIN | TH_ACK | TH_PSH, buf, sizeof buf);
        CHECK_STR(buf, "FIN,PSH,ACK");

        tcp_flags_str(TH_RST, buf, sizeof buf);
        CHECK_STR(buf, "RST");

        tcp_flags_str(0, buf, sizeof buf);
        CHECK_STR(buf, "none");
    }

    /* ---- pseudo-header checksum must be address sensitive ---- */
    {
        uint8_t seg[32];
        memset(seg, 0, sizeof seg);
        wr16_be(seg + 0, 1000);
        wr16_be(seg + 2, 2000);
        wr16_be(seg + 14, 4096);

        uint32_t a, b, c;
        inet_pton(AF_INET, "10.0.0.1", &a);
        inet_pton(AF_INET, "10.0.0.2", &b);
        inet_pton(AF_INET, "10.0.0.3", &c);

        uint16_t ab = harness_tcp_csum(a, b, seg, TCP_HDR_MIN_LEN);
        uint16_t ba = harness_tcp_csum(b, a, seg, TCP_HDR_MIN_LEN);
        uint16_t ac = harness_tcp_csum(a, c, seg, TCP_HDR_MIN_LEN);

        /* Changing either address must change the checksum, which is the
         * whole point of the pseudo-header. */
        CHECK(ab != ba);
        CHECK(ab != ac);
    }
}