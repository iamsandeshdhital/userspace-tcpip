/*
 * test_icmp.c -- echo request/reply through the full receive and send path.
 */
#include "harness.h"
#include "icmp.h"
#include "checksum.h"

void test_icmp(void)
{
    wire_t w;
    capture_t cap;

    /* TUN mode: the device hands over bare IPv4 datagrams. */
    wire_init(&w, false);
    harness_attach_capture(&w.sa, &cap);

    uint32_t peer;
    inet_pton(AF_INET, "192.168.0.9", &peer);

    const size_t payload_len = 32;
    uint8_t pkt[128];
    size_t len = harness_icmp_echo(pkt, peer, w.ip_a, 0x1234, 7, payload_len);

    /* The request we built must itself be well formed. */
    CHECK(ip_validate(pkt, len) == IP_OK);
    CHECK(csum16_verify(pkt + IP_HDR_MIN_LEN, len - IP_HDR_MIN_LEN, 2));

    net_rx(&w.sa, pkt, len);

    CHECK_EQ_INT(cap.count, 1);
    if (cap.count < 1) {
        wire_free(&w);
        return;
    }

    const uint8_t *out = cap.buf[0];
    size_t out_len = cap.len[0];

    CHECK_EQ_INT(out_len, len);
    CHECK(ip_validate(out, out_len) == IP_OK);

    const ip_hdr_t *iph = (const ip_hdr_t *)out;
    CHECK_EQ_INT(iph->proto, IP_PROTO_ICMP);
    CHECK_EQ_INT(iph->ttl, USSTACK_TTL_DEFAULT);

    /* The reply comes from us and is addressed to the requester. */
    CHECK_EQ_HEX(iph->src_ip, w.ip_a);
    CHECK_EQ_HEX(iph->dst_ip, peer);

    const icmp_echo_t *echo = (const icmp_echo_t *)(out + IP_HDR_MIN_LEN);
    CHECK_EQ_INT(echo->type, ICMP_ECHOREPLY);
    CHECK_EQ_INT(echo->code, 0);
    CHECK_EQ_INT(ntohs(echo->id), 0x1234);
    CHECK_EQ_INT(ntohs(echo->seq), 7);

    /* Both checksums must verify against the emitted bytes. */
    CHECK(csum16_verify(out, 20, 10));
    CHECK(csum16_verify(out + IP_HDR_MIN_LEN, out_len - IP_HDR_MIN_LEN, 2));

    /* The payload must be echoed back unchanged. */
    CHECK_EQ_INT(memcmp(out + IP_HDR_MIN_LEN + 8,
                        pkt + IP_HDR_MIN_LEN + 8, payload_len), 0);

    /* An unknown destination must be answered with an unreachable. */
    cap.count = 0;
    inet_pton(AF_INET, "203.0.113.1", &peer);
    len = harness_icmp_echo(pkt, peer, w.ip_a, 0x1234, 8, 16);
    net_rx(&w.sa, pkt, len);

    CHECK_EQ_INT(cap.count, 1);
    if (cap.count >= 1) {
        const ip_hdr_t *iph2 = (const ip_hdr_t *)cap.buf[0];
        CHECK_EQ_HEX(iph2->dst_ip, peer);
        CHECK_EQ_INT(iph2->proto, IP_PROTO_ICMP);
        CHECK_EQ_INT(cap.buf[0][IP_HDR_MIN_LEN], ICMP_UNREACH);
        CHECK_EQ_INT(cap.buf[0][IP_HDR_MIN_LEN + 1], ICMP_UNREACH_NET);
    }

    /* An unknown IP protocol must yield protocol-unreachable, quoting the
     * offending header plus eight payload bytes. */
    cap.count = 0;
    {
        uint8_t udp[64];
        ip_hdr_t *iph = (ip_hdr_t *)udp;
        memset(udp, 0, sizeof udp);
        ip_build(iph, peer, w.ip_a, IP_PROTO_UDP, 1, 20, 64);
        memset(udp + 20, 0x11, 20);
        ip_finalize(iph, 20);

        net_rx(&w.sa, udp, 40);

        CHECK_EQ_INT(cap.count, 1);
        if (cap.count >= 1) {
            const ip_hdr_t *o = (const ip_hdr_t *)cap.buf[0];
            CHECK_EQ_INT(o->proto, IP_PROTO_ICMP);
            CHECK_EQ_INT(cap.buf[0][IP_HDR_MIN_LEN], ICMP_UNREACH);
            CHECK_EQ_INT(cap.buf[0][IP_HDR_MIN_LEN + 1], ICMP_UNREACH_PROTO);
            CHECK_EQ_INT(cap.len[0], IP_HDR_MIN_LEN + ICMP_QUOTE_LEN);
        }
    }

    /* A corrupt ICMP checksum must be dropped, not answered. */
    cap.count = 0;
    len = harness_icmp_echo(pkt, peer, w.ip_a, 0x1234, 9, 16);
    pkt[IP_HDR_MIN_LEN + 2] ^= 0xFF;      /* break the ICMP checksum */
    net_rx(&w.sa, pkt, len);
    CHECK_EQ_INT(cap.count, 0);

    wire_free(&w);
}