/*
 * test_arp.c -- the ARP cache and the on-wire request/reply exchange.
 */
#include "harness.h"
#include "arp.h"

void test_arp(void)
{
    /* ---------------- cache behaviour ---------------- */
    arp_cache_t c;
    arp_init(&c);

    uint32_t a, b;
    inet_pton(AF_INET, "10.0.0.2", &a);
    inet_pton(AF_INET, "10.0.0.3", &b);

    const uint8_t mac_a[6] = { 0x02, 0, 0, 0, 0, 0x0A };
    const uint8_t mac_b[6] = { 0x02, 0, 0, 0, 0, 0x0B };
    uint8_t out[6];

    /* A miss must not invent an answer. */
    CHECK(!arp_lookup(&c, a, out));
    CHECK_EQ_INT(c.misses, 1);

    arp_insert(&c, a, mac_a);
    CHECK(arp_lookup(&c, a, out));
    CHECK_EQ_INT(memcmp(out, mac_a, 6), 0);
    CHECK_EQ_INT(c.hits, 1);
    CHECK_EQ_INT(arp_count(&c), 1);

    /* Re-inserting the same address refreshes it instead of duplicating. */
    arp_insert(&c, a, mac_b);
    CHECK_EQ_INT(arp_count(&c), 1);
    CHECK(arp_lookup(&c, a, out));
    CHECK_EQ_INT(memcmp(out, mac_b, 6), 0);

    /* A different address is a different entry. */
    arp_insert(&c, b, mac_a);
    CHECK_EQ_INT(arp_count(&c), 2);

    /* Filling past capacity evicts rather than overflowing. */
    for (int i = 0; i < ARP_TABLE_SIZE + 8; i++) {
        uint32_t ip;
        char text[24];
        snprintf(text, sizeof text, "10.1.%d.%d", (i >> 8) & 0xFF, i & 0xFF);
        inet_pton(AF_INET, text, &ip);
        arp_insert(&c, ip, mac_a);
    }
    CHECK_EQ_INT(arp_count(&c), ARP_TABLE_SIZE);

    /* Every surviving entry must still be self-consistent. */
    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        const arp_entry_t *e = arp_get(&c, i);
        if (!e)
            continue;
        uint8_t got[6];
        CHECK(arp_lookup(&c, e->ip, got));
        CHECK_EQ_INT(memcmp(got, e->mac, 6), 0);
    }

    arp_flush(&c);
    CHECK_EQ_INT(arp_count(&c), 0);
    CHECK(!arp_lookup(&c, a, out));

    /* ---------------- on-the-wire request and reply ---------------- */
    {
        wire_t w;
        capture_t cap;

        wire_init(&w, true);              /* TAP: Ethernet framing plus ARP */

        /*
         * A asks the network "who has 10.0.0.2?".  B is the only other
         * endpoint, so it must answer, and A must learn from the answer.
         */
        uint8_t req[ETH_HDR_LEN + ARP_HDR_LEN];
        arp_pkt_t *arp = (arp_pkt_t *)(req + ETH_HDR_LEN);

        eth_build_frame(req, ETH_BROADCAST, w.mac_a, ETHERTYPE_ARP, NULL, 0);
        arp->htype  = htons(ARP_HTYPE_ETHER);
        arp->ptype  = htons(ETHERTYPE_IP);
        arp->hlen   = 6;
        arp->plen   = 4;
        arp->opcode = htons(ARP_OP_REQUEST);
        memcpy(arp->sha, w.mac_a, 6);
        arp->spa = w.ip_a;
        memset(arp->tha, 0, 6);
        arp->tpa = w.ip_b;

        /* A must learn B's address from the request itself. */
        net_rx(&w.sa, req, sizeof req);
        uint8_t got[6];
        CHECK(arp_lookup(&w.sa.arp, w.ip_b, got));
        CHECK_EQ_INT(memcmp(got, w.mac_b, 6), 0);

        /* B, having learned A, must answer with its own address. */
        capture_t bcap;
        harness_attach_capture(&w.sb, &bcap);
        net_rx(&w.sb, req, sizeof req);

        CHECK_EQ_INT(bcap.count, 1);
        CHECK_EQ_INT(bcap.len[0], ETH_HDR_LEN + ARP_HDR_LEN);

        const eth_hdr_t *eth = (const eth_hdr_t *)bcap.buf[0];
        const arp_pkt_t *rep = (const arp_pkt_t *)(bcap.buf[0] + ETH_HDR_LEN);

        CHECK_EQ_INT(memcmp(eth->dst, w.mac_a, 6), 0);
        CHECK_EQ_INT(rd16_be((const uint8_t *)rep->opcode), ARP_OP_REPLY);
        CHECK_EQ_HEX(rd32_be((const uint8_t *)rep->spa), w.ip_b);
        CHECK_EQ_INT(memcmp(rep->sha, w.mac_b, 6), 0);
        CHECK_EQ_HEX(rd32_be((const uint8_t *)rep->tpa), w.ip_a);

        /* An ARP request for somebody else must be ignored, not answered. */
        bcap.count = 0;
        arp->tpa = 0x0300A8C0;           /* 10.0.0.3, not B */
        net_rx(&w.sb, req, sizeof req);
        CHECK_EQ_INT(bcap.count, 0);

        /* A RST needs no reply. */
        bcap.count = 0;
        arp->tpa = w.ip_b;
        arp->opcode = htons(ARP_OP_REPLY);
        net_rx(&w.sb, req, sizeof req);
        CHECK_EQ_INT(bcap.count, 0);

        (void)cap;
        wire_free(&w);
    }
}