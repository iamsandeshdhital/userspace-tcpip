/*
 * test_tcp_handshake.c -- the three-way handshake, end to end.
 *
 * This runs over the virtual wire in TAP mode, so ARP resolution, Ethernet
 * framing, IP and TCP are all exercised together.  A passive open in particular
 * cannot be faked: it only works if the SYN reaches the listener, the listener
 * allocates a child control block, and the final ACK promotes it.
 */
#include "harness.h"

/* Bring up a listener on B and an active connection from A. */
static void establish(wire_t *w, uint16_t port,
                      tcp_pcb_t **out_a, tcp_pcb_t **out_b)
{
    tcp_pcb_t *listener = tcp_new(&w->sb, 0);
    CHECK(listener != NULL);
    if (!listener)
        return;

    CHECK_EQ_INT(tcp_bind(listener, port), 0);
    CHECK_EQ_INT(tcp_listen(listener), 0);

    tcp_pcb_t *client = tcp_connect(&w->sa, w->ip_b, port);
    CHECK(client != NULL);

    /* Enough virtual time for ARP to settle, then for the handshake. */
    wire_run_until(w, w->now_ms + 200, 10);

    tcp_pcb_t *server = tcp_accept(listener);
    CHECK(server != NULL);

    if (out_a)
        *out_a = client;
    if (out_b)
        *out_b = server;
}

/*
 * The wire is in TAP mode, so an injected packet needs an Ethernet header.
 * Returns the frame length.
 */
static size_t wrap_for(wire_t *w, int dst_side, const uint8_t *ip,
                       size_t ip_len, uint8_t *frame)
{
    return eth_build_frame(frame,
                           dst_side == 0 ? w->mac_a : w->mac_b,
                           dst_side == 0 ? w->mac_b : w->mac_a,
                           ETHERTYPE_IP, ip, ip_len);
}

void test_tcp_handshake(void)
{
    wire_t w;

    /* ---- the first packet on a cold cache must be ARP, not a SYN ---- */
    wire_init(&w, true);

    {
        tcp_pcb_t *c = tcp_connect(&w.sa, w->ip_b, 80);
        CHECK(c != NULL);

        CHECK_EQ_INT(c->state, TCP_SYN_SENT);
        /* A SYN occupies one sequence number even though it carries no data. */
        CHECK_EQ_INT(c->snd_nxt, c->snd_una + 1);

        CHECK_EQ_INT(w.count, 1);
        if (w.count == 1) {
            const eth_hdr_t *eth = (const eth_hdr_t *)w.q[w.head].data;
            const arp_pkt_t *arp =
                (const arp_pkt_t *)(w.q[w.head].data + ETH_HDR_LEN);

            CHECK_EQ_INT(eth_is_broadcast(eth->dst), 1);
            CHECK_EQ_INT(rd16_be((const uint8_t *)eth->ethertype),
                         ETHERTYPE_ARP);
            CHECK_EQ_INT(rd16_be((const uint8_t *)arp->opcode),
                         ARP_OP_REQUEST);
            CHECK_EQ_HEX(rd32_be((const uint8_t *)arp->tpa), w.ip_b);
        }

        /* The SYN is parked, not lost: dropping it would mean no connection
         * could ever be opened to a host whose MAC is unknown. */
        CHECK_EQ_INT(w.sa.pend_count, 1);

        wire_run_until(&w, w.now_ms + 200, 10);
        CHECK_EQ_INT(c->state, TCP_ESTABLISHED);
        CHECK_EQ_INT(w.sa.pend_count, 0);
    }
    wire_free(&w);

    /* ---- the full three-way handshake ---- */
    wire_init(&w, true);

    tcp_pcb_t *a = NULL, *b = NULL;
    establish(&w, 8080, &a, &b);

    CHECK(a != NULL);
    CHECK(b != NULL);

    if (a && b) {
        CHECK_EQ_INT(a->state, TCP_ESTABLISHED);
        CHECK_EQ_INT(b->state, TCP_ESTABLISHED);

        /* Nothing is left in flight on either side. */
        CHECK_EQ_INT(a->snd_una, a->snd_nxt);
        CHECK_EQ_INT(b->snd_una, b->snd_nxt);
        CHECK(a->txq_head == NULL);
        CHECK(b->txq_head == NULL);
        CHECK_EQ_INT(a->txq_bytes, 0);

        /*
         * Each side has absorbed the other's SYN and acknowledged it, so
         * RCV.NXT equals the peer's SND.UNA.
         */
        CHECK_EQ_INT(a->rcv_nxt, b->snd_una);
        CHECK_EQ_INT(b->rcv_nxt, a->snd_una);

        /* Window scaling was offered by both and accepted by both. */
        CHECK_EQ_INT(a->wscale_remote, 7);
        CHECK_EQ_INT(b->wscale_remote, 7);

        /* The MSS A advertised became B's send limit. */
        CHECK_EQ_INT(b->mss_remote, USSTACK_MSS_DEFAULT);

        /* ARP completed in both directions. */
        CHECK_EQ_INT(arp_count(&w.sa.arp), 1);
        CHECK_EQ_INT(arp_count(&w.sb.arp), 1);

        /* ---- data flows, and sliding-window accounting stays consistent -- */
        {
            const char *msg = "the quick brown fox";
            int rc = tcp_send(a, msg, strlen(msg));
            CHECK_EQ_INT(rc, (int)strlen(msg));

            wire_run_until(&w, w.now_ms + 100, 10);

            uint8_t got[64];
            int n = tcp_recv(b, got, sizeof got);
            CHECK_EQ_INT(n, (int)strlen(msg));
            CHECK_EQ_INT(memcmp(got, msg, strlen(msg)), 0);

            /* The peer's ACK must have advanced SND.UNA to SND.NXT, and the
             * send buffer must have been released. */
            CHECK_EQ_INT(a->snd_una, a->snd_nxt);
            CHECK_EQ_INT(tcp_send_space(a), TCP_TXBUF_SIZE);
            CHECK_EQ_INT(b->rcv_nxt, a->snd_nxt);
        }

        /* ---- a segment to a closed port is refused with RST ---- */
        {
            uint8_t ip[128], frame[256];
            capture_t cap;
            harness_attach_capture(&w.sb, &cap);

            uint32_t peer;
            inet_pton(AF_INET, "192.168.0.77", &peer);

            size_t iplen = harness_tcp_packet(ip, peer, w.ip_b, 5555, 9999,
                                              0x12345678, 0, TH_SYN, 1024,
                                              NULL, 0);
            size_t framelen = wrap_for(&w, 1, ip, iplen, frame);
            net_rx(&w.sb, frame, framelen);

            CHECK_EQ_INT(cap.count, 1);
            if (cap.count >= 1) {
                const uint8_t *seg = cap.buf[0] + IP_HDR_MIN_LEN;
                CHECK_EQ_INT(seg[13] & TH_RST, TH_RST);
                /*
                 * RFC 793: with nothing to echo, the RST is sent without an
                 * ACK and its sequence number is zero.
                 */
                CHECK_EQ_INT(seg[13] & TH_ACK, 0);
                CHECK_EQ_HEX(rd32_be(seg + 4), 0);
            }
        }

        /* ---- a non-SYN to a listening port is also refused ---- */
        {
            uint8_t ip[128], frame[256];
            capture_t cap;
            harness_attach_capture(&w.sb, &cap);

            uint32_t peer;
            inet_pton(AF_INET, "192.168.0.78", &peer);

            /* Correct source port so a listener exists, but no SYN. */
            size_t iplen = harness_tcp_packet(ip, peer, w.ip_b, a->lport,
                                              8080, 1000, 0, TH_ACK, 1024,
                                              NULL, 0);
            size_t framelen = wrap_for(&w, 1, ip, iplen, frame);
            net_rx(&w.sb, frame, framelen);

            CHECK_EQ_INT(cap.count, 1);
            if (cap.count >= 1) {
                const uint8_t *seg = cap.buf[0] + IP_HDR_MIN_LEN;
                CHECK_EQ_INT(seg[13] & TH_RST, TH_RST);
                CHECK_EQ_INT(seg[13] & TH_ACK, TH_ACK);
                /* It acknowledges the end of the offending segment. */
                CHECK_EQ_HEX(rd32_be(seg + 8), 1000);
            }
        }

        /* ---- a corrupted segment is dropped without a reply ---- */
        {
            uint8_t ip[256], frame[400];
            capture_t cap;
            harness_attach_capture(&w.sb, &cap);

            const char *msg = "hello";
            uint32_t before = b->rcv_nxt;

            /* Use the real four-tuple so the segment belongs to the live
             * connection: the checksum, not the lookup, must reject it. */
            size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport,
                                              8080, b->rcv_nxt, b->snd_nxt,
                                              TH_ACK | TH_PSH, 1024, msg, 5);
            /* Damage the payload after the checksum was computed. */
            ip[IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN] ^= 0xFF;

            size_t framelen = wrap_for(&w, 1, ip, iplen, frame);
            net_rx(&w.sb, frame, framelen);

            CHECK_EQ_INT(cap.count, 0);
            CHECK_EQ_INT(tcp_recv_avail(b), 0);
            CHECK_EQ_HEX(b->rcv_nxt, before);
        }
    }

    /* ---- port conflicts ---- */
    {
        tcp_pcb_t *l1 = tcp_new(&w.sa, 0);
        CHECK(l1 != NULL);
        CHECK_EQ_INT(tcp_bind(l1, 7000), 0);
        CHECK_EQ_INT(tcp_listen(l1), 0);

        tcp_pcb_t *l2 = tcp_new(&w.sa, 0);
        CHECK(l2 != NULL);
        CHECK_EQ_INT(tcp_bind(l2, 7000), -EADDRINUSE);
        CHECK_EQ_INT(tcp_listen(l2), -EADDRINUSE);

        /* Listening without a port is meaningless. */
        tcp_pcb_t *l3 = tcp_new(&w.sa, 0);
        CHECK(l3 != NULL);
        CHECK_EQ_INT(tcp_listen(l3), -EADDRNOTAVAIL);
    }

    wire_free(&w);
}