/*
 * test_tcp_out_of_order.c -- receive-side reassembly.
 *
 * Segments can arrive in any order.  The receiver must deliver bytes to the
 * application strictly in sequence, once, and must re-advertise RCV.NXT while
 * a gap is outstanding so the sender knows what is still missing.
 */
#include "harness.h"

/* Wrap a bare IP datagram so it can be injected into the TAP wire. */
static size_t wrap(wire_t *w, int dst_side, const uint8_t *ip, size_t ip_len,
                   uint8_t *frame)
{
    return eth_build_frame(frame,
                           dst_side == 0 ? w->mac_a : w->mac_b,
                           dst_side == 0 ? w->mac_b : w->mac_a,
                           ETHERTYPE_IP, ip, ip_len);
}

void test_tcp_out_of_order(void)
{
    wire_t w;

    wire_init(&w, true);

    tcp_pcb_t *listener = tcp_new(&w.sb, 0);
    CHECK(listener != NULL);
    if (!listener) {
        wire_free(&w);
        return;
    }
    CHECK_EQ_INT(tcp_bind(listener, 7001), 0);
    CHECK_EQ_INT(tcp_listen(listener), 0);

    tcp_pcb_t *a = tcp_connect(&w.sa, w.ip_b, 7001);
    CHECK(a != NULL);

    wire_run_until(&w, w.now_ms + 200, 10);

    tcp_pcb_t *b = tcp_accept(listener);
    CHECK(b != NULL);

    if (!a || !b) {
        wire_free(&w);
        return;
    }

    /* Segments of the payload A would emit, injected by hand in a chosen
     * order.  Four logical pieces of eight bytes each. */
    uint8_t piece[4][8] = {
        { 1, 1, 1, 1, 1, 1, 1, 1 },
        { 2, 2, 2, 2, 2, 2, 2, 2 },
        { 3, 3, 3, 3, 3, 3, 3, 3 },
        { 4, 4, 4, 4, 4, 4, 4, 4 },
    };
    const uint32_t base = b->rcv_nxt;

    /* ---- deliver piece 1 (the gap) last ---- */
    {
        uint8_t ip[128], frame[256];

        for (int i = 3; i >= 1; i--) {
            size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport,
                                              7001, base + i * 8,
                                              b->snd_nxt,
                                              TH_ACK | TH_PSH, 4096,
                                              piece[i], 8);
            size_t flen = wrap(&w, 1, ip, iplen, frame);
            net_rx(&w.sb, frame, flen);
        }

        /*
         * Nothing may be delivered yet: RCV.NXT has not moved, so the
         * application must see an empty stream despite three segments having
         * arrived.
         */
        CHECK_EQ_HEX(b->rcv_nxt, base);
        CHECK_EQ_INT(tcp_recv_avail(b), 0);

        /* The gap is still open: an empty read must report no data at all,
         * rather than whatever happened to arrive first. */
        uint8_t scratch[8];
        CHECK_EQ_INT(tcp_recv(b, scratch, sizeof scratch), 0);
    }

    /* ---- now fill the gap: everything must be released in order ---- */
    {
        uint8_t ip[128], frame[256];
        size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport, 7001,
                                          base, b->snd_nxt,
                                          TH_ACK | TH_PSH, 4096,
                                          piece[0], 8);
        size_t flen = wrap(&w, 1, ip, iplen, frame);
        net_rx(&w.sb, frame, flen);
    }

    CHECK_EQ_HEX(b->rcv_nxt, base + 32);

    uint8_t got[64];
    int n = 0;
    for (int i = 0; i < 20 && n < 32; i++) {
        int rc = tcp_recv(b, got + n, sizeof got - n);
        if (rc <= 0)
            break;
        n += rc;
    }

    /* All four pieces, in order, once each -- this is the whole contract of
     * reassembly. */
    CHECK_EQ_INT(n, 32);
    for (int i = 0; i < 4; i++)
        CHECK_EQ_INT(got[i * 8], piece[i][0]);

    /* ---- overlapping and duplicate data must be delivered only once ---- */
    {
        uint32_t now = b->rcv_nxt;
        uint8_t ip[128], frame[256];

        /* Re-send the final piece verbatim. */
        size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport, 7001,
                                          now - 8, b->snd_nxt,
                                          TH_ACK | TH_PSH, 4096,
                                          piece[3], 8);
        size_t flen = wrap(&w, 1, ip, iplen, frame);
        net_rx(&w.sb, frame, flen);

        CHECK_EQ_INT(tcp_recv_avail(b), 0);
        CHECK_EQ_HEX(b->rcv_nxt, now);
    }

    /* ---- a segment straddling RCV.NXT is trimmed, not duplicated ---- */
    {
        uint32_t now = b->rcv_nxt;
        uint8_t payload[12];
        for (int i = 0; i < 12; i++)
            payload[i] = (uint8_t)(0xA0 + i);

        /* Starts 4 bytes before where we are, so the first 4 are stale. */
        size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport, 7001,
                                          now - 4, b->snd_nxt,
                                          TH_ACK | TH_PSH, 4096,
                                          payload, 12);
        size_t flen = wrap(&w, 1, ip, iplen, frame);
        net_rx(&w.sb, frame, flen);

        CHECK_EQ_HEX(b->rcv_nxt, now + 8);

        uint8_t tail[16];
        int m = tcp_recv(b, tail, sizeof tail);
        CHECK_EQ_INT(m, 8);
        CHECK_EQ_INT(memcmp(tail, payload + 4, 8), 0);
    }

    /* ---- a segment past RCV.NXT but inside the window is queued, not
     * accepted ---- */
    {
        uint32_t now = b->rcv_nxt;
        uint8_t far[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
        uint8_t ip[128], frame[256];

        /* Still within the receive window, so it must be buffered rather than
         * discarded: that is what lets a later segment complete the stream. */
        size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport, 7001,
                                          now + 1000, b->snd_nxt,
                                          TH_ACK | TH_PSH, 4096, far, 8);
        size_t flen = wrap(&w, 1, ip, iplen, frame);
        net_rx(&w.sb, frame, flen);

        CHECK_EQ_HEX(b->rcv_nxt, now);
        CHECK_EQ_INT(tcp_recv_avail(b), 0);
        CHECK(b->ooo_head != NULL);      /* parked, waiting for its prefix */
    }

    /* ---- a segment beyond the window is refused outright ---- */
    {
        uint32_t now = b->rcv_nxt;
        uint8_t ip[128], frame[256];
        uint8_t way_out[8] = { 7, 7, 7, 7, 7, 7, 7, 7 };

        capture_t cap;
        harness_attach_capture(&w.sb, &cap);

        /* Far past the window: the receiver must refuse it and re-advertise
         * RCV.NXT rather than buffering it. */
        size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b, a->lport, 7001,
                                          now + 60000, b->snd_nxt,
                                          TH_ACK | TH_PSH, 4096,
                                          way_out, 8);
        size_t flen = wrap(&w, 1, ip, iplen, frame);
        net_rx(&w.sb, frame, flen);

        CHECK_EQ_HEX(b->rcv_nxt, now);
        CHECK_EQ_INT(tcp_recv_avail(b), 0);

        /* A single re-acknowledgement is the correct response. */
        CHECK_EQ_INT(cap.count, 1);
        if (cap.count >= 1) {
            const uint8_t *seg = cap.buf[0] + ETH_HDR_LEN + IP_HDR_MIN_LEN;
            CHECK_EQ_INT(seg[13], TH_ACK);
            CHECK_EQ_HEX(rd32_be(seg + 8), now);
        }
    }

    wire_free(&w);
}