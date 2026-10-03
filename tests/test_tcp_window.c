/*
 * test_tcp_window.c -- the sliding window, in both directions.
 *
 * Flow control is the reason a receiver advertises a window at all: it is a
 * promise about buffer space.  These tests check that the promise is kept in
 * both directions -- a sender never exceeds the window, a blocked sender
 * resumes when the window opens, and a receive buffer is never overrun no
 * matter how much the peer sends.
 */
#include "harness.h"

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

    wire_run_until(w, w->now_ms + 200, 10);

    tcp_pcb_t *server = tcp_accept(listener);
    CHECK(server != NULL);

    if (out_a)
        *out_a = client;
    if (out_b)
        *out_b = server;
}

void test_tcp_window(void)
{
    /* ================= window scaling round-trip ========================= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;
        capture_t cap;

        wire_init(&w, true);
        establish(&w, 5001, &a, &b);

        if (a && b) {
            /*
             * Ask B to acknowledge something and inspect the window field it
             * puts on the wire.  B holds TCP_RXBUF_SIZE bytes but can only
             * describe 16 bits of it, so the value must have been divided by
             * the scale factor it negotiated.
             */
            harness_attach_capture(&w.sb, &cap);

            tcp_send(a, "x", 1);
            wire_run_until(&w, w.now_ms + 20, 5);

            CHECK(cap.count >= 1);
            if (cap.count >= 1) {
                const uint8_t *seg =
                    cap.buf[0] + ETH_HDR_LEN + IP_HDR_MIN_LEN;
                uint16_t on_wire = rd16_be(seg + 14);

                /* 16 KiB cannot be expressed directly: it had to be scaled. */
                CHECK(on_wire < TCP_RXBUF_SIZE);

                /* A must scale it back up and land on the real buffer size --
                 * that round trip is what makes scaling correct. */
                uint32_t recovered = (uint32_t)on_wire << a->wscale_remote;
                CHECK_EQ_INT(recovered, TCP_RXBUF_SIZE);
                CHECK_EQ_INT(a->snd_wnd, TCP_RXBUF_SIZE);
            }
        }
        wire_free(&w);
    }

    /* ================= a blocked sender waits, then resumes ============= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 5002, &a, &b);

        if (a && b) {
            uint32_t payload = a->mss_remote * 4;
            uint8_t *data = (uint8_t *)malloc(payload);

            CHECK(data != NULL);
            if (!data) {
                wire_free(&w);
                return;
            }

            for (uint32_t i = 0; i < payload; i++)
                data[i] = (uint8_t)(i * 13 + 5);

            /*
             * Simulate a peer whose window has closed to zero.  The
             * application may still queue data -- that is the point of a send
             * buffer -- but none of it may reach the wire.
             */
            uint32_t saved_wnd = a->snd_wnd;
            a->snd_wnd = 0;

            uint32_t queued = 0;
            while (queued < payload) {
                int rc = tcp_send(a, data + queued, payload - queued);
                if (rc < 0)
                    break;
                queued += (uint32_t)rc;
            }
            CHECK_EQ_INT(queued, (int)payload);

            /* Queued, but not transmitted: SND.NXT has not moved. */
            CHECK_EQ_INT(a->snd_nxt, a->snd_una);
            CHECK_EQ_INT(tcp_recv_avail(b), 0);

            /* Time passing must not help; the window is still shut. */
            wire_run_until(&w, w.now_ms + 500, 50);
            CHECK_EQ_INT(a->snd_nxt, a->snd_una);
            CHECK_EQ_INT(a->segs_retrans, 0);

            /*
             * Reopen the window and drive the same call the ACK path uses.
             * Everything queued must go out and arrive intact.
             */
            a->snd_wnd = saved_wnd;
            tcp_send_pending(&w.sa, a);

            CHECK(a->snd_nxt > a->snd_una);
            wire_run_until(&w, w.now_ms + 200, 10);

            uint8_t *got = (uint8_t *)malloc(payload);
            CHECK(got != NULL);

            if (got) {
                int n = 0;
                for (int i = 0; i < 400 && n < (int)payload; i++) {
                    int rc = tcp_recv(b, got + n, payload - n);
                    if (rc <= 0)
                        break;
                    n += rc;
                }

                CHECK_EQ_INT(n, (int)payload);
                if (n == (int)payload)
                    CHECK_EQ_INT(memcmp(got, data, payload), 0);

                /* The queue drained, so the send buffer is available again. */
                CHECK_EQ_INT(tcp_send_space(a), TCP_TXBUF_SIZE);
                CHECK_EQ_INT(a->snd_una, a->snd_nxt);
                free(got);
            }

            free(data);
        }
        wire_free(&w);
    }

    /* ================= a receive buffer cannot be overrun ================ */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 5003, &a, &b);

        if (a && b) {
            uint8_t ip[1200], frame[1300];
            uint32_t base = b->rcv_nxt;
            const uint32_t chunk = 1000;

            /*
             * Offer B far more than its receive buffer can hold, without ever
             * reading from it.  It must accept exactly what fits, advertise
             * zero once full, and refuse everything after that.
             */
            for (uint32_t i = 0; i < 80; i++) {
                uint8_t body[1000];
                memset(body, (int)(i & 0xFF), sizeof body);

                size_t iplen = harness_tcp_packet(ip, w.ip_a, w.ip_b,
                                                  a->lport, 5003,
                                                  base + i * chunk,
                                                  b->snd_nxt,
                                                  TH_ACK | TH_PSH, 8192,
                                                  body, sizeof body);
                size_t flen = eth_build_frame(frame, w.mac_b, w.mac_a,
                                              ETHERTYPE_IP, ip, iplen);
                net_rx(&w.sb, frame, flen);
            }

            /* The buffer is full and not one byte more. */
            CHECK_EQ_INT(tcp_recv_avail(b), (int)TCP_RXBUF_SIZE);
            CHECK_EQ_INT(rb_avail(&b->rx_buf), 0);
            CHECK_EQ_HEX(b->rcv_nxt, base + TCP_RXBUF_SIZE);

            /* Nothing beyond the buffer was accepted, and nothing was stored
             * out of order. */
            uint8_t *got = (uint8_t *)malloc(TCP_RXBUF_SIZE);
            CHECK(got != NULL);

            if (got) {
                int n = 0;
                for (int i = 0; i < 400 && n < (int)TCP_RXBUF_SIZE; i++) {
                    int rc = tcp_recv(b, got + n, TCP_RXBUF_SIZE - n);
                    if (rc <= 0)
                        break;
                    n += rc;
                }

                CHECK_EQ_INT(n, (int)TCP_RXBUF_SIZE);

                /* Every byte must be the one the peer actually sent: the
                 * truncation has to land exactly at the buffer boundary. */
                int mismatch = 0;
                for (uint32_t i = 0; i < (uint32_t)n; i++) {
                    uint8_t want = (uint8_t)((i / chunk) & 0xFF);
                    if (got[i] != want) {
                        mismatch = 1;
                        break;
                    }
                }
                CHECK_EQ_INT(mismatch, 0);
                free(got);
            }
        }
        wire_free(&w);
    }
}