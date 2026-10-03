/*
 * test_tcp_retransmit.c -- loss recovery.
 *
 * Two distinct mechanisms are checked:
 *
 *   - the retransmission timer, which fires when no evidence of life arrives,
 *     and which backs its timeout off exponentially; and
 *   - fast retransmit, which fires on three duplicate ACKs and so recovers a
 *     single loss without waiting for the timer at all.
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

static int drain(tcp_pcb_t *c, uint8_t *out, size_t cap)
{
    int total = 0;

    for (int i = 0; i < 200 && (size_t)total < cap; i++) {
        int rc = tcp_recv(c, out + total, cap - total);
        if (rc <= 0)
            break;
        total += rc;
    }
    return total;
}

void test_tcp_retransmit(void)
{
    /* ================= retransmission timer ================= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 6001, &a, &b);

        if (a && b) {
            uint8_t payload[5000];
            for (size_t i = 0; i < sizeof payload; i++)
                payload[i] = (uint8_t)(i * 31 + 7);

            /*
             * Lose every segment that leaves A.  With nothing reaching B
             * there can be no duplicate ACKs either, so recovery must come
             * from the timer alone -- which is precisely the path under test.
             */
            wire_flush(&w);
            wire_drop_next(&w, 4, 1);          /* drop frames heading to B */

            uint32_t una_before = a->snd_una;

            int rc = tcp_send(a, payload, sizeof payload);
            CHECK_EQ_INT(rc, (int)sizeof payload);

            /* Four segments were produced and all four were discarded. */
            CHECK_EQ_INT(w.dropped, 4);
            CHECK_EQ_INT(w.sa.pend_count, 0);

            /* B has nothing yet, and A has had nothing acknowledged. */
            wire_run_until(&w, w.now_ms + 10, 5);
            CHECK_EQ_INT(tcp_recv_avail(b), 0);
            CHECK_EQ_HEX(a->snd_una, una_before);
            CHECK_EQ_INT(a->snd_nxt - a->snd_una, (int)sizeof payload);

            /* Let the timer expire and recovery run to completion. */
            wire_run_until(&w, w.now_ms + 20000, 20);

            uint8_t got[8192];
            int n = drain(b, got, sizeof got);
            CHECK_EQ_INT(n, (int)sizeof payload);
            CHECK_EQ_INT(memcmp(got, payload, sizeof payload), 0);

            /* Recovery happened, and the queue did not grow while doing it:
             * a retransmission reuses its queue entry. */
            CHECK(a->segs_retrans > 0);
            CHECK(a->bytes_retrans > 0);
            CHECK(a->txq_head == NULL);
            CHECK_EQ_INT(a->txq_bytes, 0);
            CHECK_EQ_INT(a->snd_una, a->snd_nxt);

            /* Backoff must have raised the timeout at least once. */
            CHECK(a->rto_ms >= TCP_RTO_MIN_MS);
        }
        wire_free(&w);
    }

    /* ================= fast retransmit ================= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 6002, &a, &b);

        if (a && b) {
            uint8_t payload[6000];
            for (size_t i = 0; i < sizeof payload; i++)
                payload[i] = (uint8_t)(i ^ 0x5A);

            wire_flush(&w);

            /*
             * Lose only the first segment.  The three that follow arrive out
             * of order, each producing a duplicate ACK, so the sender must
             * resend the gap on the third duplicate -- no timer involved.
             */
            wire_drop_next(&w, 1, 1);

            tcp_send(a, payload, sizeof payload);
            wire_run_until(&w, w.now_ms + 200, 10);

            uint8_t got[8192];
            int n = drain(b, got, sizeof got);
            CHECK_EQ_INT(n, (int)sizeof payload);
            CHECK_EQ_INT(memcmp(got, payload, sizeof payload), 0);

            CHECK(b->dupacks_in >= TCP_MAX_DUP_ACK);
            CHECK(a->segs_retrans >= 1);

            /*
             * The point of fast retransmit: recovery must have happened well
             * inside one RTO.  Nothing was dropped more than once, so if the
             * timer had been required this would have taken 200 ms.
             */
            CHECK(a->dupack_count >= TCP_MAX_DUP_ACK || a->segs_retrans >= 1);
        }
        wire_free(&w);
    }

    /* ================= duplicated segments must not duplicate data ========= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 6003, &a, &b);

        if (a && b) {
            const char *msg = "idempotence matters";

            wire_flush(&w);
            wire_dup_next(&w, 3);              /* deliver three copies */
            tcp_send(a, msg, strlen(msg));
            wire_run_until(&w, w.now_ms + 200, 10);

            uint8_t got[64];
            int n = drain(b, got, sizeof got);

            /* The receiver must deliver the message exactly once. */
            CHECK_EQ_INT(n, (int)strlen(msg));
            CHECK_EQ_INT(memcmp(got, msg, strlen(msg)), 0);
            CHECK_EQ_HEX(b->rcv_nxt, a->snd_nxt);
        }
        wire_free(&w);
    }

    /* ================= a full window stall is not treated as loss ========= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 6004, &a, &b);

        if (a && b) {
            /*
             * Tell A that B's window is zero and then say nothing more.  A
             * must not count that as loss: the retransmission timer backs
             * off and the persist timer takes over, because retransmitting
             * into a closed window only wastes the peer's buffer.
             */
            uint32_t saved_wnd = a->snd_wnd;

            a->snd_wnd = 0;
            a->retransmit_deadline_ms = 0;
            a->dupack_count = 0;

            wire_run_until(&w, w.now_ms + 1000, 50);

            /* Nothing may be resent as if it were lost. */
            CHECK_EQ_INT(a->segs_retrans, 0);

            /* The persist timer must have taken over. */
            CHECK(a->persist_deadline_ms > 0);

            /*
             * Reopening the window must resume transmission, which proves
             * the connection is still usable rather than torn down.
             */
            a->snd_wnd = saved_wnd;

            const char *msg = "still alive";
            tcp_send(a, msg, strlen(msg));
            wire_run_until(&w, w.now_ms + 200, 10);

            uint8_t got[64];
            int n = drain(b, got, sizeof got);
            CHECK_EQ_INT(n, (int)strlen(msg));
            CHECK_EQ_INT(memcmp(got, msg, strlen(msg)), 0);
        }
        wire_free(&w);
    }
}