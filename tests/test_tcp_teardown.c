/*
 * test_tcp_teardown.c -- orderly shutdown in both directions.
 *
 * The interesting part is that the two sides usually cross: the closer is
 * still waiting for its own FIN when the peer's FIN arrives, so the connection
 * passes through CLOSING before reaching TIME-WAIT.
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

void test_tcp_teardown(void)
{
    wire_t w;
    tcp_pcb_t *a = NULL, *b = NULL;

    wire_init(&w, true);
    establish(&w, 9000, &a, &b);

    if (!a || !b) {
        wire_free(&w);
        return;
    }

    CHECK_EQ_INT(a->state, TCP_ESTABLISHED);
    CHECK_EQ_INT(b->state, TCP_ESTABLISHED);

    /* Push some data across first so the close has to drain a real queue. */
    {
        uint8_t payload[2000];
        for (size_t i = 0; i < sizeof payload; i++)
            payload[i] = (uint8_t)i;

        int sent = 0;
        while (sent < (int)sizeof payload) {
            int rc = tcp_send(a, payload + sent, sizeof payload - sent);
            if (rc < 0)
                break;
            sent += rc;
        }
        CHECK_EQ_INT(sent, (int)sizeof payload);

        wire_run_until(&w, w.now_ms + 200, 10);

        uint8_t got[4096];
        int total = 0;
        for (int i = 0; i < 50 && total < (int)sizeof payload; i++) {
            int rc = tcp_recv(b, got + total, sizeof got - total);
            if (rc <= 0)
                break;
            total += rc;
        }
        CHECK_EQ_INT(total, (int)sizeof payload);
        CHECK_EQ_INT(memcmp(got, payload, sizeof payload), 0);
    }

    /* ---- A closes first ---- */
    tcp_close(a);
    CHECK_EQ_INT(a->state, TCP_FIN_WAIT_1);

    wire_run_until(&w, w.now_ms + 50, 10);

    /* B saw the FIN: half-open from its point of view, and it may still send. */
    CHECK_EQ_INT(b->state, TCP_CLOSE_WAIT);
    CHECK(b->flags & TF_GOT_FIN);

    /* Reading past the FIN must report a clean end of stream. */
    {
        uint8_t sink[4096];
        int rc = tcp_recv(b, sink, sizeof sink);
        CHECK_EQ_INT(rc, 0);
    }

    /* ---- B responds with its own FIN ---- */
    tcp_close(b);
    CHECK_EQ_INT(b->state, TCP_LAST_ACK);

    wire_run_until(&w, w.now_ms + 50, 10);

    /* A's FIN is acknowledged and its peer's FIN has arrived: TIME-WAIT. */
    CHECK_EQ_INT(a->state, TCP_TIME_WAIT);
    CHECK(a->timewait_deadline_ms > 0);

    /* B has nothing left to wait for. */
    CHECK_EQ_INT(b->state, TCP_CLOSED);

    /* Nothing is still queued for retransmission anywhere. */
    CHECK(a->txq_head == NULL);
    CHECK(b->txq_head == NULL);
    CHECK_EQ_INT(a->txq_bytes, 0);
    CHECK_EQ_INT(b->txq_bytes, 0);

    /* Further data must be refused now that the connection is gone. */
    CHECK_EQ_INT(tcp_send(a, "x", 1), -EPIPE);

    /* ---- TIME-WAIT eventually expires ---- */
    wire_run_until(&w, a->timewait_deadline_ms + 1000, 100);
    CHECK_EQ_INT(a->state, TCP_CLOSED);

    wire_free(&w);

    /* ---- closing half-open connections needs no handshake ---- */
    wire_init(&w, true);
    {
        tcp_pcb_t *c = tcp_connect(&w.sa, w.ip_b, 77);
        CHECK(c != NULL);
        CHECK_EQ_INT(c->state, TCP_SYN_SENT);
        tcp_close(c);
        CHECK_EQ_INT(c->state, TCP_CLOSED);
    }
    wire_free(&w);

    /* ---- a peer that vanishes mid-connection is detected by RTO ---- */
    wire_init(&w, true);
    establish(&w, 9100, &a, &b);

    if (a && b) {
        /* Black-hole the link: the SYN's ACK can never come back. */
        wire_drop_next(&w, 1, 0);

        tcp_send(a, "hello", 5);
        wire_run_until(&w, w.now_ms + 10, 5);

        /*
         * Long enough to exhaust the retry budget.  The RTO starts at 200 ms
         * and doubles on every attempt up to a 60 s ceiling, so the twelfth
         * attempt lands near 282 s and the failure is declared on the next
         * timer expiry.
         */
        uint32_t sent_before = a->segs_retrans;
        wire_run_until(&w, w.now_ms + 400000, 500);

        CHECK(a->segs_retrans > sent_before);
        CHECK_EQ_INT(a->state, TCP_CLOSED);
        CHECK_EQ_INT(a->err, ETIMEDOUT);
    }
    wire_free(&w);
}