/*
 * test_tcp_loopback.c -- two stacks talking to each other over a lossy link.
 *
 * This is the integration test.  It is the one that catches mistakes in how
 * the pieces interact: a window that is advertised but not honoured, a
 * sequence number that slips after retransmission, an acknowledgement that
 * frees the wrong bytes.  None of those show up when testing a layer alone.
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

    for (int i = 0; i < 4000 && (size_t)total < cap; i++) {
        int rc = tcp_recv(c, out + total, cap - total);
        if (rc <= 0)
            break;
        total += rc;
    }
    return total;
}

void test_tcp_loopback(void)
{
    /* ================= a clean bulk transfer ============================ */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 4001, &a, &b);

        if (a && b) {
            const size_t total = 64 * 1024;
            uint8_t *data = (uint8_t *)malloc(total);
            uint8_t *got  = (uint8_t *)malloc(total);

            CHECK(data != NULL);
            CHECK(got != NULL);

            if (data && got) {
                for (size_t i = 0; i < total; i++)
                    data[i] = (uint8_t)(i * 251 + (i >> 8));

                /*
                 * Interleave sending and receiving, as an echo application
                 * would, so the window genuinely opens and closes instead of
                 * staying wide open.
                 */
                size_t written = 0, read = 0;

                while (read < total) {
                    while (written < total) {
                        int rc = tcp_send(a, data + written, total - written);
                        if (rc <= 0)
                            break;
                        written += (size_t)rc;
                    }

                    wire_run_until(&w, w.now_ms + 5, 5);

                    if (read < total) {
                        int rc = tcp_recv(b, got + read, total - read);
                        if (rc > 0)
                            read += (size_t)rc;
                    }

                    if (a->state == TCP_CLOSED || b->state == TCP_CLOSED)
                        break;
                }

                CHECK_EQ_INT(read, (int)total);
                if (read == total)
                    CHECK_EQ_INT(memcmp(got, data, total), 0);

                /* A link that loses nothing must not need a retransmission. */
                CHECK_EQ_INT(a->segs_retrans, 0);
                CHECK_EQ_INT(a->bytes_retrans, 0);

                /* The accounting must balance afterwards. */
                CHECK_EQ_INT(a->snd_una, a->snd_nxt);
                CHECK_EQ_INT(tcp_send_space(a), TCP_TXBUF_SIZE);
                CHECK_EQ_HEX(b->rcv_nxt, a->snd_nxt);

                free(got);
                free(data);
            }
        }
        wire_free(&w);
    }

    /* ================= the same transfer over a lossy link ============== */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 4002, &a, &b);

        if (a && b) {
            const size_t total = 48 * 1024;
            uint8_t *data = (uint8_t *)malloc(total);
            uint8_t *got  = (uint8_t *)malloc(total);

            CHECK(data != NULL);
            CHECK(got != NULL);

            if (data && got) {
                for (size_t i = 0; i < total; i++)
                    data[i] = (uint8_t)(i * 7 + 3);

                size_t written = 0, read = 0;
                uint32_t tick = 0;

                while (read < total) {
                    /*
                     * Lose a frame every so often, alternating direction, and
                     * duplicate one occasionally.  Both fast retransmit and
                     * the retransmission timer therefore have to earn their
                     * keep.
                     */
                    if (++tick % 7 == 0)
                        wire_drop_next(&w, 1, (tick % 2) ? 1 : 0);
                    if (tick % 11 == 0)
                        wire_dup_next(&w, 1);

                    while (written < total) {
                        int rc = tcp_send(a, data + written, total - written);
                        if (rc <= 0)
                            break;
                        written += (size_t)rc;
                    }

                    wire_run_until(&w, w.now_ms + 5, 5);

                    if (read < total) {
                        int rc = tcp_recv(b, got + read, total - read);
                        if (rc > 0)
                            read += (size_t)rc;
                    }

                    if (a->state == TCP_CLOSED || b->state == TCP_CLOSED)
                        break;
                }

                CHECK_EQ_INT(read, (int)total);
                if (read == total) {
                    /*
                     * Byte-exact, in order, with no duplication and nothing
                     * skipped.  This single assertion is what the entire
                     * retransmission and reassembly machinery exists to make
                     * true.
                     */
                    CHECK_EQ_INT(memcmp(got, data, total), 0);
                }

                /* Loss happened, so recovery must have happened too. */
                CHECK(w.dropped > 0);
                CHECK(a->segs_retrans + b->segs_retrans > 0);

                /* And the connection must still be usable afterwards. */
                CHECK_EQ_INT(a->state, TCP_ESTABLISHED);
                CHECK_EQ_INT(b->state, TCP_ESTABLISHED);

                free(got);
                free(data);
            }
        }
        wire_free(&w);
    }

    /* ================= simultaneous transfer in both directions ========= */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 4003, &a, &b);

        if (a && b) {
            const size_t total = 8000;
            uint8_t *data = (uint8_t *)malloc(total);
            uint8_t *echo = (uint8_t *)malloc(total);
            uint8_t *stage = (uint8_t *)malloc(total);

            CHECK(data != NULL);
            CHECK(echo != NULL);
            CHECK(stage != NULL);

            if (data && echo && stage) {
                for (size_t i = 0; i < total; i++)
                    data[i] = (uint8_t)(i ^ 0x3C);

                /*
                 * B echoes what it receives, so the two stacks pump each
                 * other.  Both sliding windows are exercised at once, which
                 * is the case a one-directional test never reaches.
                 */
                size_t a_sent = 0, a_read = 0;
                size_t b_read = 0, b_pending = 0;

                while (a_read < total) {
                    int rc = tcp_send(a, data + a_sent, total - a_sent);
                    if (rc > 0)
                        a_sent += (size_t)rc;

                    wire_run_until(&w, w.now_ms + 5, 5);

                    while (b_read < total) {
                        int r = tcp_recv(b, stage + b_pending,
                                         total - b_pending);
                        if (r <= 0)
                            break;
                        b_read += (size_t)r;
                        b_pending += (size_t)r;
                    }

                    /* Echo back whatever has arrived, oldest first. */
                    while (b_pending > 0) {
                        int r = tcp_send(b, stage, b_pending);
                        if (r <= 0)
                            break;
                        memmove(stage, stage + r, b_pending - (size_t)r);
                        b_pending -= (size_t)r;
                    }

                    while (a_read < total) {
                        int r = tcp_recv(a, echo + a_read, total - a_read);
                        if (r <= 0)
                            break;
                        a_read += (size_t)r;
                    }

                    if (a->state == TCP_CLOSED || b->state == TCP_CLOSED)
                        break;
                }

                CHECK_EQ_INT(a_read, (int)total);
                if (a_read == total)
                    CHECK_EQ_INT(memcmp(echo, data, total), 0);

                free(stage);
            }

            free(echo);
            free(data);
        }
        wire_free(&w);
    }

    /* ================= orderly shutdown after all that ================== */
    {
        wire_t w;
        tcp_pcb_t *a = NULL, *b = NULL;

        wire_init(&w, true);
        establish(&w, 4004, &a, &b);

        if (a && b) {
            uint8_t buf[2048];
            for (size_t i = 0; i < sizeof buf; i++)
                buf[i] = (uint8_t)i;

            tcp_send(a, buf, sizeof buf);
            wire_run_until(&w, w.now_ms + 100, 10);

            uint8_t sink[4096];
            CHECK_EQ_INT(drain(b, sink, sizeof sink), (int)sizeof buf);

            tcp_close(a);
            wire_run_until(&w, w.now_ms + 20, 5);
            CHECK_EQ_INT(b->state, TCP_CLOSE_WAIT);

            tcp_close(b);
            wire_run_until(&w, w.now_ms + 20, 5);

            CHECK_EQ_INT(a->state, TCP_TIME_WAIT);
            CHECK_EQ_INT(b->state, TCP_CLOSED);
        }
        wire_free(&w);
    }
}