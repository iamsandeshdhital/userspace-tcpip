#include "harness.h"
#include "log.h"
#include "clock.h"
#include "checksum.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

int g_test_failures;
int g_test_assertions;
const char *g_current_test = "(none)";

void test_fail(const char *file, int line, const char *fmt, ...)
{
    g_test_failures++;

    fprintf(stderr, "\n  FAIL %s:%d [%s]\n    ", file, line, g_current_test);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

/* ------------------------------------------------------------------ */
/* transmit hooks                                                     */
/* ------------------------------------------------------------------ */

static void enqueue(wire_t *w, int dst, const uint8_t *frame, size_t len)
{
    if (len > WIRE_FRAME_MAX) {
        w->dropped++;
        return;
    }

    /* Apply loss and duplication on the way onto the wire. */
    if (w->drop_next > 0) {
        int toward_b = (dst == 1);
        if (!w->drop_toward_b || w->drop_toward_b == toward_b) {
            w->drop_next--;
            w->dropped++;
            return;
        }
    }

    if (w->count >= WIRE_MAX_QUEUE) {
        fprintf(stderr, "  wire queue overflow, dropping a frame\n");
        w->dropped++;
        return;
    }

    int slot = (w->head + w->count) % WIRE_MAX_QUEUE;
    memcpy(w->q[slot].data, frame, len);
    w->q[slot].len = len;
    w->q[slot].dst = dst;
    w->count++;

    if (w->dup_next > 0) {
        w->dup_next--;
        if (w->count < WIRE_MAX_QUEUE) {
            int dup = (w->head + w->count) % WIRE_MAX_QUEUE;
            memcpy(w->q[dup].data, frame, len);
            w->q[dup].len = len;
            w->q[dup].dst = dst;
            w->count++;
        }
    }
}

static void side_tx(void *ctx, const uint8_t *frame, size_t len)
{
    wire_side_t *s = (wire_side_t *)ctx;
    if (!s || !s->w)
        return;
    /* A transmission by one endpoint arrives at the other. */
    enqueue(s->w, s->side == 0 ? 1 : 0, frame, len);
}

/* ------------------------------------------------------------------ */
/* setup                                                              */
/* ------------------------------------------------------------------ */

void wire_init(wire_t *w, bool tap)
{
    memset(w, 0, sizeof *w);

    w->ip_a = 0x0100A8C0;   /* 192.168.0.1, network byte order */
    w->ip_b = 0x0200A8C0;   /* 192.168.0.2 */
    w->mask = 0x00FFFFFF;
    w->now_ms = 1000;       /* nonzero: net_now() falls back to the real clock
                             * when now_ms is 0, which tests must avoid */

    /* Distinguishable MACs so misrouted frames are obvious. */
    static const uint8_t ma[6] = { 0x02, 0, 0, 0, 0, 0x0A };
    static const uint8_t mb[6] = { 0x02, 0, 0, 0, 0, 0x0B };
    memcpy(w->mac_a, ma, 6);
    memcpy(w->mac_b, mb, 6);

    net_init(&w->sa, NULL);
    net_init(&w->sb, NULL);

    w->sa.laddr = w->ip_a;
    w->sa.netmask = w->mask;
    w->sa.is_tap = tap;
    memcpy(w->sa.mac, w->mac_a, 6);

    w->sb.laddr = w->ip_b;
    w->sb.netmask = w->mask;
    w->sb.is_tap = tap;
    memcpy(w->sb.mac, w->mac_b, 6);

    w->side_a.w = w;
    w->side_a.side = 0;
    w->side_b.w = w;
    w->side_b.side = 1;

    net_set_tx_hook(&w->sa, side_tx, &w->side_a);
    net_set_tx_hook(&w->sb, side_tx, &w->side_b);

    net_set_time(&w->sa, w->now_ms);
    net_set_time(&w->sb, w->now_ms);
}

void wire_free(wire_t *w)
{
    net_shutdown(&w->sa);
    net_shutdown(&w->sb);
}

/* ------------------------------------------------------------------ */
/* delivery                                                           */
/* ------------------------------------------------------------------ */

uint32_t wire_flush(wire_t *w)
{
    uint32_t moved = 0;

    while (w->count > 0) {
        wire_pkt_t p = w->q[w->head];
        w->head = (w->head + 1) % WIRE_MAX_QUEUE;
        w->count--;

        netstack_t *dst = (p.dst == 0) ? &w->sa : &w->sb;
        net_rx(dst, p.data, p.len);
        moved++;
        w->delivered++;
    }

    return moved;
}

static void run_timers(wire_t *w)
{
    net_set_time(&w->sa, w->now_ms);
    net_set_time(&w->sb, w->now_ms);
    tcp_timer_tick(&w->sa, w->now_ms);
    tcp_timer_tick(&w->sb, w->now_ms);
}

void wire_advance(wire_t *w, uint64_t ms, uint32_t step_ms)
{
    if (step_ms == 0)
        step_ms = 1;

    uint64_t end = w->now_ms + ms;

    while (w->now_ms < end) {
        w->now_ms += step_ms;
        if (w->now_ms > end)
            w->now_ms = end;

        run_timers(w);
        wire_flush(w);
    }
}

uint32_t wire_run_until(wire_t *w, uint64_t deadline_ms, uint32_t step_ms)
{
    uint32_t moved = 0;

    if (step_ms == 0)
        step_ms = 1;

    while (w->now_ms < deadline_ms) {
        uint64_t next = w->now_ms + step_ms;
        if (next > deadline_ms)
            next = deadline_ms;
        w->now_ms = next;

        run_timers(w);
        moved += wire_flush(w);
    }

    return moved;
}

void wire_drop_next(wire_t *w, int frames, int toward_b)
{
    w->drop_next = frames;
    w->drop_toward_b = toward_b;
}

void wire_dup_next(wire_t *w, int frames)
{
    w->dup_next = frames;
}

void wire_inject(wire_t *w, int side, const uint8_t *frame, size_t len)
{
    netstack_t *dst = (side == 0) ? &w->sa : &w->sb;
    net_rx(dst, frame, len);
}

tcp_pcb_t *wire_find_state(netstack_t *s, tcp_state_t st)
{
    for (tcp_pcb_t *p = s->pcbs; p; p = p->next)
        if (p->state == st)
            return p;
    return NULL;
}

tcp_pcb_t *wire_find_conn(netstack_t *s, uint16_t rport)
{
    for (tcp_pcb_t *p = s->pcbs; p; p = p->next)
        if (p->state != TCP_CLOSED && p->state != TCP_LISTEN &&
            (rport == 0 || p->rport == rport))
            return p;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* packet builders                                                    */
/* ------------------------------------------------------------------ */

uint16_t harness_tcp_csum(uint32_t src_ip, uint32_t dst_ip,
                          const uint8_t *seg, size_t len)
{
    uint8_t pseudo[12];
    wr32_be(pseudo + 0, src_ip);
    wr32_be(pseudo + 4, dst_ip);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_TCP;
    wr16_be(pseudo + 10, (uint16_t)len);

    csum_state_t st;
    csum_init(&st);
    csum_add(&st, pseudo, sizeof pseudo);
    csum_add(&st, seg, len);
    return csum_final(&st);
}

size_t harness_tcp_packet(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                          uint16_t sport, uint16_t dport,
                          uint32_t seq, uint32_t ack,
                          uint8_t flags, uint16_t window,
                          const void *payload, size_t len)
{
    uint8_t *seg = out + IP_HDR_MIN_LEN;

    wr16_be(seg + 0, sport);
    wr16_be(seg + 2, dport);
    wr32_be(seg + 4, seq);
    wr32_be(seg + 8, ack);
    seg[12] = (uint8_t)((TCP_HDR_MIN_LEN / 4) << 4);
    seg[13] = flags;
    wr16_be(seg + 14, window);
    wr16_be(seg + 16, 0);
    wr16_be(seg + 18, 0);

    if (len)
        memcpy(seg + TCP_HDR_MIN_LEN, payload, len);

    size_t seg_len = TCP_HDR_MIN_LEN + len;
    wr16_be(seg + 16, harness_tcp_csum(src_ip, dst_ip, seg, seg_len));

    ip_hdr_t *iph = (ip_hdr_t *)out;
    ip_build(iph, src_ip, dst_ip, IP_PROTO_TCP, 0, (uint16_t)seg_len,
             USSTACK_TTL_DEFAULT);
    ip_finalize(iph, (uint16_t)seg_len);

    return IP_HDR_MIN_LEN + seg_len;
}

size_t harness_icmp_echo(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t id, uint16_t seq, size_t payload_len)
{
    size_t icmp_len = ICMP_HDR_LEN + 4 + payload_len;
    icmp_echo_t *echo = (icmp_echo_t *)(out + IP_HDR_MIN_LEN);

    echo->type = ICMP_ECHO;
    echo->code = 0;
    echo->id = htons(id);
    echo->seq = htons(seq);

    uint8_t *payload = out + IP_HDR_MIN_LEN + 8;
    for (size_t i = 0; i < payload_len; i++)
        payload[i] = (uint8_t)(0xA0 + i);

    icmp_finalize(echo, icmp_len);

    ip_hdr_t *iph = (ip_hdr_t *)out;
    ip_build(iph, src_ip, dst_ip, IP_PROTO_ICMP, 0, (uint16_t)icmp_len,
             USSTACK_TTL_DEFAULT);
    ip_finalize(iph, (uint16_t)icmp_len);

    return IP_HDR_MIN_LEN + icmp_len;
}

static void capture_tx(void *ctx, const uint8_t *frame, size_t len)
{
    capture_t *c = (capture_t *)ctx;

    if (!c || c->count >= 32 || len > WIRE_FRAME_MAX)
        return;

    memcpy(c->buf[c->count], frame, len);
    c->len[c->count] = len;
    c->count++;
}

void harness_attach_capture(netstack_t *s, capture_t *c)
{
    memset(c, 0, sizeof *c);
    c->stack = s;
    net_set_tx_hook(s, capture_tx, c);
}