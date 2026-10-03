/*
 * tcp_socket.c -- the TCP protocol engine.
 *
 * Layout:
 *
 *   1. helpers                  state names, dumps, spans
 *   2. control-block lifetime   allocation, lookup, teardown
 *   3. RTT / RTO                RFC 6298
 *   4. retransmission queue     enqueue, acknowledge, retransmit
 *   5. segment output           header build, checksum, hand to the IP layer
 *   6. window management        sliding window, effective send window
 *   7. input processing         RFC 793 section 3.9 state machine
 *   8. reassembly               out-of-order segment queue
 *   9. timers                   RTO, zero-window persist, TIME-WAIT
 *  10. application API          bind/listen/connect/accept/send/recv/close
 */
#include "tcp_socket.h"
#include "net.h"
#include "checksum.h"
#include "log.h"
#include "clock.h"

#include <stdio.h>
#include <stdarg.h>

#define TCP_SNDBUF TCP_TXBUF_SIZE
#define TCP_RCVBUF TCP_RXBUF_SIZE

/* ------------------------------------------------------------------ */
/* 1. helpers                                                         */
/* ------------------------------------------------------------------ */

const char *tcp_state_str(tcp_state_t s)
{
    static const char *const names[TCP_STATE_MAX] = {
        "CLOSED", "LISTEN", "SYN-SENT", "SYN-RECEIVED", "ESTABLISHED",
        "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK",
        "TIME-WAIT",
    };

    if ((int)s < 0 || (int)s >= (int)TCP_STATE_MAX)
        return "???";
    return names[s];
}

void tcp_pcb_dump(const tcp_pcb_t *p)
{
    char lb[INET_ADDRSTRLEN], rb[INET_ADDRSTRLEN];

    log_info("  %s:%u -> %s:%u  state=%s%s",
             ip_str(p->laddr, lb, sizeof lb), p->lport,
             ip_str(p->raddr, rb, sizeof rb), p->rport,
             tcp_state_str(p->state),
             p->err ? "  [error]" : "");

    log_info("    seq: una=%u nxt=%u   snd_wnd=%u   rcv_nxt=%u rcv_wnd=%u",
             p->snd_una, p->snd_nxt, p->snd_wnd,
             p->rcv_nxt, (unsigned)rb_avail(&p->rx_buf));

    log_info("    buf: tx %u/%u   rx %u/%u   in-flight=%u   ooo-queued=%u",
             rb_used(&p->tx_buf), TCP_SNDBUF,
             rb_used(&p->rx_buf), TCP_RCVBUF,
             p->txq_bytes, (unsigned)p->ooo_head ? 1u : 0u);

    log_info("    rto=%llums srtt=%llums rttvar=%llums dupacks=%u",
             (unsigned long long)p->rto_ms,
             (unsigned long long)p->srtt_ms,
             (unsigned long long)p->rttvar_ms,
             p->dupack_count);

    log_info("    stats: sent=%llu recv=%llu retrans=%llu segs=%llu dupacks=%llu",
             (unsigned long long)p->bytes_sent,
             (unsigned long long)p->bytes_recv,
             (unsigned long long)p->bytes_retrans,
             (unsigned long long)p->segs_sent,
             (unsigned long long)p->dupacks_in);
}

/* Sequence-space bytes a queued transmission occupies: the payload plus one
 * each for SYN and FIN, which occupy a sequence number but no buffer byte. */
static uint32_t txseg_span(const tcp_txseg_t *t)
{
    uint32_t n = t->len;
    if (t->flags & TH_SYN) n++;
    if (t->flags & TH_FIN) n++;
    return n;
}

static uint32_t seg_span(const tcp_seg_t *seg)
{
    uint32_t n = seg->payload_len;
    if (seg->flags & TH_SYN) n++;
    if (seg->flags & TH_FIN) n++;
    return n;
}

static void pcb_log(const tcp_pcb_t *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void pcb_log(const tcp_pcb_t *p, const char *fmt, ...)
{
    char  lb[INET_ADDRSTRLEN], rb[INET_ADDRSTRLEN], buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    log_debug("tcp %s:%u <-> %s:%u [%s] %s",
              ip_str(p->laddr, lb, sizeof lb), p->lport,
              ip_str(p->raddr, rb, sizeof rb), p->rport,
              tcp_state_str(p->state), buf);
}

static void tcp_set_state(tcp_pcb_t *p, tcp_state_t st)
{
    if (p->state == st)
        return;
    pcb_log(p, "state -> %s", tcp_state_str(st));
    p->state = st;
}

static netstack_t *stack_of(const tcp_pcb_t *p)
{
    return (netstack_t *)p->stack;
}

static void tcp_pcb_unlink(tcp_pcb_t *p);

/* Defined with the retransmission queue, used by both the fast-retransmit and
 * the timeout paths. */
static void retransmit_segment(netstack_t *s, tcp_pcb_t *p, tcp_txseg_t *t,
                               uint64_t now);

/* ------------------------------------------------------------------ */
/* 2. control-block lifetime                                          */
/* ------------------------------------------------------------------ */

static uint32_t pcb_isn(void)
{
    /*
     * Initial send sequence numbers must be unpredictable, otherwise an
     * off-path attacker could blind-splice data into a connection.  A clock
     * plus a counter is the classic cheap approximation.
     */
    static uint32_t counter;
    uint64_t t = mono_ms();
    return (uint32_t)((t << 16) ^ (t >> 16) ^ (++counter * 2654435761u));
}

static tcp_pcb_t *pcb_alloc(uint32_t laddr, uint16_t lport)
{
    tcp_pcb_t *p = (tcp_pcb_t *)calloc(1, sizeof *p);
    if (!p)
        return NULL;

    if (!rb_init(&p->tx_buf, TCP_SNDBUF)) {
        free(p);
        return NULL;
    }
    if (!rb_init(&p->rx_buf, TCP_RCVBUF)) {
        rb_free(&p->tx_buf);
        free(p);
        return NULL;
    }

    p->laddr = laddr;
    p->lport = lport;
    p->raddr = 0;
    p->rport = 0;
    p->state = TCP_CLOSED;
    p->rto_ms = TCP_RTO_INITIAL_MS;
    p->mss_local = USSTACK_MSS_DEFAULT;
    p->mss_remote = 0;
    p->wscale_local = 0;
    p->wscale_remote = 0;
    p->next_ack = 1;
    p->created_ms = mono_ms();
    p->stack = NULL;
    return p;
}

static void pcb_free(tcp_pcb_t *p)
{
    if (!p)
        return;

    while (p->txq_head) {
        tcp_txseg_t *n = p->txq_head->next;
        free(p->txq_head);
        p->txq_head = n;
    }
    p->txq_tail = NULL;
    p->txq_bytes = 0;

    while (p->ooo_head) {
        tcp_ooo_t *n = p->ooo_head->next;
        free(p->ooo_head->data);
        free(p->ooo_head);
        p->ooo_head = n;
    }

    /* Accepted children the application never took ownership of. */
    while (p->accept_head) {
        tcp_pcb_t *n = p->accept_head->accept_next;
        p->accept_head->accept_next = NULL;
        tcp_pcb_unlink(p->accept_head);
        pcb_free(p->accept_head);
        p->accept_head = n;
    }

    rb_free(&p->tx_buf);
    rb_free(&p->rx_buf);
    free(p);
}

static void pcb_link(netstack_t *s, tcp_pcb_t *p)
{
    p->stack = s;
    p->next = s->pcbs;
    s->pcbs = p;
}

void tcp_pcb_destroy(tcp_pcb_t *p)
{
    if (!p)
        return;
    tcp_pcb_unlink(p);
    pcb_free(p);
}

static void tcp_pcb_unlink(tcp_pcb_t *p)
{
    if (!p || !p->stack)
        return;

    tcp_pcb_t **pp = &p->stack->pcbs;
    while (*pp) {
        if (*pp == p) {
            *pp = p->next;
            p->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

/*
 * Find the control block a segment belongs to.  Two kinds of match count:
 *
 *   - an exact four-tuple match against a live connection, and
 *   - a LISTEN socket whose local port matches, which is how a passive open is
 *     recognised before any connection for that peer exists.
 *
 * CLOSED blocks are skipped: those are dead sockets the application may still
 * hold a pointer to.  TIME-WAIT is deliberately *not* skipped -- a
 * retransmitted FIN must be re-acknowledged there, and the state machine
 * handles that case by restarting the 2*MSL timer.
 */
static tcp_pcb_t *tcp_find_pcb(netstack_t *s, uint32_t src_ip, uint32_t dst_ip,
                               const tcp_seg_t *seg)
{
    tcp_pcb_t *fallback = NULL;

    for (tcp_pcb_t *p = s->pcbs; p; p = p->next) {
        if (p->state == TCP_CLOSED)
            continue;
        if (p->lport != seg->dst_port)
            continue;
        if (p->laddr != dst_ip)
            continue;

        if (p->state == TCP_LISTEN) {
            if (!fallback)
                fallback = p;
            continue;
        }

        if (p->rport == seg->src_port && p->raddr == src_ip)
            return p;
    }

    return fallback;
}

tcp_pcb_t *tcp_first(struct netstack *s_v)
{
    netstack_t *s = (netstack_t *)s_v;
    return s->pcbs;
}

/* Is this local port already claimed by a live socket? */
static bool port_in_use(netstack_t *s, uint32_t laddr, uint16_t lport,
                        const tcp_pcb_t *except)
{
    for (tcp_pcb_t *p = s->pcbs; p; p = p->next) {
        if (p == except)
            continue;
        if (p->state == TCP_CLOSED)
            continue;
        if (p->lport != lport || p->laddr != laddr)
            continue;
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* 3. RTT estimation and RTO (RFC 6298)                               */
/* ------------------------------------------------------------------ */

#define RTO_K 4          /* clock granularity factor */
#define RTO_ALPHA 8      /* smoothing weight          */
#define RTO_BETA  4      /* variance weight           */

static void rtt_update(tcp_pcb_t *p, uint64_t sample_ms)
{
    if (!p->rtt_sampled) {
        p->srtt_ms    = sample_ms;
        p->rttvar_ms  = sample_ms / 2;
        p->rtt_sampled = true;
    } else {
        /* RTTVAR must use the *previous* SRTT, so update it first. */
        uint64_t diff = (p->srtt_ms > sample_ms) ? p->srtt_ms - sample_ms
                                                 : sample_ms - p->srtt_ms;
        p->rttvar_ms = ((RTO_BETA - 1) * p->rttvar_ms + diff) / RTO_BETA;
        p->srtt_ms   = ((RTO_ALPHA - 1) * p->srtt_ms + sample_ms) / RTO_ALPHA;
    }

    uint64_t var = RTO_K * p->rttvar_ms;
    p->rto_ms = p->srtt_ms + MAX(var, (uint64_t)1);
    p->rto_ms = MAX(p->rto_ms, (uint64_t)TCP_RTO_MIN_MS);
    p->rto_ms = MIN(p->rto_ms, (uint64_t)TCP_RTO_MAX_MS);
}

/* ------------------------------------------------------------------ */
/* 4. retransmission queue                                             */
/* ------------------------------------------------------------------ */

static tcp_txseg_t *txq_push(tcp_pcb_t *p, uint32_t seq, uint32_t len,
                             uint8_t flags, uint32_t off, uint64_t now)
{
    tcp_txseg_t *t = (tcp_txseg_t *)calloc(1, sizeof *t);
    if (!t) {
        log_error("tcp: out of memory allocating a transmit queue entry");
        return NULL;
    }

    t->seq     = seq;
    t->len     = len;
    t->flags   = flags;
    t->off     = off;
    t->sent_ms = now;
    t->rto_ms  = p->rto_ms;

    if (p->txq_tail)
        p->txq_tail->next = t;
    else
        p->txq_head = t;
    p->txq_tail = t;

    p->txq_bytes += txseg_span(t);
    return t;
}

/*
 * Retire every queue entry the peer has acknowledged, reclaim the matching
 * send-buffer space, and take the opportunity to sample the round-trip time.
 *
 * Karn's algorithm: only a segment that has never been retransmitted yields a
 * sample.  Timing a retransmission would measure the ack of the retry while
 * attributing it to the original, producing an RTO that is wrong precisely
 * when the path is misbehaving.
 */
static void txq_ack(tcp_pcb_t *p, uint32_t ack, uint64_t now)
{
    uint32_t freed = 0;

    while (p->txq_head) {
        tcp_txseg_t *t = p->txq_head;
        if (!SEQ_LEQ(t->seq + txseg_span(t), ack))
            break;

        if (t->rtx_count == 0 && !p->rtt_sampled)
            rtt_update(p, now - t->sent_ms);

        freed += t->len;
        p->txq_bytes -= txseg_span(t);

        p->txq_head = t->next;
        free(t);
        if (!p->txq_head)
            p->txq_tail = NULL;
    }

    if (freed) {
        rb_consume(&p->tx_buf, freed);
        p->tx_base_seq += freed;
        p->bytes_sent += freed;
    }

    /*
     * Re-point the retransmission timer at the new head of the queue, or
     * disarm it.  Without this the timer could still be aimed at a deadline
     * derived from a segment that no longer exists.
     */
    if (p->txq_head)
        p->retransmit_deadline_ms = now + p->txq_head->rto_ms;
    else
        p->retransmit_deadline_ms = 0;
}

/* ------------------------------------------------------------------ */
/* 5. segment output                                                  */
/* ------------------------------------------------------------------ */

static uint16_t tcp_csum(uint32_t src_ip, uint32_t dst_ip,
                         const uint8_t *seg, size_t len)
{
    /*
     * The TCP checksum covers a 12-byte pseudo-header as well as the segment,
     * which is what stops a segment being replayed against a different
     * connection or a different protocol.  Summing both through one
     * accumulator is valid because the sum is commutative.
     */
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

static uint16_t advertised_window(const tcp_pcb_t *p)
{
    /*
     * With window scaling (RFC 7323) we may hold more than 65535 bytes, but
     * the wire field is 16 bits, so the advertised value is the real window
     * right-shifted by our scale.  Never round a non-empty window down to
     * zero: a zero window tells the peer to stop, and a peer that is waiting
     * for us to read would deadlock.
     */
    uint32_t avail = rb_avail(&p->rx_buf);

    if (p->wscale_local == 0)
        return (uint16_t)MIN(avail, 0xFFFFu);

    uint32_t scaled = avail >> p->wscale_local;
    if (avail > 0 && scaled == 0)
        scaled = 1;
    return (uint16_t)MIN(scaled, 0xFFFFu);
}

/*
 * How many bytes may go on the wire right now: the smaller of
 *
 *   - the peer's advertised window (already scaled), which is flow control,
 *     and
 *   - our own free send-buffer space, which stops us accepting more data than
 *     we could still retransmit.
 */
static uint32_t effective_send_window(const tcp_pcb_t *p)
{
    return MIN(p->snd_wnd, rb_avail(&p->tx_buf));
}

/*
 * Build and transmit one segment.  This does everything except maintain
 * sequence and retransmission state, which is what lets a retransmission
 * re-send a segment without enqueueing a second copy of it.
 *
 * `seq` is the sequence number the segment should carry.  Normally that is
 * SND.NXT, but a retransmission passes the original value so SND.NXT is left
 * alone.
 */
static int tcp_transmit(netstack_t *s, tcp_pcb_t *p, uint32_t seq,
                        uint8_t flags, const uint8_t *data, uint32_t len)
{
    uint8_t  buf[USSTACK_MTU_DEFAULT];
    uint8_t  opts[TCP_MAX_OPTIONS];
    size_t   opt_len = 0;
    bool     syn = (flags & TH_SYN) != 0;

    uint32_t max_payload = s->mtu - IP_HDR_MIN_LEN - TCP_HDR_MIN_LEN -
                           TCP_MAX_OPTIONS;

    if (len > max_payload) {
        log_error("tcp: segment of %u bytes exceeds the %u-byte MTU",
                  len, s->mtu);
        return -1;
    }

    /*
     * Options appear only on the SYN.  Re-offering MSS or window scale later
     * is forbidden (RFC 7323 section 2.3) and would only waste bytes.
     */
    if (syn)
        opt_len = tcp_build_options(opts, sizeof opts, p->mss_local,
                                    p->wscale_local, true,
                                    (uint32_t)net_now(s), true);

    size_t hdr_len = TCP_HDR_MIN_LEN + opt_len;

    /*
     * The header is written at explicit offsets in network byte order: the
     * buffer is not guaranteed to be aligned, and assigning the packed
     * struct's fields one at a time would be both slower and no clearer.
     */
    wr16_be(buf + 0,  p->lport);
    wr16_be(buf + 2,  p->rport);
    wr32_be(buf + 4,  seq);
    wr32_be(buf + 8,  (flags & TH_ACK) ? p->rcv_nxt : 0u);
    buf[12] = (uint8_t)((hdr_len / 4) << 4);   /* data offset, in 32-bit words */
    buf[13] = flags;
    wr16_be(buf + 14, advertised_window(p));
    wr16_be(buf + 16, 0);                      /* checksum placeholder */
    wr16_be(buf + 18, 0);                      /* urgent pointer */

    if (opt_len)
        memcpy(buf + TCP_HDR_MIN_LEN, opts, opt_len);
    if (len)
        memcpy(buf + TCP_HDR_MIN_LEN + opt_len, data, len);

    size_t seg_len = hdr_len + len;
    wr16_be(buf + 16, tcp_csum(p->laddr, p->raddr, buf, seg_len));

    uint8_t packet[USSTACK_MTU_DEFAULT];
    ip_hdr_t *iph = (ip_hdr_t *)packet;
    ip_build(iph, p->laddr, p->raddr, IP_PROTO_TCP, s->ip_id++,
             (uint16_t)seg_len, USSTACK_TTL_DEFAULT);
    memcpy(packet + IP_HDR_MIN_LEN, buf, seg_len);
    ip_finalize(iph, (uint16_t)seg_len);

    char lb[INET_ADDRSTRLEN], rb[INET_ADDRSTRLEN], fb[24];
    log_trace("tcp TX %s:%u -> %s:%u seq=%u ack=%u len=%u wnd=%u [%s]",
              ip_str(p->laddr, lb, sizeof lb), p->lport,
              ip_str(p->raddr, rb, sizeof rb), p->rport,
              seq, (flags & TH_ACK) ? p->rcv_nxt : 0u, len,
              advertised_window(p), tcp_flags_str(flags, fb, sizeof fb));
    log_hexdump(LOG_LEVEL_TRACE, "  tcp segment", buf, seg_len);

    return net_tx(s, packet, IP_HDR_MIN_LEN + seg_len) < 0 ? -1 : 0;
}

/*
 * Transmit a segment and record it for retransmission, advancing SND.NXT.
 */
static int tcp_output(netstack_t *s, tcp_pcb_t *p, uint32_t seq, uint8_t flags,
                      const uint8_t *data, uint32_t len)
{
    uint64_t now = net_now(s);
    uint32_t span = len + ((flags & TH_SYN) ? 1u : 0u) +
                    ((flags & TH_FIN) ? 1u : 0u);

    if (tcp_transmit(s, p, seq, flags, data, len) < 0)
        return -1;

    /*
     * Queue it.  The payload offset follows from SND.NXT's position in the
     * send buffer, and stays valid because the buffer is trimmed only on
     * acknowledgement.
     */
    if (span) {
        uint32_t off = len ? (seq - p->tx_base_seq) : 0;
        tcp_txseg_t *t = txq_push(p, seq, len, flags, off, now);

        /*
         * Arm the retransmission timer only when this segment became the
         * oldest unacknowledged one: the timer must track the head of the
         * queue, not the most recent transmission.
         */
        if (t && t == p->txq_head)
            p->retransmit_deadline_ms = now + t->rto_ms;
    }

    p->snd_nxt += span;
    p->segs_sent++;
    return 0;
}

/*
 * Send a bare ACK.  Used after consuming data, on out-of-order arrival, after
 * a state transition, and whenever an otherwise valid segment is unacceptable.
 *
 * This is an immediate ACK rather than a delayed one.  Correctness does not
 * require the delay and skipping it keeps the receive path easy to follow;
 * docs/PROTOCOL_NOTES.md records the trade-off.
 */
static void tcp_ack_now(netstack_t *s, tcp_pcb_t *p)
{
    tcp_output(s, p, p->snd_nxt, TH_ACK, NULL, 0);
}

/*
 * RST for an unacceptable segment (RFC 793 section 3.10.7.1).
 *
 * If the segment carried an ACK, our sequence number is the peer's ACK number
 * and we send a bare RST.  Otherwise there is nothing to echo, so we send
 * RST+ACK acknowledging the end of the segment.
 */
static void tcp_send_reset(netstack_t *s, uint32_t laddr, uint16_t lport,
                           uint32_t raddr, uint16_t rport,
                           const tcp_seg_t *seg)
{
    uint8_t buf[TCP_HDR_MIN_LEN];
    uint8_t flags = TH_RST;
    uint32_t seq = 0;

    if (seg && (seg->flags & TH_ACK)) {
        seq = seg->ack;
    } else if (seg) {
        flags |= TH_ACK;
    }

    wr16_be(buf + 0, lport);
    wr16_be(buf + 2, rport);
    wr32_be(buf + 4, seq);
    wr32_be(buf + 8, (flags & TH_ACK) ? (seg->seq + seg_span(seg)) : 0u);
    buf[12] = (uint8_t)((TCP_HDR_MIN_LEN / 4) << 4);
    buf[13] = flags;
    wr16_be(buf + 14, 0);
    wr16_be(buf + 16, 0);
    wr16_be(buf + 18, 0);

    size_t seg_len = TCP_HDR_MIN_LEN;
    wr16_be(buf + 16, tcp_csum(laddr, raddr, buf, seg_len));

    uint8_t packet[IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN];
    ip_hdr_t *iph = (ip_hdr_t *)packet;
    ip_build(iph, laddr, raddr, IP_PROTO_TCP, s->ip_id++,
             (uint16_t)seg_len, USSTACK_TTL_DEFAULT);
    memcpy(packet + IP_HDR_MIN_LEN, buf, seg_len);
    ip_finalize(iph, (uint16_t)seg_len);

    char rb[INET_ADDRSTRLEN];
    log_debug("tcp: sending RST to %s:%u",
              ip_str(raddr, rb, sizeof rb), rport);

    net_tx(s, packet, IP_HDR_MIN_LEN + seg_len);
}

/* ------------------------------------------------------------------ */
/* 6. sending                                                         */
/* ------------------------------------------------------------------ */

/*
 * Push queued data out as far as the window allows, and emit a FIN once the
 * queue has drained and the application has asked to close.
 *
 * The unsent region is [SND.NXT, tx_base_seq + rb_used(tx_buf)), so its size
 * follows from SND.NXT alone -- which is exactly why the send buffer is only
 * ever trimmed on acknowledgement.
 */
void tcp_send_pending(void *stack_v, tcp_pcb_t *p)
{
    netstack_t *s = (netstack_t *)stack_v;

    if (p->state != TCP_ESTABLISHED && p->state != TCP_CLOSE_WAIT &&
        p->state != TCP_SYN_RECEIVED)
        return;

    uint32_t max_payload = s->mtu - IP_HDR_MIN_LEN - TCP_HDR_MIN_LEN -
                           TCP_MAX_OPTIONS;
    uint32_t mss = p->mss_remote ? p->mss_remote : USSTACK_MSS_DEFAULT;
    if (mss > max_payload)
        mss = max_payload;

    for (;;) {
        uint32_t buffered_end = p->tx_base_seq + rb_used(&p->tx_buf);
        uint32_t unsent = SEQ_GT(buffered_end, p->snd_nxt)
                        ? buffered_end - p->snd_nxt : 0;

        bool fin_pending = (p->flags & TF_NEED_FIN) && (unsent == 0);

        if (!unsent && !fin_pending)
            return;

        if (unsent) {
            uint32_t wnd = effective_send_window(p);
            uint32_t inflight = p->txq_bytes;

            if (inflight >= wnd)
                return;                    /* the window is closed */

            uint32_t len = MIN(MIN(unsent, wnd - inflight), mss);
            if (!len)
                return;

            uint8_t payload[USSTACK_MTU_DEFAULT];
            rb_read(&p->tx_buf, p->snd_nxt - p->tx_base_seq,
                    payload, len);

            /*
             * A FIN rides along with the final byte when the remaining data
             * fits in this one segment, which saves a round trip.
             */
            bool with_fin = (p->flags & TF_NEED_FIN) && (len == unsent);
            uint8_t flags = TH_ACK | TH_PSH | (with_fin ? TH_FIN : 0u);

            if (tcp_output(s, p, p->snd_nxt, flags, payload, len) < 0)
                return;

            if (with_fin) {
                p->flags &= ~TF_NEED_FIN;
                p->flags |= TF_SENT_FIN;
                if (p->state == TCP_ESTABLISHED)
                    tcp_set_state(p, TCP_FIN_WAIT_1);
                else
                    tcp_set_state(p, TCP_LAST_ACK);
            }
            continue;
        }

        /* Only a FIN is left to send. */
        if (tcp_output(s, p, p->snd_nxt, TH_ACK | TH_FIN, NULL, 0) < 0)
            return;

        p->flags &= ~TF_NEED_FIN;
        p->flags |= TF_SENT_FIN;
        tcp_set_state(p, p->state == TCP_ESTABLISHED ? TCP_FIN_WAIT_1
                                                      : TCP_LAST_ACK);
        return;
    }
}

/* ------------------------------------------------------------------ */
/* 7. input processing                                                */
/* ------------------------------------------------------------------ */

/*
 * Sequence acceptability, RFC 793 section 3.9 step 4.
 *
 * A segment is acceptable when any part of it falls inside the receive
 * window.  Four cases have to be covered, and the fourth is easy to forget:
 * a segment that lies entirely *ahead* of RCV.NXT but still inside the window
 * is perfectly acceptable -- it is simply out of order, and rejecting it would
 * make reassembly and duplicate-ACK-driven fast retransmit impossible.
 */
static bool seq_acceptable(const tcp_pcb_t *p, uint32_t seq, uint32_t seg_len)
{
    uint32_t wnd = rb_avail(&p->rx_buf);

    /* A closed window admits nothing but an exact-position ACK. */
    if (wnd == 0)
        return seq == p->rcv_nxt;

    /* No payload: acceptable anywhere in the window, RCV.NXT included. */
    if (seg_len == 0)
        return SEQ_GEQ(seq, p->rcv_nxt) && SEQ_LEQ(seq, p->rcv_nxt + wnd);

    /* Cases 1 and 2: the segment starts at or before RCV.NXT and reaches
     * past it. */
    if (SEQ_LEQ(seq, p->rcv_nxt) && SEQ_GT(seq + seg_len, p->rcv_nxt))
        return true;

    /* Case 4: entirely ahead of RCV.NXT but still within the window. */
    if (SEQ_GT(seq, p->rcv_nxt) && SEQ_LT(seq, p->rcv_nxt + wnd))
        return true;

    /* Case 3: a segment at least as long as the window can only be
     * acceptable if it swallows RCV.NXT. */
    if (seg_len >= wnd)
        return SEQ_LEQ(seq, p->rcv_nxt) && SEQ_GT(seq + seg_len, p->rcv_nxt + wnd);

    return false;
}

/* Apply the peer's SYN options; fill in defaults when they are absent. */
static void negotiate_options(tcp_pcb_t *p, const tcp_seg_t *seg)
{
    if (seg->mss && seg->mss < p->mss_local)
        p->mss_local = seg->mss;
    if (!p->mss_local)
        p->mss_local = USSTACK_MSS_DEFAULT;

    p->mss_remote = seg->mss ? seg->mss : USSTACK_MSS_DEFAULT;

    /*
     * Window scaling may be enabled only by the segment carrying the SYN; an
     * offer in any other segment must be ignored (RFC 7323 section 2.3).
     */
    if (seg->wscale != 0xFF) {
        p->wscale_remote = seg->wscale;
        p->wscale_local  = 7;       /* 64 KiB << 7 = 8 MiB ceiling */
        p->flags |= TF_TIMESTAMP;
    }
}

/* ------------------------------------------------------------------ */

static void ooo_insert(tcp_pcb_t *p, uint32_t seq, const uint8_t *data,
                       uint32_t len);
static void ooo_drain(tcp_pcb_t *p);

static bool syn_acked(const tcp_pcb_t *p)
{
    /* Our SYN has been acknowledged when nothing is queued below the ACK. */
    return !p->txq_head || SEQ_LEQ(p->snd_una, p->txq_head->seq);
}

/*
 * Process the ACK field: retire acknowledged data, update the send window,
 * count duplicate ACKs, and run the state transitions that an acknowledgement
 * of our SYN or FIN triggers.
 */
static void tcp_process_ack(netstack_t *s, tcp_pcb_t *p, const tcp_seg_t *seg)
{
    uint32_t ack = seg->ack;

    /* An ACK outside (SND.UNA, SND.NXT] is unacceptable: re-state ours. */
    if (SEQ_LT(ack, p->snd_una) || SEQ_GT(ack, p->snd_nxt)) {
        log_debug("tcp: unacceptable ACK %u outside (%u, %u]",
                  ack, p->snd_una, p->snd_nxt);
        tcp_ack_now(s, p);
        return;
    }

    if (SEQ_GT(ack, p->snd_una)) {
        uint32_t acked = ack - p->snd_una;
        pcb_log(p, "ACK %u, retiring %u byte(s)", ack, acked);
        txq_ack(p, ack, net_now(s));
        p->snd_una = ack;
        p->dupack_count = 0;
        p->recover = 0;
        p->flags &= ~TF_FAST_RETRANS;

    } else if (seg->payload_len == 0 && !(seg->flags & TH_SYN) &&
               (p->txq_head || p->snd_una != p->snd_nxt)) {
        /*
         * A duplicate ACK: no new data acknowledged.  Three in a row is
         * strong evidence of loss rather than reordering, because it means
         * four segments have arrived out of order.
         *
         * The condition also requires something to be outstanding.  An ACK
         * that acknowledges nothing and has nothing left to acknowledge --
         * the third leg of the handshake, say -- is not a duplicate
         * acknowledgement of data, and counting it would corrupt the
         * fast-retransmit state.
         */
        p->dupack_count++;
        p->dupacks_in++;

        if (p->dupack_count == TCP_MAX_DUP_ACK) {
            tcp_txseg_t *t = p->txq_head;

            if (t && !p->recover) {
                p->recover = p->snd_nxt;
                p->flags |= TF_FAST_RETRANS;
                pcb_log(p, "3 duplicate ACKs: fast retransmit of seq %u",
                        t->seq);

                retransmit_segment(s, p, t, net_now(s));
                p->retransmit_deadline_ms = net_now(s) + t->rto_ms;
            }
        } else if (p->dupack_count > TCP_MAX_DUP_ACK &&
                   p->flags & TF_FAST_RETRANS && p->recover &&
                   SEQ_GEQ(p->snd_nxt, p->recover)) {
            /*
             * Each further duplicate ACK means another segment reached the
             * peer, so send one more immediately instead of waiting for the
             * timer.  This is the "fast recovery" half of RFC 5681.
             */
            tcp_txseg_t *t = p->txq_head;
            if (t && t->rtx_count == 0) {
                retransmit_segment(s, p, t, net_now(s));
                p->retransmit_deadline_ms = net_now(s) + t->rto_ms;
            }
        }
    }

    /* Update the send window from the peer's advertised value. */
    uint32_t peer_wnd = (uint32_t)seg->window << p->wscale_remote;
    if (peer_wnd > TCP_SNDBUF)
        peer_wnd = TCP_SNDBUF;

    bool reopened = (p->snd_wnd == 0 && peer_wnd > 0);
    p->snd_wnd = peer_wnd;
    if (reopened) {
        pcb_log(p, "peer window reopened (%u bytes)", peer_wnd);
        p->persist_deadline_ms = 0;
    }

    /*
     * Acknowledgement of our SYN opens a passive connection.
     */
    if (p->state == TCP_SYN_RECEIVED && syn_acked(p))
        tcp_set_state(p, TCP_ESTABLISHED);

    /* Acknowledgement of our FIN. */
    if ((p->flags & TF_SENT_FIN) && SEQ_GEQ(p->snd_una, p->snd_nxt)) {
        p->flags &= ~TF_SENT_FIN;

        switch (p->state) {
        case TCP_FIN_WAIT_1:
            tcp_set_state(p, TCP_FIN_WAIT_2);
            break;
        case TCP_CLOSING:
        case TCP_FIN_WAIT_2:
            tcp_set_state(p, TCP_TIME_WAIT);
            p->timewait_deadline_ms = net_now(s) + TCP_TIME_WAIT_MS;
            break;
        case TCP_LAST_ACK:
            tcp_set_state(p, TCP_CLOSED);
            break;
        case TCP_TIME_WAIT:
            /* A retransmitted FIN re-arms the TIME-WAIT timer. */
            p->timewait_deadline_ms = net_now(s) + TCP_TIME_WAIT_MS;
            break;
        default:
            break;
        }
    }

    /*
     * The peer may have advertised a larger window, or reopened one that had
     * been closed to zero.  Either way there may now be room to send.
     */
    tcp_send_pending(s, p);
}

void tcp_input(void *stack_v, uint32_t src_ip, uint32_t dst_ip,
               const uint8_t *buf, size_t len)
{
    netstack_t *s = (netstack_t *)stack_v;
    char rb[INET_ADDRSTRLEN], lb[INET_ADDRSTRLEN];

    if (len < TCP_HDR_MIN_LEN) {
        log_debug("tcp: runt segment (%zu bytes), dropping", len);
        s->rx_dropped++;
        return;
    }

    tcp_seg_t seg;
    if (!tcp_parse(buf, len, len, &seg)) {
        log_warn("tcp: malformed segment (%zu bytes), dropping", len);
        s->rx_dropped++;
        return;
    }

    /*
     * The checksum covers the pseudo-header plus the whole segment.  A bad
     * checksum is fatal: trusting the header of a corrupted segment would let
     * a stray bit drive our sequence state.
     */
    uint8_t pseudo[12];
    wr32_be(pseudo + 0, src_ip);
    wr32_be(pseudo + 4, dst_ip);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_TCP;
    wr16_be(pseudo + 10, (uint16_t)len);

    csum_state_t cs;
    csum_init(&cs);
    csum_add(&cs, pseudo, sizeof pseudo);
    csum_add(&cs, buf, len);
    if (csum_final(&cs) != 0) {
        log_warn("tcp: bad checksum from %s:%u, dropping",
                 ip_str(src_ip, rb, sizeof rb), seg.src_port);
        s->rx_dropped++;
        return;
    }

    char fb[24];
    log_trace("tcp RX %s:%u -> %s:%u seq=%u ack=%u len=%u wnd=%u [%s]",
              ip_str(src_ip, rb, sizeof rb), seg.src_port,
              ip_str(dst_ip, lb, sizeof lb),
              seg.dst_port, seg.seq, seg.ack, seg.payload_len, seg.window,
              tcp_flags_str(seg.flags, fb, sizeof fb));
    log_hexdump(LOG_LEVEL_TRACE, "  tcp segment", buf, len);

    /*
     * Locate the socket.  If there is none, the connection does not exist:
     * reply with RST, unless the offending segment was itself a RST -- in
     * which case there is nothing to do, and answering would risk a RST
     * storm.
     */
    tcp_pcb_t *p = tcp_find_pcb(s, src_ip, dst_ip, &seg);
    if (!p) {
        if (seg.flags & TH_RST) {
            log_trace("tcp: RST for an unknown connection, ignoring");
            return;
        }
        log_info("tcp: no socket for %s:%u -> port %u, sending RST",
                 ip_str(src_ip, rb, sizeof rb), seg.src_port, seg.dst_port);
        tcp_send_reset(s, dst_ip, seg.dst_port, src_ip, seg.src_port, &seg);
        return;
    }

    /* ---- Step 1: RST ---- */
    if (seg.flags & TH_RST) {
        if (p->state == TCP_SYN_SENT) {
            pcb_log(p, "connection refused (RST received)");
            p->err = ECONNREFUSED;
            tcp_set_state(p, TCP_CLOSED);
            return;
        }
        if (p->state != TCP_LISTEN) {
            pcb_log(p, "reset by peer");
            p->err = ECONNRESET;
            tcp_set_state(p, TCP_CLOSED);
        }
        return;
    }

    /* ---- Step 2: passive open ---- */
    if (p->state == TCP_LISTEN) {
        if (!(seg.flags & TH_SYN)) {
            log_debug("tcp: non-SYN segment to listening port %u, sending RST",
                      seg.dst_port);
            tcp_send_reset(s, dst_ip, seg.dst_port, src_ip, seg.src_port,
                           &seg);
            return;
        }

        /*
         * A SYN on a listening port creates a child control block for the
         * incoming four-tuple.  The listener itself is left untouched, which
         * is how one accept()ing socket can serve several simultaneous
         * connections.
         */
        tcp_pcb_t *c = pcb_alloc(dst_ip, seg.dst_port);
        if (!c)
            return;

        c->rport = seg.src_port;
        c->raddr = src_ip;
        c->state = TCP_SYN_RECEIVED;
        c->flags |= TF_PASSIVE;
        c->mss_local = p->mss_local ? p->mss_local : USSTACK_MSS_DEFAULT;
        c->wscale_local = p->wscale_local;
        c->snd_una = pcb_isn();
        c->snd_nxt = c->snd_una;
        c->rcv_nxt = seg.seq + 1;         /* SYN consumes one number */
        c->snd_wnd = 0;

        negotiate_options(c, &seg);

        /* Queue on the listener, then link into the stack. */
        if (p->accept_tail)
            p->accept_tail->accept_next = c;
        else
            p->accept_head = c;
        p->accept_tail = c;
        pcb_link(s, c);

        if (tcp_output(s, c, c->snd_nxt, TH_SYN | TH_ACK, NULL, 0) < 0) {
            tcp_pcb_unlink(c);
            pcb_free(c);
            return;
        }

        pcb_log(c, "passive open accepted");
        return;
    }

    /* ---- Step 3: active open ---- */
    if (p->state == TCP_SYN_SENT) {
        if (!(seg.flags & TH_ACK)) {
            /* Simultaneous open: the peer started one at the same time. */
            if (seg.flags & TH_SYN) {
                p->rcv_nxt = seg.seq + 1;
                txq_ack(p, seg.ack, net_now(s));
                p->snd_una = seg.ack;
                negotiate_options(p, &seg);
                tcp_set_state(p, TCP_SYN_RECEIVED);
                tcp_output(s, p, p->snd_nxt, TH_SYN | TH_ACK, NULL, 0);
            }
            /* Otherwise our SYN is still outstanding: nothing to do. */
            return;
        }

        /* The ACK must cover our SYN, which is the only thing we sent. */
        if (SEQ_LEQ(seg.ack, p->snd_una) || SEQ_GT(seg.ack, p->snd_nxt)) {
            log_debug("tcp: bad ACK in SYN-SENT, sending RST");
            tcp_send_reset(s, dst_ip, seg.dst_port, src_ip, seg.src_port,
                           &seg);
            p->err = ECONNREFUSED;
            tcp_set_state(p, TCP_CLOSED);
            return;
        }

        if (seg.flags & TH_SYN)
            p->rcv_nxt = seg.seq + 1;

        negotiate_options(p, &seg);
        txq_ack(p, seg.ack, net_now(s));
        p->snd_una = seg.ack;
        p->dupack_count = 0;
        tcp_set_state(p, TCP_ESTABLISHED);
        pcb_log(p, "connection established (active open)");
        /* Fall through: the SYN-ACK may also have carried data. */
    }

    /* ---- Step 4: sequence acceptability ---- */
    uint32_t span = seg_span(&seg);
    if (!seq_acceptable(p, seg.seq, span)) {
        log_debug("tcp: segment outside the receive window "
                  "(seq=%u rcv_nxt=%u wnd=%u); sending ACK",
                  seg.seq, p->rcv_nxt, rb_avail(&p->rx_buf));
        tcp_ack_now(s, p);
        return;
    }

    /* ---- Step 5: ACK ---- */
    if (seg.flags & TH_ACK)
        tcp_process_ack(s, p, &seg);

    /* ---- Step 6: segment text (payload) ---- */
    if (seg.payload_len) {
        uint32_t seq = seg.seq;
        uint32_t len = seg.payload_len;
        const uint8_t *data = seg.payload;

        /* Trim the prefix we have already accepted. */
        if (SEQ_LT(seq, p->rcv_nxt)) {
            uint32_t skip = p->rcv_nxt - seq;
            if (skip >= len) {
                tcp_ack_now(s, p);
                if (seg.flags & TH_FIN)
                    goto fin;
                return;
            }
            data += skip;
            len -= skip;
            seq = p->rcv_nxt;
        }

        if (SEQ_GT(seq, p->rcv_nxt)) {
            /* Out of order: hold it and re-advertise what we still need. */
            ooo_insert(p, seq, data, len);
            pcb_log(p, "out-of-order seq=%u len=%u (rcv_nxt=%u)",
                    seq, len, p->rcv_nxt);
            tcp_ack_now(s, p);
            if (seg.flags & TH_FIN)
                goto fin;
            return;
        }

        /* In order: never accept more than the window can hold. */
        uint32_t room = rb_avail(&p->rx_buf);
        if (len > room) {
            log_warn("tcp: receive window exhausted, accepting %u of %u bytes",
                     room, len);
            len = room;
        }

        if (len) {
            rb_write(&p->rx_buf, data, len);
            p->rcv_nxt += len;
            p->bytes_recv += len;
        }

        /* The new data may have filled holes that queued segments wait on. */
        ooo_drain(p);

        tcp_ack_now(s, p);
        tcp_send_pending(s, p);
    }

fin:
    /* ---- Step 7: FIN ---- */
    if (seg.flags & TH_FIN) {
        uint32_t fin_seq = seg.seq + seg.payload_len;

        /* The FIN's own sequence number must be exactly where we expect it. */
        if (fin_seq != p->rcv_nxt && !seg.payload_len) {
            log_debug("tcp: FIN at %u, expected %u; acknowledging only",
                      fin_seq, p->rcv_nxt);
            tcp_ack_now(s, p);
            return;
        }

        pcb_log(p, "peer FIN at seq %u", fin_seq);
        p->rcv_nxt = fin_seq + 1;
        p->flags |= TF_GOT_FIN;
        tcp_ack_now(s, p);

        switch (p->state) {
        case TCP_ESTABLISHED:
            /* We may still have data to send, so wait for close(). */
            tcp_set_state(p, TCP_CLOSE_WAIT);
            break;

        case TCP_FIN_WAIT_1:
            /* Our FIN is outstanding: CLOSING until it too is acknowledged. */
            if (p->flags & TF_SENT_FIN)
                tcp_set_state(p, TCP_CLOSING);
            else {
                tcp_set_state(p, TCP_TIME_WAIT);
                p->timewait_deadline_ms = net_now(s) + TCP_TIME_WAIT_MS;
            }
            break;

        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
            tcp_set_state(p, TCP_TIME_WAIT);
            p->timewait_deadline_ms = net_now(s) + TCP_TIME_WAIT_MS;
            break;

        case TCP_TIME_WAIT:
            /* Duplicate FIN: restart the 2*MSL timer. */
            p->timewait_deadline_ms = net_now(s) + TCP_TIME_WAIT_MS;
            break;

        case TCP_CLOSE_WAIT:
        case TCP_LAST_ACK:
            /* A duplicate FIN for a shutdown already in progress. */
            break;

        default:
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* 8. out-of-order reassembly                                         */
/* ------------------------------------------------------------------ */

/* Is [seq, seq+len) already wholly covered by the queue? */
static bool ooo_covered(const tcp_pcb_t *p, uint32_t seq, uint32_t len)
{
    for (const tcp_ooo_t *o = p->ooo_head; o; o = o->next)
        if (SEQ_LEQ(seq, o->seq) && SEQ_GEQ(seq + len, o->seq + o->len))
            return true;
    return false;
}

static void ooo_insert(tcp_pcb_t *p, uint32_t seq, const uint8_t *data,
                       uint32_t len)
{
    if (!len || seq == p->rcv_nxt)
        return;

    if (ooo_covered(p, seq, len)) {
        log_debug("tcp: out-of-order seq=%u len=%u already covered",
                  seq, len);
        return;
    }

    tcp_ooo_t *o = (tcp_ooo_t *)calloc(1, sizeof *o);
    if (!o)
        return;

    o->data = (uint8_t *)malloc(len);
    if (!o->data) {
        free(o);
        return;
    }
    memcpy(o->data, data, len);
    o->seq = seq;
    o->len = len;

    /* Keep the queue sorted by sequence number. */
    tcp_ooo_t **pp = &p->ooo_head;
    while (*pp && SEQ_LT((*pp)->seq, seq))
        pp = &(*pp)->next;

    o->next = *pp;
    *pp = o;
}

/*
 * Move every queued segment that now begins at RCV.NXT into the receive
 * buffer.  Called after in-order data arrives, because that data may have
 * just filled the gap a queued segment was waiting behind.
 */
static void ooo_drain(tcp_pcb_t *p)
{
    tcp_ooo_t **pp = &p->ooo_head;

    while (*pp) {
        tcp_ooo_t *o = *pp;

        /* Wholly superseded: discard. */
        if (SEQ_LEQ(o->seq + o->len, p->rcv_nxt)) {
            *pp = o->next;
            free(o->data);
            free(o);
            continue;
        }

        /* Partly behind RCV.NXT: drop the bytes we already have. */
        if (SEQ_LT(o->seq, p->rcv_nxt)) {
            uint32_t skip = p->rcv_nxt - o->seq;
            memmove(o->data, o->data + skip, o->len - skip);
            o->seq += skip;
            o->len -= skip;
        }

        if (o->seq == p->rcv_nxt) {
            uint32_t room = rb_avail(&p->rx_buf);
            uint32_t take = MIN(o->len, room);
            if (!take)
                return;                     /* window full; wait for the app */

            rb_write(&p->rx_buf, o->data, take);
            p->rcv_nxt += take;
            p->bytes_recv += take;

            if (take == o->len) {
                *pp = o->next;
                free(o->data);
                free(o);
                continue;
            }

            /* The window filled part-way through: keep the remainder queued. */
            memmove(o->data, o->data + take, o->len - take);
            o->seq += take;
            o->len -= take;
            return;
        }

        pp = &o->next;
    }
}

/* ------------------------------------------------------------------ */
/* 9. timers                                                          */
/* ------------------------------------------------------------------ */

/*
 * Re-send a queued segment.  This deliberately goes through tcp_transmit
 * rather than tcp_output: the segment is already in the queue, and enqueueing
 * a second copy would double-count the bytes in flight and make the queue
 * grow without bound.
 */
static void retransmit_segment(netstack_t *s, tcp_pcb_t *p, tcp_txseg_t *t,
                               uint64_t now)
{
    uint8_t payload[USSTACK_MTU_DEFAULT];

    if (t->len)
        rb_read(&p->tx_buf, t->off, payload, t->len);

    if (tcp_transmit(s, p, t->seq, TH_ACK | t->flags, payload, t->len) < 0)
        return;

    p->segs_retrans++;
    p->bytes_retrans += t->len;
    t->sent_ms = now;

    /* RFC 6298 backoff: double, clamped to the maximum. */
    t->rto_ms = MIN(t->rto_ms * 2, (uint64_t)TCP_RTO_MAX_MS);
    t->rtx_count++;

    pcb_log(p, "retransmit seq=%u len=%u (attempt %u, rto=%llu ms)",
            t->seq, t->len, t->rtx_count + 1, (unsigned long long)t->rto_ms);
}

void tcp_timer_tick(void *stack_v, uint64_t now)
{
    netstack_t *s = (netstack_t *)stack_v;

    for (tcp_pcb_t *p = s->pcbs; p; ) {
        tcp_pcb_t *cur = p;
        p = p->next;

        switch (cur->state) {

        case TCP_ESTABLISHED:
        case TCP_CLOSE_WAIT:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:

            /* -- retransmission timeout -- */
            if (cur->retransmit_deadline_ms &&
                now >= cur->retransmit_deadline_ms) {
                if (cur->snd_wnd == 0 && cur->txq_head) {
                    /*
                     * The peer has closed its window.  That is flow control,
                     * not congestion, so the timer must NOT treat it as loss:
                     * back off and let the persist timer probe instead.
                     */
                    cur->retransmit_deadline_ms = now + cur->rto_ms;
                    if (!cur->persist_deadline_ms)
                        cur->persist_deadline_ms = now + cur->rto_ms;
                } else if (cur->txq_head) {
                    tcp_txseg_t *t = cur->txq_head;

                    if (t->rtx_count >= TCP_MAX_RETRANSMITS) {
                        pcb_log(cur, "giving up after %u retransmissions",
                                t->rtx_count + 1);
                        tcp_send_reset(s, cur->laddr, cur->rport, cur->raddr,
                                       cur->lport, NULL);
                        cur->err = ETIMEDOUT;
                        tcp_set_state(cur, TCP_CLOSED);
                        break;
                    }

                    pcb_log(cur, "retransmission timeout (rto=%llu ms)",
                            (unsigned long long)t->rto_ms);
                    retransmit_segment(s, cur, t, now);
                    cur->dupack_count = 0;
                    cur->recover = 0;
                    cur->flags &= ~TF_FAST_RETRANS;
                    cur->retransmit_deadline_ms = now + t->rto_ms;
                } else {
                    cur->retransmit_deadline_ms = 0;
                }
            }

            /* -- zero-window persist -- */
            if (cur->persist_deadline_ms && now >= cur->persist_deadline_ms) {
                cur->persist_deadline_ms = now + cur->rto_ms;

                if (cur->snd_wnd == 0) {
                    /*
                     * Probe with a segment so the peer's reply reveals
                     * whether the window reopened.  A zero-length segment
                     * would elicit no useful information, so send one byte
                     * when we have one.
                     */
                    uint32_t buffered_end =
                        cur->tx_base_seq + rb_used(&cur->tx_buf);
                    uint32_t unsent = SEQ_GT(buffered_end, cur->snd_nxt)
                                    ? buffered_end - cur->snd_nxt : 0;

                    if (unsent) {
                        uint8_t payload[1];
                        rb_read(&cur->tx_buf, cur->snd_nxt - cur->tx_base_seq,
                                payload, 1);
                        tcp_output(s, cur, cur->snd_nxt, TH_ACK | TH_PSH,
                                   payload, 1);
                    } else {
                        tcp_output(s, cur, cur->snd_nxt, TH_ACK, NULL, 0);
                    }
                    pcb_log(cur, "zero-window probe");
                }
            }

            /* -- arm the retransmission timer if it somehow went idle -- */
            if (cur->txq_head && !cur->retransmit_deadline_ms)
                cur->retransmit_deadline_ms = now + cur->txq_head->rto_ms;

            tcp_send_pending(s, cur);
            break;

        case TCP_TIME_WAIT:
            if (cur->timewait_deadline_ms && now >= cur->timewait_deadline_ms) {
                pcb_log(cur, "TIME-WAIT expired");
                tcp_set_state(cur, TCP_CLOSED);
            }
            break;

        case TCP_LISTEN:
        case TCP_CLOSED:
        default:
            break;
        }
    }
}

int tcp_next_timeout_ms(void *stack_v)
{
    netstack_t *s = (netstack_t *)stack_v;
    uint64_t now = s->now_ms ? s->now_ms : mono_ms();
    int64_t  best = 60000;

    for (tcp_pcb_t *p = s->pcbs; p; p = p->next) {
        uint64_t deadlines[3];
        deadlines[0] = p->retransmit_deadline_ms;
        deadlines[1] = p->persist_deadline_ms;
        deadlines[2] = p->timewait_deadline_ms;

        for (int i = 0; i < 3; i++) {
            if (!deadlines[i])
                continue;
            int64_t delta = (int64_t)deadlines[i] - (int64_t)now;
            if (delta < best)
                best = delta;
        }
    }

    if (best < 0)
        best = 0;
    if (best > 60000)
        best = 60000;
    return (int)best;
}

/* ------------------------------------------------------------------ */
/* 10. application API                                                */
/* ------------------------------------------------------------------ */

tcp_pcb_t *tcp_new(struct netstack *s_v, uint16_t lport)
{
    netstack_t *s = (netstack_t *)s_v;

    tcp_pcb_t *p = pcb_alloc(s->laddr, lport);
    if (!p)
        return NULL;

    p->mss_local = (uint16_t)(s->mtu - IP_HDR_MIN_LEN - TCP_HDR_MIN_LEN);
    p->wscale_local = 7;      /* offer scaling: 64 KiB << 7 = 8 MiB */
    pcb_link(s, p);
    return p;
}

int tcp_bind(tcp_pcb_t *p, uint16_t lport)
{
    if (!p || p->state != TCP_CLOSED)
        return -EINVAL;
    if (lport == 0)
        return 0;

    netstack_t *s = stack_of(p);
    if (port_in_use(s, p->laddr, lport, p))
        return -EADDRINUSE;

    p->lport = lport;
    return 0;
}

int tcp_listen(tcp_pcb_t *p)
{
    if (!p)
        return -EINVAL;
    if (p->state != TCP_CLOSED)
        return -EISCONN;
    if (p->lport == 0)
        return -EADDRNOTAVAIL;

    netstack_t *s = stack_of(p);
    if (port_in_use(s, p->laddr, p->lport, p))
        return -EADDRINUSE;

    tcp_set_state(p, TCP_LISTEN);
    log_info("tcp: listening on port %u", p->lport);
    return 0;
}

tcp_pcb_t *tcp_connect(struct netstack *s_v, uint32_t raddr, uint16_t rport)
{
    netstack_t *s = (netstack_t *)s_v;

    if (rport == 0)
        return NULL;

    tcp_pcb_t *p = pcb_alloc(s->laddr, 0);
    if (!p)
        return NULL;

    p->raddr = raddr;
    p->rport = rport;
    p->mss_remote = USSTACK_MSS_DEFAULT;
    p->wscale_local = 7;
    p->snd_una = pcb_isn();
    p->snd_nxt = p->snd_una;
    p->rcv_nxt = 0;
    p->snd_wnd = 0;
    pcb_link(s, p);

    tcp_set_state(p, TCP_SYN_SENT);

    /* The SYN carries the options and consumes one sequence number. */
    if (tcp_output(s, p, p->snd_nxt, TH_SYN, NULL, 0) < 0) {
        tcp_pcb_unlink(p);
        pcb_free(p);
        return NULL;
    }

    return p;
}

tcp_pcb_t *tcp_accept(tcp_pcb_t *listener)
{
    if (!listener || listener->state != TCP_LISTEN)
        return NULL;

    /*
     * Hand back the oldest connection that has finished its handshake.  A
     * child still in SYN-RECEIVED stays queued: the application has not
     * committed to it yet.
     */
    tcp_pcb_t **pp = &listener->accept_head;
    tcp_pcb_t *prev = NULL;

    while (*pp) {
        tcp_pcb_t *c = *pp;

        if (c->state == TCP_ESTABLISHED) {
            if (prev)
                prev->accept_next = c->accept_next;
            else
                listener->accept_head = c->accept_next;
            if (listener->accept_tail == c)
                listener->accept_tail = prev;

            c->accept_next = NULL;
            return c;
        }
        prev = c;
        pp = &c->accept_next;
    }

    return NULL;
}

void tcp_close(tcp_pcb_t *p)
{
    if (!p)
        return;

    switch (p->state) {
    case TCP_ESTABLISHED:
        /* Ask for a FIN; it leaves once the send queue has drained. */
        p->flags |= TF_NEED_FIN;
        tcp_send_pending(stack_of(p), p);
        break;

    case TCP_CLOSE_WAIT:
        p->flags |= TF_NEED_FIN;
        tcp_send_pending(stack_of(p), p);
        break;

    case TCP_LISTEN:
    case TCP_SYN_RECEIVED:
    case TCP_SYN_SENT:
    case TCP_CLOSED:
        /* Nothing established to shut down gracefully. */
        tcp_set_state(p, TCP_CLOSED);
        break;

    default:
        /* Already shutting down; wait for the peer. */
        break;
    }
}

int tcp_send(tcp_pcb_t *p, const void *data, size_t len)
{
    if (!p || !data)
        return -EINVAL;
    if (len > (size_t)INT32_MAX)
        return -EINVAL;

    if (p->state == TCP_CLOSED || p->state == TCP_TIME_WAIT)
        return -EPIPE;
    if (p->err == ECONNRESET)
        return -ECONNRESET;
    if (p->state != TCP_ESTABLISHED && p->state != TCP_CLOSE_WAIT)
        return -ENOTCONN;

    if (len > rb_avail(&p->tx_buf))
        return -EWOULDBLOCK;     /* the caller retries once space frees up */

    if (!rb_write(&p->tx_buf, data, (uint32_t)len))
        return -EWOULDBLOCK;

    tcp_send_pending(stack_of(p), p);
    return (int)len;
}

int tcp_recv(tcp_pcb_t *p, void *buf, size_t len)
{
    if (!p || !buf)
        return -EINVAL;

    uint32_t avail = rb_used(&p->rx_buf);
    uint32_t take = (uint32_t)MIN((size_t)avail, len);

    if (take) {
        rb_read(&p->rx_buf, 0, buf, take);
        rb_consume(&p->rx_buf, take);
    }

    /*
     * Reading frees receive-buffer space, which widens the window.  Tell the
     * peer straight away -- a window update is not worth delaying here,
     * because until it arrives we cannot receive anything else.
     */
    if (take && (p->state == TCP_ESTABLISHED || p->state == TCP_CLOSE_WAIT))
        tcp_ack_now(stack_of(p), p);

    if (!avail && (p->flags & TF_GOT_FIN))
        return 0;                /* orderly shutdown: end of stream */

    if (p->state == TCP_CLOSED && p->err && !avail)
        return p->err;

    return (int)take;
}

size_t tcp_send_space(const tcp_pcb_t *p)
{
    if (!p || p->state == TCP_CLOSED)
        return 0;
    return rb_avail(&p->tx_buf);
}

size_t tcp_recv_avail(const tcp_pcb_t *p)
{
    return p ? rb_used(&p->rx_buf) : 0;
}