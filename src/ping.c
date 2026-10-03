/*
 * ping.c -- ICMP echo requests.
 */
#include "ping.h"
#include "ip.h"
#include "icmp.h"
#include "log.h"
#include "clock.h"

#include <stdio.h>
#include <unistd.h>

void ping_start(netstack_t *s, ping_ctx_t *ctx, uint32_t peer,
                size_t size, uint8_t ttl)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->peer = peer;
    ctx->ttl = ttl ? ttl : USSTACK_TTL_DEFAULT;
    ctx->id = (uint16_t)(getpid() & 0xFFFF);

    /*
     * The whole ICMP message must fit the MTU: 20 bytes of IP header, 8 of
     * echo header, and whatever payload is left.
     */
    size_t max_payload = s->mtu - IP_HDR_MIN_LEN - ICMP_HDR_LEN - 4;
    if (size > max_payload) {
        size = max_payload;
        log_warn("ping: payload limited to %zu bytes by the %u-byte MTU",
                 size, s->mtu);
    }
    ctx->size = size;

    ctx->rtt_min = UINT64_MAX;
}

bool ping_tick(netstack_t *s, ping_ctx_t *ctx)
{
    /* Find a free slot. */
    size_t idx = PING_MAX_INFLIGHT;
    for (size_t i = 0; i < PING_MAX_INFLIGHT; i++) {
        if (!ctx->slots[i].sent) {
            idx = i;
            break;
        }
    }
    if (idx == PING_MAX_INFLIGHT)
        return false;                 /* every slot is still outstanding */

    size_t body = ICMP_HDR_LEN + 4 + ctx->size;
    uint8_t buf[USSTACK_MTU_DEFAULT];
    ip_hdr_t *iph = (ip_hdr_t *)buf;
    icmp_echo_t *echo = (icmp_echo_t *)(buf + IP_HDR_MIN_LEN);

    ip_build(iph, s->laddr, ctx->peer, IP_PROTO_ICMP, s->ip_id++,
             (uint16_t)body, ctx->ttl);

    echo->type = ICMP_ECHO;
    echo->code = 0;
    echo->id   = htons(ctx->id);
    echo->seq  = htons(ctx->next_seq);

    /*
     * Standard payload: eight bytes of timestamp derived from the clock, so a
     * reply's payload can be sanity-checked against the request even when the
     * stack's own timing is unavailable.
     */
    uint8_t *payload = buf + IP_HDR_MIN_LEN + ICMP_HDR_LEN + 4;
    uint64_t now = mono_ms();
    uint32_t t0 = (uint32_t)now;
    uint32_t t1 = (uint32_t)(now >> 32);
    wr32_be(payload + 0, t0);
    wr32_be(payload + 4, t1);
    for (size_t i = 8; i < ctx->size; i++)
        payload[i] = (uint8_t)(i & 0xFF);

    icmp_finalize(echo, body);
    ip_finalize(iph, (uint16_t)body);

    ctx->slots[idx].sent = true;
    ctx->slots[idx].sent_ms = now;
    ctx->slots[idx].seq = ctx->next_seq++;
    ctx->sent++;
    ctx->last_seq = ctx->slots[idx].seq;

    ip_send(s, buf, IP_HDR_MIN_LEN + body);

    char ipb[INET_ADDRSTRLEN];
    log_debug("ping: echo request seq=%u to %s", ctx->last_seq,
              ip_str(ctx->peer, ipb, sizeof ipb));
    return true;
}

/*
 * Called from the ICMP layer when a reply arrives.
 */
void ping_on_reply(netstack_t *s, ping_ctx_t *ctx,
                   uint16_t id, uint16_t seq, size_t reply_len)
{
    char ipb[INET_ADDRSTRLEN];

    if (id != ctx->id) {
        log_debug("ping: reply id=%u is not ours (%u)", id, ctx->id);
        return;
    }

    for (size_t i = 0; i < PING_MAX_INFLIGHT; i++) {
        if (!ctx->slots[i].sent || ctx->slots[i].seq != seq)
            continue;

        uint64_t now = mono_ms();
        uint64_t rtt = now - ctx->slots[i].sent_ms;

        ctx->slots[i].sent = false;
        ctx->received++;
        ctx->last_rtt_ms = rtt;
        ctx->rtt_sum += rtt;
        if (rtt < ctx->rtt_min) ctx->rtt_min = rtt;
        if (rtt > ctx->rtt_max) ctx->rtt_max = rtt;
        ctx->idle = false;

        log_info("ping: reply from %s seq=%u time=%.3f ms (%zu bytes)",
                 ip_str(ctx->peer, ipb, sizeof ipb), seq,
                 (double)rtt / 1000.0, reply_len);
        return;
    }

    ctx->dup_replies++;
    log_debug("ping: no outstanding request with seq=%u (duplicate?)", seq);
}

void ping_report(const ping_ctx_t *ctx, uint32_t lost)
{
    char ipb[INET_ADDRSTRLEN];
    uint32_t total = ctx->sent + lost;

    printf("\n--- ping statistics for %s ---\n",
           ip_str(ctx->peer, ipb, sizeof ipb));
    printf("%u transmitted, %u received, %.1f%% loss\n",
           total, ctx->received,
           total ? (100.0 * lost / total) : 0.0);

    if (ctx->received) {
        double avg = (double)ctx->rtt_sum / ctx->received;
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
               (double)ctx->rtt_min / 1000.0, avg / 1000.0,
               (double)ctx->rtt_max / 1000.0);
    }
    if (ctx->dup_replies)
        printf("%u duplicate replies ignored\n", ctx->dup_replies);
    fflush(stdout);
}