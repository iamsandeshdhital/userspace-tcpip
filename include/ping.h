/*
 * ping.h -- ICMP echo client built on top of the stack.
 *
 * The replies are matched by (id, seq) against a small table of in-flight
 * requests, which is the minimum needed to report loss and RTT variation
 * rather than just the first answer.
 */
#ifndef USSTACK_PING_H
#define USSTACK_PING_H

#include "common.h"
#include "net.h"

#define PING_MAX_INFLIGHT 8

typedef struct {
    bool     sent;
    uint64_t sent_ms;
    uint16_t seq;
} ping_slot_t;

typedef struct {
    uint16_t   id;
    uint16_t   next_seq;
    uint32_t   peer;
    uint8_t    ttl;
    size_t     size;         /* payload size requested */

    ping_slot_t slots[PING_MAX_INFLIGHT];

    uint32_t   sent;
    uint32_t   received;
    uint64_t   rtt_min, rtt_max, rtt_sum;
    uint16_t   last_seq;
    uint64_t   last_rtt_ms;
    uint32_t   dup_replies;
    bool       idle;
} ping_ctx_t;

/* Start pinging `peer`.  `size` is the payload size in bytes. */
void ping_start(netstack_t *s, ping_ctx_t *ctx, uint32_t peer,
                size_t size, uint8_t ttl);

/* Returns true if a request was actually sent (false if all slots are busy). */
bool ping_tick(netstack_t *s, ping_ctx_t *ctx);

/* Print the summary.  `lost` is the number of requests that never came back. */
void ping_report(const ping_ctx_t *ctx, uint32_t lost);

/* Called by the ICMP layer when an echo reply is received. */
void ping_on_reply(netstack_t *s, ping_ctx_t *ctx,
                   uint16_t id, uint16_t seq, size_t reply_len);

#endif /* USSTACK_PING_H */