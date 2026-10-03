/*
 * ringbuf.h -- byte ring used for TCP send/receive buffers.
 *
 * The receive buffer is the advertised window: whatever is free is what we
 * promise to accept.  The send buffer holds unacknowledged bytes, and it is
 * only truncated from the front once the peer acknowledges them.
 *
 * That property is what lets the retransmission queue store plain *offsets*
 * into this ring instead of copying payload: a queued range stays valid until
 * it is acknowledged, and acknowledgement is exactly when we drop it.
 */
#ifndef USSTACK_RINGBUF_H
#define USSTACK_RINGBUF_H

#include "common.h"

typedef struct {
    uint8_t *data;
    uint32_t cap;    /* capacity in bytes */
    uint32_t head;   /* write offset */
    uint32_t len;    /* number of valid bytes */
} ringbuf_t;

bool    rb_init(ringbuf_t *rb, uint32_t cap);
void    rb_free(ringbuf_t *rb);
void    rb_reset(ringbuf_t *rb);

static inline uint32_t rb_used(const ringbuf_t *rb) { return rb->len; }
static inline uint32_t rb_avail(const ringbuf_t *rb) { return rb->cap - rb->len; }

/* Copy `len` bytes in.  Returns false if there is not enough room. */
bool rb_write(ringbuf_t *rb, const void *src, uint32_t len);

/* Copy `len` bytes out starting at logical offset `off`.  Caller guarantees
 * off + len <= rb_used(). */
void rb_read(const ringbuf_t *rb, uint32_t off, void *dst, uint32_t len);

/* Drop `len` bytes from the front. */
void rb_consume(ringbuf_t *rb, uint32_t len);

#endif /* USSTACK_RINGBUF_H */