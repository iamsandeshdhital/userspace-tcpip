#include "ringbuf.h"

bool rb_init(ringbuf_t *rb, uint32_t cap)
{
    memset(rb, 0, sizeof *rb);
    rb->data = (uint8_t *)calloc(1, cap);
    if (!rb->data)
        return false;
    rb->cap = cap;
    return true;
}

void rb_free(ringbuf_t *rb)
{
    free(rb->data);
    memset(rb, 0, sizeof *rb);
}

void rb_reset(ringbuf_t *rb)
{
    rb->head = 0;
    rb->len  = 0;
}

bool rb_write(ringbuf_t *rb, const void *src, uint32_t len)
{
    if (len > rb_avail(rb))
        return false;

    const uint8_t *s = (const uint8_t *)src;

    /*
     * The write may wrap.  Splitting at the ring boundary rather than copying
     * byte-by-byte keeps this at two memcpys in the worst case.
     */
    uint32_t first = rb->cap - rb->head;      /* room before the end of storage */
    if (first > len)
        first = len;

    memcpy(rb->data + rb->head, s, first);
    if (len > first)
        memcpy(rb->data, s + first, len - first);

    rb->head = (rb->head + len) % rb->cap;
    rb->len += len;
    return true;
}

void rb_read(const ringbuf_t *rb, uint32_t off, void *dst, uint32_t len)
{
    if (off + len > rb->len) {
        len = (off < rb->len) ? rb->len - off : 0;
    }
    if (!len || !dst)
        return;

    uint8_t *d = (uint8_t *)dst;
    uint32_t start = (rb->head + rb->cap - rb->len + off) % rb->cap;
    uint32_t first = rb->cap - start;
    if (first > len)
        first = len;

    memcpy(d, rb->data + start, first);
    if (len > first)
        memcpy(d + first, rb->data, len - first);
}

void rb_consume(ringbuf_t *rb, uint32_t len)
{
    if (len > rb->len)
        len = rb->len;

    rb->len -= len;
    /* head stays put; the freed space is reclaimed by wrapping the start. */
    if (rb->len == 0)
        rb->head = 0;
}