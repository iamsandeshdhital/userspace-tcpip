/*
 * test_ringbuf.c -- the byte ring that backs both TCP buffers.
 *
 * The send buffer's defining property is that data is only removed from the
 * front on acknowledgement, so these tests concentrate on wrap-around reads
 * and partial consumption, which is where the arithmetic usually goes wrong.
 */
#include "harness.h"
#include "ringbuf.h"

static void fill(uint8_t *dst, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = (uint8_t)(start + i);
}

static int check_prefix(const uint8_t *got, size_t n, uint8_t start)
{
    for (size_t i = 0; i < n; i++) {
        if (got[i] != (uint8_t)(start + i))
            return -1;
    }
    return 0;
}

void test_ringbuf(void)
{
    ringbuf_t rb;
    CHECK(rb_init(&rb, 16));
    CHECK_EQ_INT(rb.cap, 16);
    CHECK_EQ_INT(rb_used(&rb), 0);
    CHECK_EQ_INT(rb_avail(&rb), 16);

    uint8_t out[32];

    /* Simple sequential write and read. */
    {
        uint8_t in[8];
        fill(in, sizeof in, 0);
        CHECK(rb_write(&rb, in, 8));
        CHECK_EQ_INT(rb_used(&rb), 8);
        CHECK_EQ_INT(rb_avail(&rb), 8);

        memset(out, 0, sizeof out);
        rb_read(&rb, 0, out, 8);
        CHECK_EQ_INT(check_prefix(out, 8, 0), 0);
    }

    /* Overwrite after consuming: the storage wraps. */
    rb_consume(&rb, 8);
    CHECK_EQ_INT(rb_used(&rb), 0);
    CHECK_EQ_INT(rb_avail(&rb), 16);

    {
        uint8_t in[12];
        fill(in, sizeof in, 100);
        CHECK(rb_write(&rb, in, 12));
        CHECK_EQ_INT(rb_used(&rb), 12);

        /* Consume 6, then write 10 so the data straddles the ring end. */
        rb_consume(&rb, 6);
        CHECK_EQ_INT(rb_used(&rb), 6);

        uint8_t in2[10];
        fill(in2, sizeof in2, 200);
        CHECK(rb_write(&rb, in2, 10));
        CHECK_EQ_INT(rb_used(&rb), 16);
        CHECK_EQ_INT(rb_avail(&rb), 0);

        /* Logical offset 0 is still byte 106, and the tail must read back
         * across the wrap. */
        memset(out, 0, sizeof out);
        rb_read(&rb, 0, out, 16);
        CHECK_EQ_INT(check_prefix(out, 6, 106), 0);
        CHECK_EQ_INT(check_prefix(out + 6, 10, 200), 0);
    }

    /* A write larger than the free space must be refused, not truncated. */
    {
        uint8_t in[9];
        fill(in, sizeof in, 0);
        CHECK(!rb_write(&rb, in, 9));
        CHECK_EQ_INT(rb_used(&rb), 16);
    }

    /* Reading an arbitrary offset is how retransmission works: the bytes for
     * an unacknowledged segment must still be addressable by offset. */
    {
        memset(out, 0, sizeof out);
        rb_read(&rb, 3, out, 5);
        CHECK_EQ_INT(check_prefix(out, 5, 109), 0);
    }

    /* Consuming everything resets the ring. */
    rb_consume(&rb, 16);
    CHECK_EQ_INT(rb_used(&rb), 0);
    CHECK_EQ_INT(rb_avail(&rb), 16);

    {
        uint8_t in[16];
        fill(in, sizeof in, 50);
        CHECK(rb_write(&rb, in, 16));
        memset(out, 0, sizeof out);
        rb_read(&rb, 0, out, 16);
        CHECK_EQ_INT(check_prefix(out, 16, 50), 0);
    }

    /* Consuming more than present clamps instead of underflowing. */
    rb_consume(&rb, 100);
    CHECK_EQ_INT(rb_used(&rb), 0);

    /* Consuming everything when partly empty, then refilling, must still
     * produce the correct logical order. */
    {
        uint8_t in[5];
        fill(in, sizeof in, 70);
        CHECK(rb_write(&rb, in, 5));
        rb_consume(&rb, 3);
        CHECK_EQ_INT(rb_used(&rb), 2);

        uint8_t in2[9];
        fill(in2, sizeof in2, 90);
        CHECK(rb_write(&rb, in2, 9));

        memset(out, 0, sizeof out);
        rb_read(&rb, 0, out, 11);
        CHECK_EQ_INT(check_prefix(out, 2, 73), 0);
        CHECK_EQ_INT(check_prefix(out + 2, 9, 90), 0);
    }

    rb_free(&rb);
    CHECK_EQ_INT(rb.data == NULL, 1);
}