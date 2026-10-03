/*
 * test_checksum.c -- the Internet checksum (RFC 1071).
 *
 * Checksums are where hand-written stacks fail most often, so these tests use
 * the worked example from RFC 1071 as a fixed reference point rather than
 * only checking the implementation against itself.
 */
#include "harness.h"
#include "checksum.h"

void test_checksum(void)
{
    /* RFC 1071 section 3 worked example: the checksum of
     * 00 01 f2 03 f4 f5 f6 f7 is 0x220d. */
    static const uint8_t rfc1071[] = { 0x00, 0x01, 0xf2, 0x03,
                                       0xf4, 0xf5, 0xf6, 0xf7 };
    CHECK_EQ_HEX(csum16(rfc1071, sizeof rfc1071), 0x220d);

    /* A checksum of zero must go out as 0xffff, since 0 means "absent". */
    {
        static const uint8_t zeros[] = { 0x00, 0x00 };
        CHECK_EQ_HEX(csum16(zeros, sizeof zeros), 0xffff);
    }

    /* An all-ones buffer also sums to zero. */
    {
        static const uint8_t ones[] = { 0xff, 0xff, 0xff, 0xff };
        CHECK_EQ_HEX(csum16(ones, sizeof ones), 0xffff);
    }

    /* Odd lengths: the trailing byte is padded on the right with zero. */
    {
        static const uint8_t odd3[] = { 0x01, 0x02, 0x03 };
        /* 0x0102 + 0x0300 = 0x0402, complement = 0xfbfd */
        CHECK_EQ_HEX(csum16(odd3, sizeof odd3), 0xfbfd);

        static const uint8_t odd5[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        /* 0x0102 + 0x0304 + 0x0500 = 0x0906, complement = 0xf6f9 */
        CHECK_EQ_HEX(csum16(odd5, sizeof odd5), 0xf6f9);
    }

    /* Incremental accumulation must equal the one-shot result, including
     * across odd-sized chunks.  This is exactly the pseudo-header case in
     * TCP, where the pseudo-header and the segment are summed separately. */
    {
        uint8_t buf[37];
        for (size_t i = 0; i < sizeof buf; i++)
            buf[i] = (uint8_t)(i * 7 + 1);

        uint16_t whole = csum16(buf, sizeof buf);

        csum_state_t st;
        csum_init(&st);
        csum_add(&st, buf, 3);      /* odd chunk */
        csum_add(&st, buf + 3, 12); /* even chunk */
        csum_add(&st, buf + 15, 1); /* odd chunk */
        csum_add(&st, buf + 16, sizeof buf - 16);
        CHECK_EQ_HEX(csum_final(&st), whole);

        /* Different chunking must give the same answer. */
        csum_init(&st);
        csum_add(&st, buf, 1);
        csum_add(&st, buf + 1, 36);
        CHECK_EQ_HEX(csum_final(&st), whole);
    }

    /* Verification: placing the checksum in the buffer must make the sum
     * fold to 0xffff, which is what csum16_verify checks for. */
    {
        uint8_t buf[20];
        for (size_t i = 0; i < sizeof buf; i++)
            buf[i] = (uint8_t)(0xA0 + i);

        uint16_t c = csum16(buf, sizeof buf);
        CHECK(!csum16_verify(buf, sizeof buf, 18));

        wr16_be(buf + 18, c);
        CHECK(csum16_verify(buf, sizeof buf, 18));

        /* Flipping one bit must break verification. */
        buf[5] ^= 0x01;
        CHECK(!csum16_verify(buf, sizeof buf, 18));
    }

    /* Verification of an odd-length buffer. */
    {
        uint8_t buf[21];
        memset(buf, 0x5A, sizeof buf);
        wr16_be(buf + 18, csum16(buf, sizeof buf));
        CHECK(csum16_verify(buf, sizeof buf, 18));
    }

    /* Carries must fold correctly: many words of 0xffff overflow 16 bits. */
    {
        uint8_t buf[64];
        memset(buf, 0xff, sizeof buf);
        CHECK_EQ_HEX(csum16(buf, sizeof buf), 0xffff);
    }
}