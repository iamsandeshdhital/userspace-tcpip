/*
 * test_ip.c -- IPv4 header construction and validation.
 */
#include "harness.h"
#include "ip.h"
#include "checksum.h"

/* Recompute just the header checksum, leaving total_len alone. */
static void fixsum(uint8_t *buf, size_t hdr_len)
{
    wr16_be(buf + 10, 0);
    wr16_be(buf + 10, csum16(buf, hdr_len));
}

void test_ip(void)
{
    uint8_t buf[128];
    uint32_t src, dst;

    inet_pton(AF_INET, "192.168.1.1", &src);
    inet_pton(AF_INET, "192.168.1.2", &dst);

    /* ---- build and validate ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 0x1234, 0, 64);

        CHECK_EQ_INT(ip_version(h), 4);
        CHECK_EQ_INT(ip_ihl(h), 5);
        CHECK_EQ_INT(ip_hdr_bytes(h), 20);
        CHECK_EQ_INT(rd16_be(buf + 4), 0x1234);   /* id */
        CHECK_EQ_INT(rd16_be(buf + 6), IP_DF);    /* Don't Fragment */
        CHECK_EQ_INT(buf[8], 64);                 /* ttl */
        CHECK_EQ_INT(buf[9], IP_PROTO_TCP);
        CHECK_EQ_HEX(h->src_ip, src);
        CHECK_EQ_HEX(h->dst_ip, dst);

        ip_finalize(h, 0);
        CHECK_EQ_INT(rd16_be(buf + 2), 20);        /* total_len */
        CHECK(csum16_verify(buf, 20, 10));
        CHECK(ip_validate(buf, 20) == IP_OK);
    }

    /* ---- with a payload ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_UDP, 7, 0, 64);
        memset(buf + 20, 0xAB, 40);
        ip_finalize(h, 40);

        CHECK_EQ_INT(rd16_be(buf + 2), 60);
        CHECK(csum16_verify(buf, 20, 10));
        CHECK(ip_validate(buf, 60) == IP_OK);
        /* A buffer larger than the datagram is fine: total_len governs. */
        CHECK(ip_validate(buf, 128) == IP_OK);
    }

    /* ---- truncated below the minimum header ---- */
    CHECK(ip_validate(buf, 10) == IP_ERR_SHORT);
    CHECK(ip_validate(buf, 19) == IP_ERR_SHORT);

    /* ---- corrupted checksum ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 1, 0, 64);
        ip_finalize(h, 8);
        CHECK(ip_validate(buf, 28) == IP_OK);

        buf[10] ^= 0x01;                 /* perturb the stored checksum */
        CHECK(ip_validate(buf, 28) == IP_ERR_CHECKSUM);
        buf[10] ^= 0x01;

        /* A perturbed header field must also be caught. */
        buf[8] = 63;                     /* ttl 64 -> 63 */
        CHECK(ip_validate(buf, 28) == IP_ERR_CHECKSUM);
    }

    /* ---- wrong version ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 1, 0, 64);
        buf[0] = 0x65;                   /* version 6 */
        fixsum(buf, 20);
        CHECK(ip_validate(buf, 20) == IP_ERR_VERSION);
    }

    /* ---- invalid IHL ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 1, 0, 64);
        buf[0] = 0x44;                   /* IHL = 4 words = 16 bytes: too small */
        fixsum(buf, 16);
        CHECK(ip_validate(buf, 64) == IP_ERR_IHL);

        /* IHL larger than the buffer must also be rejected. */
        buf[0] = 0x4F;                   /* 60 bytes of header, buffer is 128 */
        fixsum(buf, 60);
        CHECK(ip_validate(buf, 40) == IP_ERR_IHL);
    }

    /* ---- inconsistent total_length ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 1, 0, 64);
        ip_finalize(h, 8);

        wr16_be(buf + 2, 10);            /* total_len smaller than the header */
        fixsum(buf, 20);
        CHECK(ip_validate(buf, 28) == IP_ERR_LENGTH);

        wr16_be(buf + 2, 200);           /* total_len beyond the buffer */
        fixsum(buf, 20);
        CHECK(ip_validate(buf, 28) == IP_ERR_LENGTH);
    }

    /* ---- fragments are refused, since reassembly is not implemented ---- */
    {
        ip_hdr_t *h = (ip_hdr_t *)buf;
        memset(buf, 0, sizeof buf);
        ip_build(h, src, dst, IP_PROTO_TCP, 1, 0, 64);
        wr16_be(buf + 6, IP_MF);         /* more fragments follow */
        ip_finalize(h, 8);
        CHECK(ip_validate(buf, 28) == IP_ERR_FRAGMENT);

        wr16_be(buf + 6, 100);           /* non-zero fragment offset */
        fixsum(buf, 20);
        CHECK(ip_validate(buf, 28) == IP_ERR_FRAGMENT);

        /* DF alone is perfectly legal. */
        wr16_be(buf + 6, IP_DF);
        fixsum(buf, 20);
        CHECK(ip_validate(buf, 28) == IP_OK);
    }

    /* ---- destination address classification ---- */
    {
        uint32_t mask, ours, other, bcast, expected;
        inet_pton(AF_INET, "255.255.255.0", &mask);
        inet_pton(AF_INET, "10.0.0.1", &ours);
        inet_pton(AF_INET, "10.0.0.2", &other);
        inet_pton(AF_INET, "10.0.0.255", &expected);

        bcast = ip_broadcast(ours, mask);
        CHECK_EQ_HEX(bcast, expected);

        CHECK_EQ_HEX(ip_dst_is_local(ours, ours, mask), ours);
        CHECK_EQ_HEX(ip_dst_is_local(other, ours, mask), 0);
        CHECK_EQ_HEX(ip_dst_is_local(0xFFFFFFFFu, ours, mask), ours);
        CHECK_EQ_HEX(ip_dst_is_local(bcast, ours, mask), ours);
    }
}