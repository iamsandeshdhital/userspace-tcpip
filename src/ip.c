/*
 * ip.c -- IPv4 header construction and validation.
 */
#include "ip.h"
#include "checksum.h"
#include "log.h"

#include <stdio.h>

ip_parse_status_t ip_validate(const void *buf, size_t buf_len)
{
    const ip_hdr_t *h = (const ip_hdr_t *)buf;

    if (buf_len < IP_HDR_MIN_LEN)
        return IP_ERR_SHORT;

    if (ip_version(h) != 4)
        return IP_ERR_VERSION;

    uint16_t hdr_len = ip_hdr_bytes(h);
    if (hdr_len < IP_HDR_MIN_LEN || hdr_len > buf_len)
        return IP_ERR_IHL;

    /* total_len must be consistent with both the header length and the buffer. */
    uint16_t total = rd16_be((const uint8_t *)buf + 2);
    if (total < hdr_len || total > buf_len)
        return IP_ERR_LENGTH;

    /*
     * The checksum is verified with the stored value left in place; the
     * verification is complete only once the *whole* header (options
     * included) has been summed, so length must cover all of it.
     */
    if (!csum16_verify(buf, hdr_len, offsetof(ip_hdr_t, checksum)))
        return IP_ERR_CHECKSUM;

    /* Fragment reassembly is out of scope: a non-zero fragment offset or the
     * more-fragments flag means we cannot process the datagram. */
    uint16_t frag = rd16_be((const uint8_t *)buf + 6);
    if ((frag & IP_MF) || (frag & IP_OFFMASK))
        return IP_ERR_FRAGMENT;

    return IP_OK;
}

const char *ip_parse_strerror(ip_parse_status_t st)
{
    switch (st) {
    case IP_OK:          return "ok";
    case IP_ERR_SHORT:   return "truncated (below minimum header length)";
    case IP_ERR_VERSION: return "not IPv4";
    case IP_ERR_IHL:     return "invalid header length (IHL)";
    case IP_ERR_LENGTH:  return "total_length inconsistent with buffer";
    case IP_ERR_CHECKSUM:return "header checksum mismatch";
    case IP_ERR_FRAGMENT:return "fragmented datagram (reassembly not implemented)";
    default:             return "unknown";
    }
}

void ip_build(ip_hdr_t *h, uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
              uint16_t ip_id, uint16_t payload_len, uint8_t ttl)
{
    memset(h, 0, sizeof *h);
    h->ver_ihl  = 0x45;                  /* version 4, 5 words = 20 bytes */
    h->tos      = 0;
    h->id       = htons(ip_id);
    /* Don't Fragment: this stack never fragments, and DF keeps paths from
     * fragmenting on our behalf. */
    h->frag_off = htons(IP_DF);
    h->ttl      = ttl;
    h->proto    = proto;
    h->src_ip   = src_ip;
    h->dst_ip   = dst_ip;
    (void)payload_len;                    /* set properly by ip_finalize() */
}

void ip_finalize(ip_hdr_t *h, uint16_t payload_len)
{
    h->total_len = htons((uint16_t)(ip_hdr_bytes(h) + payload_len));
    h->checksum  = 0;
    uint16_t c = csum16(h, ip_hdr_bytes(h));
    h->checksum  = htons(c);
}

uint32_t ip_dst_is_local(uint32_t dst_ip, uint32_t our_ip, uint32_t netmask)
{
    /*
     * A destination is ours if it matches our address exactly, or if it is
     * the broadcast address of our subnet (limited broadcast 255.255.255.255
     * is accepted too).
     */
    if (dst_ip == our_ip)
        return our_ip;

    if (dst_ip == 0xFFFFFFFFu)
        return our_ip;

    uint32_t bcast = ip_broadcast(our_ip, netmask);
    if (dst_ip == bcast)
        return our_ip;

    return 0;
}

uint32_t ip_broadcast(uint32_t ip, uint32_t netmask)
{
    return (ip & netmask) | ~netmask;
}