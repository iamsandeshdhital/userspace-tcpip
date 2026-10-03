/*
 * icmp.c -- Echo handling and error generation.
 *
 * The stack needs ICMP for two things:
 *
 *   1. Echo request/reply -- how ping works at layer 3.
 *   2. Destination Unreachable (port unreachable) -- how a listening TCP
 *      socket tells the peer "I have no connection for that 4-tuple", which
 *      is the standard mechanism by which connect() fails with ECONNREFUSED.
 */
#include "icmp.h"
#include "net.h"
#include "checksum.h"
#include "log.h"

#include <stdio.h>

void icmp_finalize(void *buf, size_t len)
{
    icmp_hdr_t *h = (icmp_hdr_t *)buf;
    h->checksum = 0;
    h->checksum = htons(csum16(buf, len));
}

void icmp_send_echo_reply(netstack_t *s, const ip_hdr_t *iph,
                          const uint8_t *icmp_body, size_t icmp_len)
{
    uint8_t  buf[USSTACK_MTU_DEFAULT];
    char     ipb[INET_ADDRSTRLEN];

    /*
     * `icmp_len` is the length of the whole ICMP message, i.e. the 8-byte
     * echo header plus the payload.  Trim it if a reply would not fit the
     * MTU; 8 is the smallest legal message.
     */
    size_t max_body = (size_t)s->mtu - IP_HDR_MIN_LEN;
    if (icmp_len > max_body)
        icmp_len = max_body;
    if (icmp_len < 8)
        icmp_len = 8;

    ip_hdr_t   *out  = (ip_hdr_t *)buf;
    icmp_echo_t *echo = (icmp_echo_t *)(buf + IP_HDR_MIN_LEN);

    ip_build(out, iph->dst_ip, iph->src_ip, IP_PROTO_ICMP,
             s->ip_id++, (uint16_t)icmp_len, USSTACK_TTL_DEFAULT);

    /* Preserve id and seq so the requester can match the reply. */
    echo->type = ICMP_ECHOREPLY;
    echo->code = 0;
    echo->id   = rd16_be((const uint8_t *)icmp_body + 4);
    echo->seq  = rd16_be((const uint8_t *)icmp_body + 6);

    /* Copy the payload, which is everything past the 8-byte echo header. */
    memcpy(buf + IP_HDR_MIN_LEN + 8, (const uint8_t *)icmp_body + 8,
           icmp_len - 8);

    icmp_finalize(echo, icmp_len);
    ip_finalize(out, (uint16_t)icmp_len);

    log_trace("icmp: echo reply id=%u seq=%u to %s",
              ntohs(echo->id), ntohs(echo->seq),
              ip_str(out->dst_ip, ipb, sizeof ipb));

    s->icmp_echo_tx++;
    ip_send(s, buf, IP_HDR_MIN_LEN + icmp_len);
}

void icmp_send_unreachable(netstack_t *s, const ip_hdr_t *iph,
                           uint8_t code, const uint8_t *payload, size_t payload_len)
{
    uint8_t buf[IP_HDR_MIN_LEN + ICMP_QUOTE_LEN];
    char    ipb[INET_ADDRSTRLEN];

    /*
     * RFC 792 requires quoting the offending IP header plus the first 8 bytes
     * of its payload.  The header length is capped so that a packet carrying
     * IPv4 options cannot make the error message overflow.
     */
    uint16_t quote_hdr = ip_hdr_bytes(iph);
    if (quote_hdr < IP_HDR_MIN_LEN)
        quote_hdr = IP_HDR_MIN_LEN;
    if (quote_hdr > 60)
        quote_hdr = 60;

    size_t body_len = ICMP_HDR_LEN + quote_hdr + 8;

    ip_hdr_t  *out  = (ip_hdr_t *)buf;
    icmp_err_t *icmp = (icmp_err_t *)(buf + IP_HDR_MIN_LEN);
    uint8_t   *quote = buf + IP_HDR_MIN_LEN + ICMP_HDR_LEN;

    ip_build(out, iph->dst_ip, iph->src_ip, IP_PROTO_ICMP,
             s->ip_id++, (uint16_t)body_len, USSTACK_TTL_DEFAULT);

    icmp->type    = ICMP_UNREACH;
    icmp->code    = code;
    icmp->unused  = 0;

    memcpy(quote, iph, quote_hdr);
    memset(quote + quote_hdr, 0, 8);
    if (payload && payload_len)
        memcpy(quote + quote_hdr, payload, MIN(payload_len, (size_t)8));

    icmp_finalize(icmp, body_len);
    ip_finalize(out, (uint16_t)body_len);

    log_debug("icmp: sending unreachable code=%u to %s",
              code, ip_str(out->dst_ip, ipb, sizeof ipb));

    ip_send(s, buf, IP_HDR_MIN_LEN + body_len);
}

/* ------------------------------------------------------------------ */
/* Input path                                                         */
/* ------------------------------------------------------------------ */

void icmp_input(netstack_t *s, const ip_hdr_t *iph,
                const uint8_t *icmp, size_t len)
{
    char ipb[INET_ADDRSTRLEN];

    if (len < ICMP_HDR_LEN) {
        log_debug("icmp: truncated (%zu bytes)", len);
        s->rx_dropped++;
        return;
    }

    if (!csum16_verify(icmp, len, 2)) {
        log_warn("icmp: bad checksum from %s, dropping",
                 ip_str(iph->src_ip, ipb, sizeof ipb));
        s->rx_dropped++;
        return;
    }

    icmp_echo_t *echo = (icmp_echo_t *)icmp;

    switch (echo->type) {
    case ICMP_ECHO:
        if (len < 8) {
            s->rx_dropped++;
            return;
        }
        s->icmp_echo_rx++;
        log_debug("icmp: echo request id=%u seq=%u from %s",
                  ntohs(echo->id), ntohs(echo->seq),
                  ip_str(iph->src_ip, ipb, sizeof ipb));
        icmp_send_echo_reply(s, iph, icmp, len);
        break;

    case ICMP_ECHOREPLY:
        if (len < 8) {
            s->rx_dropped++;
            return;
        }
        if (s->icmp_reply_hook)
            s->icmp_reply_hook(s->icmp_reply_ctx, ntohs(echo->id),
                               ntohs(echo->seq), len);
        else
            log_debug("icmp: echo reply id=%u seq=%u (no listener)",
                      ntohs(echo->id), ntohs(echo->seq));
        break;

    case ICMP_UNREACH:
        log_warn("icmp: dest unreachable code=%u from %s",
                 icmp[1], ip_str(iph->src_ip, ipb, sizeof ipb));
        break;

    case ICMP_TIMXCEED:
        log_warn("icmp: time exceeded code=%u from %s",
                 icmp[1], ip_str(iph->src_ip, ipb, sizeof ipb));
        break;

    default:
        log_trace("icmp: type %u ignored", echo->type);
        break;
    }
}