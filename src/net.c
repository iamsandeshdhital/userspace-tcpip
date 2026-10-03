/*
 * net.c -- the stack: framing, ARP, IP demultiplexing and the transmit path.
 */
#include "net.h"
#include "tcp_socket.h"
#include "checksum.h"
#include "log.h"
#include "clock.h"

#include <stdio.h>

void net_init(netstack_t *s, netdev_t *dev)
{
    memset(s, 0, sizeof *s);
    s->dev = dev;
    s->start_ms = mono_ms();
    s->now_ms = 0;
    arp_init(&s->arp);

    if (dev) {
        s->laddr = dev->ip;
        s->netmask = dev->netmask;
        s->mtu = dev->mtu ? dev->mtu : USSTACK_MTU_DEFAULT;
        s->is_tap = dev->is_tap;
        memcpy(s->mac, dev->mac, 6);
    } else {
        s->mtu = USSTACK_MTU_DEFAULT;
    }
}

void net_shutdown(netstack_t *s)
{
    /* Always destroy the head: destruction unlinks as it frees. */
    while (s->pcbs)
        tcp_pcb_destroy(s->pcbs);

    arp_flush(&s->arp);
}

void net_set_tx_hook(netstack_t *s, net_tx_hook_t hook, void *ctx)
{
    s->tx_hook = hook;
    s->tx_ctx = ctx;
}

void net_set_icmp_reply_hook(netstack_t *s, net_icmp_reply_hook_t hook, void *ctx)
{
    s->icmp_reply_hook = hook;
    s->icmp_reply_ctx = ctx;
}

void net_set_time(netstack_t *s, uint64_t now_ms) { s->now_ms = now_ms; }
uint64_t net_now(const netstack_t *s) { return s->now_ms ? s->now_ms : mono_ms(); }

/* ------------------------------------------------------------------ */
/* Transmit path                                                      */
/* ------------------------------------------------------------------ */

size_t eth_build_frame(uint8_t *buf, const uint8_t dst[6], const uint8_t src[6],
                       uint16_t ethertype, const void *payload, size_t payload_len)
{
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->dst, dst, 6);
    memcpy(eth->src, src, 6);
    eth->ethertype = htons(ethertype);
    if (payload && payload_len)
        memcpy(buf + ETH_HDR_LEN, payload, payload_len);
    return ETH_HDR_LEN + payload_len;
}

/*
 * Send one IPv4 packet.  With TAP this first requires a link-layer address for
 * the destination; without one we solicit an ARP request and drop the packet.
 * Silently dropping is not great, but re-queueing would need a routing cache;
 * for a loopback demo the ARP reply arrives within microseconds and the next
 * attempt succeeds.  We log it loudly so the behaviour is never a mystery.
 */
static int net_tx_frame(netstack_t *s, const uint8_t *ip_pkt, size_t ip_len);

int net_tx(netstack_t *s, const void *ip_pkt, size_t ip_len)
{
    return net_tx_frame(s, (const uint8_t *)ip_pkt, ip_len);
}

static int net_tx_frame(netstack_t *s, const uint8_t *ip_pkt, size_t ip_len)
{
    s->tx_ip++;

    if (!s->is_tap) {
        /* TUN: the device takes bare IP packets. */
        s->tx_frames++;
        if (s->tx_hook) {
            s->tx_hook(s->tx_ctx, ip_pkt, ip_len);
            return (int)ip_len;
        }
        if (s->dev && s->dev->fd >= 0)
            return netdev_tx(s->dev, ip_pkt, ip_len);
        return (int)ip_len;
    }

    const ip_hdr_t *iph = (const ip_hdr_t *)ip_pkt;
    uint8_t dst_mac[6];
    char    ipb[INET_ADDRSTRLEN];

    if (!arp_lookup(&s->arp, iph->dst_ip, dst_mac)) {
        /* No entry yet: broadcast a request and hold the datagram back. */
        uint8_t frame[ETH_HDR_LEN + ARP_HDR_LEN];
        arp_pkt_t *arp = (arp_pkt_t *)(frame + ETH_HDR_LEN);

        eth_build_frame(frame, ETH_BROADCAST, s->mac, ETHERTYPE_ARP, NULL, 0);
        arp->htype  = htons(ARP_HTYPE_ETHER);
        arp->ptype  = htons(ETHERTYPE_IP);
        arp->hlen   = 6;
        arp->plen   = 4;
        arp->opcode = htons(ARP_OP_REQUEST);
        memcpy(arp->sha, s->mac, 6);
        arp->spa = s->laddr;
        memset(arp->tha, 0, 6);
        arp->tpa = iph->dst_ip;

        s->arp_requests++;
        log_debug("net: no ARP entry for %s, broadcasting a request",
                  ip_str(iph->dst_ip, ipb, sizeof ipb));

        if (s->tx_hook)
            s->tx_hook(s->tx_ctx, frame, sizeof frame);
        else if (s->dev && s->dev->fd >= 0)
            netdev_tx(s->dev, frame, sizeof frame);

        /*
         * Park the datagram.  Dropping it would lose the SYN of a connection
         * that does not exist yet, so a client could never reach a host whose
         * address it had not already cached.
         */
        if (ip_len <= sizeof s->pend[0].pkt) {
            if (s->pend_count < NET_PEND_MAX) {
                net_pend_t *slot = &s->pend[s->pend_count++];
                slot->dst_ip = iph->dst_ip;
                slot->len = (uint32_t)ip_len;
                memcpy(slot->pkt, ip_pkt, ip_len);
                s->arp_deferred++;
                log_debug("net: deferred a %zu-byte datagram for %s "
                          "(%d waiting on ARP)", ip_len,
                          ip_str(iph->dst_ip, ipb, sizeof ipb), s->pend_count);
                return (int)ip_len;
            }
            log_warn("net: ARP queue full, dropping datagram for %s",
                     ip_str(iph->dst_ip, ipb, sizeof ipb));
        }
        s->rx_dropped++;
        return -1;
    }

    uint8_t frame[USSTACK_MTU_DEFAULT + ETH_HDR_LEN];
    size_t flen = eth_build_frame(frame, dst_mac, s->mac, ETHERTYPE_IP,
                                  ip_pkt, ip_len);

    s->tx_frames++;
    if (s->tx_hook) {
        s->tx_hook(s->tx_ctx, frame, flen);
        return (int)flen;
    }
    if (s->dev && s->dev->fd >= 0)
        return netdev_tx(s->dev, frame, flen);

    return (int)flen;
}

/*
 * An address just became known: replay everything that was waiting for it.
 */
void net_arp_resolved(netstack_t *s, uint32_t ip)
{
    char ipb[INET_ADDRSTRLEN];

    for (int i = 0; i < s->pend_count; ) {
        if (s->pend[i].dst_ip != ip) {
            i++;
            continue;
        }

        /* Remove the entry before replaying it, so a failure inside
         * net_tx_frame cannot leave us looping over the same datagram. */
        net_pend_t copy = s->pend[i];
        s->pend[i] = s->pend[--s->pend_count];

        log_debug("net: replaying the deferred datagram for %s",
                  ip_str(ip, ipb, sizeof ipb));
        net_tx_frame(s, copy.pkt, copy.len);
    }
}

int ip_send(netstack_t *s, const void *ip_pkt, size_t ip_len)
{
    return net_tx(s, (const uint8_t *)ip_pkt, ip_len);
}

/* ------------------------------------------------------------------ */
/* ARP                                                                */
/* ------------------------------------------------------------------ */

void arp_input(netstack_t *s, const uint8_t *frame, size_t len)
{
    char ipb[INET_ADDRSTRLEN];
    char macb[24];

    if (len < ARP_HDR_LEN) {
        s->rx_dropped++;
        return;
    }

    const arp_pkt_t *arp = (const arp_pkt_t *)frame;

    if (rd16_be((const uint8_t *)arp->htype) != ARP_HTYPE_ETHER ||
        rd16_be((const uint8_t *)arp->ptype) != ETHERTYPE_IP ||
        arp->hlen != 6 || arp->plen != 4) {
        log_debug("arp: unsupported hardware/protocol address format");
        s->rx_dropped++;
        return;
    }

    uint32_t spa = rd32_be((const uint8_t *)arp->spa);
    uint32_t tpa = rd32_be((const uint8_t *)arp->tpa);
    uint16_t op  = rd16_be((const uint8_t *)arp->opcode);

    /*
     * Learn from any sender we hear from: gratuitous ARP and replies both
     * populate the cache, which is what makes ARP a "free" learning protocol.
     */
    if (spa != 0 && !eth_is_broadcast(arp->sha)) {
        arp_insert(&s->arp, spa, arp->sha);
        log_debug("arp: learned %s -> %s", ip_str(spa, ipb, sizeof ipb),
                  eth_fmt_mac(arp->sha, macb, sizeof macb));
        net_arp_resolved(s, spa);
    }

    if (tpa != s->laddr) {
        log_trace("arp: request for %s is not ours, ignoring",
                  ip_str(tpa, ipb, sizeof ipb));
        return;
    }

    if (op == ARP_OP_REQUEST) {
        uint8_t out[ETH_HDR_LEN + ARP_HDR_LEN];

        arp_pkt_t *rep = (arp_pkt_t *)(out + ETH_HDR_LEN);
        eth_build_frame(out, arp->sha, s->mac, ETHERTYPE_ARP, NULL, 0);

        rep->htype   = htons(ARP_HTYPE_ETHER);
        rep->ptype   = htons(ETHERTYPE_IP);
        rep->hlen    = 6;
        rep->plen    = 4;
        rep->opcode  = htons(ARP_OP_REPLY);
        memcpy(rep->sha, s->mac, 6);
        rep->spa = s->laddr;
        memcpy(rep->tha, arp->sha, 6);
        rep->tpa = spa;

        log_debug("arp: replying to %s (%s)",
                  ip_str(spa, ipb, sizeof ipb),
                  eth_fmt_mac(arp->sha, macb, sizeof macb));

        if (s->tx_hook)
            s->tx_hook(s->tx_ctx, out, sizeof out);
        else if (s->dev && s->dev->fd >= 0)
            netdev_tx(s->dev, out, sizeof out);
    }
}

/* ------------------------------------------------------------------ */
/* IP input                                                           */
/* ------------------------------------------------------------------ */

void ip_input(netstack_t *s, const uint8_t *pkt, size_t len)
{
    char srcb[INET_ADDRSTRLEN], dstb[INET_ADDRSTRLEN];

    if (len < IP_HDR_MIN_LEN) {
        s->rx_dropped++;
        return;
    }

    const ip_hdr_t *iph = (const ip_hdr_t *)pkt;

    ip_parse_status_t st = ip_validate(pkt, len);
    if (st != IP_OK) {
        log_warn("ip: dropping packet from %s: %s",
                 ip_str(iph->src_ip, srcb, sizeof srcb), ip_parse_strerror(st));
        s->rx_dropped++;
        return;
    }

    uint16_t hdr_len = ip_hdr_bytes(iph);
    uint16_t total   = rd16_be((const uint8_t *)pkt + 2);
    size_t   payload_len = (size_t)total - hdr_len;
    const uint8_t *payload = pkt + hdr_len;

    if (!ip_dst_is_local(iph->dst_ip, s->laddr, s->netmask)) {
        /*
         * Not addressed to us.  This stack has no forwarding table, so the
         * packet is dropped.  Enabling forwarding would mean decrementing
         * TTL, decrementing the header checksum by 4 (RFC 1624) and looking
         * the destination up in a route table.
         */
        log_info("ip: dst=%s is not local (from %s), dropping: no forwarding",
                 ip_str(iph->dst_ip, dstb, sizeof dstb),
                 ip_str(iph->src_ip, srcb, sizeof srcb));
        s->rx_dropped++;
        return;
    }

    s->rx_ip++;
    log_trace("ip: %s -> %s proto=%u len=%u ttl=%u id=%u",
              ip_str(iph->src_ip, srcb, sizeof srcb),
              ip_str(iph->dst_ip, dstb, sizeof dstb),
              iph->proto, total, iph->ttl, rd16_be((const uint8_t *)pkt + 4));

    switch (iph->proto) {
    case IP_PROTO_ICMP:
        icmp_input(s, iph, payload, payload_len);
        break;

    case IP_PROTO_TCP:
        tcp_input(s, iph->src_ip, iph->dst_ip, payload, payload_len);
        break;

    default:
        log_info("ip: no handler for protocol %u, sending unreachable",
                 iph->proto);
        icmp_send_unreachable(s, iph, ICMP_UNREACH_PROTO, payload, payload_len);
        s->rx_dropped++;
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Ethernet / device entry point                                      */
/* ------------------------------------------------------------------ */

void net_rx(netstack_t *s, const uint8_t *pkt, size_t len)
{
    if (!s->is_tap) {
        /* TUN delivers bare IPv4 packets. */
        s->rx_frames++;
        ip_input(s, pkt, len);
        return;
    }

    if (len < ETH_HDR_LEN) {
        s->rx_dropped++;
        return;
    }

    s->rx_frames++;
    const eth_hdr_t *eth = (const eth_hdr_t *)pkt;

    if (!eth_is_ours(eth->dst, s->mac)) {
        log_trace("net: frame not addressed to us, dropping");
        s->rx_dropped++;
        return;
    }

    uint16_t et = rd16_be((const uint8_t *)pkt + 12);
    const uint8_t *payload = pkt + ETH_HDR_LEN;
    size_t payload_len = len - ETH_HDR_LEN;

    switch (et) {
    case ETHERTYPE_ARP:
        arp_input(s, payload, payload_len);
        break;

    case ETHERTYPE_IP:
        ip_input(s, payload, payload_len);
        break;

    default:
        log_trace("net: unsupported ethertype 0x%04x, dropping", et);
        s->rx_dropped++;
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Timers                                                             */
/* ------------------------------------------------------------------ */

void net_tick(netstack_t *s)
{
    s->now_ms = mono_ms();
    tcp_timer_tick(s, s->now_ms);
}

int net_poll_timeout_ms(netstack_t *s)
{
    int t = tcp_next_timeout_ms(s);
    if (t < 0 || t > 1000)
        t = 1000;
    return t;
}