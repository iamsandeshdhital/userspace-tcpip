/*
 * net.h -- the stack: device binding, receive path and transmit path.
 *
 * Receive path (a packet arrives from TUN/TAP):
 *
 *   net_rx
 *     -> eth_parse          strip 14-byte Ethernet header (TAP)
 *          -> arp_input
 *          -> ip_input
 *               -> icmp_input
 *               -> tcp_input
 *               -> icmp_send_unreachable (unknown protocol)
 *
 * Transmit path (a protocol wants to send):
 *
 *   icmp_send / tcp_output
 *     -> ip_send            prepend + checksum the IPv4 header
 *          -> net_tx         arp_resolve, then hand a frame to the device
 *
 * net_tx is deliberately indirected through a hook so the whole protocol stack
 * can be driven by unit tests with no kernel device present.
 */
#ifndef USSTACK_NET_H
#define USSTACK_NET_H

#include "common.h"
#include "tun.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"

/* TCP's control block is defined in tcp_socket.h, which deliberately does not
 * include this header (see the comment there).  Only the shape matters here. */
struct tcp_pcb;

/* Called with a fully-formed link-layer frame (or an IPv4 packet for TUN). */
typedef void (*net_tx_hook_t)(void *ctx, const uint8_t *frame, size_t len);

/* Notified when an echo reply arrives, so the application can time it. */
typedef void (*net_icmp_reply_hook_t)(void *ctx, uint16_t id, uint16_t seq,
                                      size_t reply_len);

/*
 * A datagram waiting for its ARP entry to resolve.
 *
 * The first packet to a new neighbour cannot be sent, because we do not yet
 * know its link-layer address.  Throwing it away would break TCP (the SYN
 * would be lost before the connection existed), so it is parked here and
 * replayed the moment the reply arrives.
 */
#define NET_PEND_MAX 8

typedef struct {
    uint32_t dst_ip;                      /* network byte order */
    uint32_t len;
    uint8_t  pkt[USSTACK_MTU_DEFAULT];    /* the IPv4 datagram, not the frame */
} net_pend_t;

typedef struct netstack {
    netdev_t  *dev;              /* NULL in unit tests */
    uint32_t   laddr;            /* network byte order */
    uint32_t   netmask;
    uint32_t   mtu;
    uint8_t    mac[6];
    bool       is_tap;

    arp_cache_t arp;
    struct tcp_pcb *pcbs;        /* all control blocks */
    uint16_t    ip_id;           /* IPv4 id counter */

    net_tx_hook_t tx_hook;
    void         *tx_ctx;

    net_icmp_reply_hook_t icmp_reply_hook;
    void                 *icmp_reply_ctx;

    /* Datagrams parked waiting for ARP resolution. */
    net_pend_t pend[NET_PEND_MAX];
    int        pend_count;

    /* Statistics. */
    uint64_t rx_frames, tx_frames, rx_ip, tx_ip, rx_dropped;
    uint64_t arp_requests, arp_deferred, icmp_echo_rx, icmp_echo_tx;

    uint64_t start_ms;
    uint64_t now_ms;             /* refreshed by net_tick() */
} netstack_t;

/* Initialise a stack bound to a device. */
void net_init(netstack_t *s, netdev_t *dev);
void net_shutdown(netstack_t *s);

/* Attach a transmit hook; pass NULL to use the real device. */
void net_set_tx_hook(netstack_t *s, net_tx_hook_t hook, void *ctx);

/* Attach a hook for echo replies (used by ping). */
void net_set_icmp_reply_hook(netstack_t *s, net_icmp_reply_hook_t hook, void *ctx);

/* Replay datagrams whose ARP entry has just been learned. */
void net_arp_resolved(netstack_t *s, uint32_t ip);

/* One receive-path entry point.  Accepts Ethernet frames or bare IPv4. */
void net_rx(netstack_t *s, const uint8_t *pkt, size_t len);

/* Push buffered data and run timers.  Called from the main loop. */
void net_tick(netstack_t *s);

/* Milliseconds until the next TCP timer needs to run (INT32_MAX if none). */
int  net_poll_timeout_ms(netstack_t *s);

/* Send a pre-built IPv4 packet (header must already be finalized). */
int  ip_send(netstack_t *s, const void *ip_pkt, size_t ip_len);

/*
 * Hand a complete IPv4 datagram to the link layer.  With TAP this resolves the
 * destination link address via ARP first; with TUN the packet is written
 * straight to the device.
 */
int  net_tx(netstack_t *s, const void *ip_pkt, size_t ip_len);

/* ICMP helpers used by TCP. */
void icmp_send_echo_reply(netstack_t *s, const ip_hdr_t *iph,
                          const uint8_t *icmp_body, size_t icmp_len);
void icmp_send_unreachable(netstack_t *s, const ip_hdr_t *iph,
                           uint8_t code, const uint8_t *payload, size_t payload_len);

/* Test/diagnostic helper: run n stack iterations without a device. */
void net_set_time(netstack_t *s, uint64_t now_ms);
uint64_t net_now(const netstack_t *s);

/* ---- layer inputs, exposed for the protocol modules ---- */
void arp_input(netstack_t *s, const uint8_t *frame, size_t len);
void ip_input(netstack_t *s, const uint8_t *pkt, size_t len);
void icmp_input(netstack_t *s, const ip_hdr_t *iph,
                const uint8_t *icmp, size_t len);

/* Fill in an Ethernet header.  Returns the total frame length. */
size_t eth_build_frame(uint8_t *buf, const uint8_t dst[6], const uint8_t src[6],
                       uint16_t ethertype, const void *payload, size_t payload_len);

#endif /* USSTACK_NET_H */