/*
 * tun.h -- TUN/TAP device I/O.
 *
 * Linux gives us two flavours of virtual NIC:
 *
 *   TUN  (IFF_TUN)  delivers/consumes bare IPv4 packets.  The kernel still
 *                   owns the L3 <-> device decision, we just own the protocol.
 *   TAP  (IFF_TAP)  delivers/consumes complete Ethernet frames, so we also get
 *                   to implement ARP and framing ourselves.  This is what the
 *                   stack uses by default because a real netstack has to deal
 *                   with link-layer address resolution.
 *
 * IFF_NO_PI is essential: without it the kernel prepends a 4-byte
 * struct tun_pi (flags + protocol) to every packet and everything downstream
 * would be off by four bytes.
 */
#ifndef USSTACK_TUN_H
#define USSTACK_TUN_H

#include "common.h"

/*
 * Size of the interface-name buffer.
 *
 * Deliberately not IFNAMSIZ: that comes from <net/if.h>, and pulling
 * <net/if.h> into this header would collide with <linux/if.h> over
 * struct ifreq, which src/tun.c needs for the ioctls.  Keeping the name in a
 * plain fixed-size buffer removes the dependency entirely.
 */
#define NETDEV_IFNAMSIZ 32

typedef struct {
    int      fd;
    bool     is_tap;                 /* true = Ethernet frames, false = IPv4 */
    char     ifname[NETDEV_IFNAMSIZ];
    uint32_t ip;                     /* our address, network byte order */
    uint32_t netmask;                /* network byte order */
    uint32_t mtu;
    uint8_t  mac[6];
    bool     up;

    /* counters */
    uint64_t rx_packets, rx_bytes, rx_errors, rx_dropped;
    uint64_t tx_packets, tx_bytes, tx_errors;
} netdev_t;

/* Creates and configures the interface.  Returns 0 on success. */
int  netdev_open(netdev_t *dev, const char *ifname, uint32_t ip,
                 uint32_t netmask, uint32_t mtu, bool tap);

/* Runs a self-test sequence: SYN -> SYN/ACK -> ACK on loopback. */
int  netdev_selftest(netdev_t *dev);

void netdev_close(netdev_t *dev);

/*
 * Read one packet.  `buf` must be at least dev->mtu + 64 bytes.
 * Returns bytes read, 0 on EOF, -1 on error (errno set), -2 on timeout.
 */
int  netdev_rx(netdev_t *dev, uint8_t *buf, size_t cap, int timeout_ms);

/* Transmit one packet.  Returns bytes written or -1. */
int  netdev_tx(netdev_t *dev, const void *buf, size_t len);

#endif /* USSTACK_TUN_H */