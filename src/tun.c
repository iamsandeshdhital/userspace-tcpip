/*
 * tun.c -- TUN/TAP device setup and I/O.
 *
 * Everything here is the only place in the stack that touches the kernel.  The
 * protocol layers above deal exclusively in byte buffers, which is what makes
 * the test suite able to run the full stack with no device at all.
 *
 * Setup sequence for a TAP device:
 *   open("/dev/net/tun", O_RDWR)
 *   ioctl(TUNSETIFF, IFF_TAP | IFF_NO_PI)   -- attach to a named interface
 *   ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS)         -- bring IFF_UP | IFF_RUNNING up
 *   ioctl(SIOCSIFMTU)                        -- set the MTU
 *
 * IFF_NO_PI is mandatory.  Without it every read returns a leading
 * struct tun_pi (2-byte flags + 2-byte protocol) that must be stripped.
 */
#include "tun.h"
#include "log.h"
#include "clock.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>

/*
 * Order matters here.  <net/if.h> and <linux/if.h> both define struct ifreq,
 * and including them the other way round fails to compile.  glibc's <net/if.h>
 * also expects <sys/socket.h> to have been included first, which is why it is
 * listed above rather than beside <linux/if.h>.
 */
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*
 * IFNAMSIZ is 16 on Linux, but the copy below uses sizeof ifr.ifr_name
 * instead so the code cannot drift out of step with the kernel's struct.
 */
static void dev_ifname(netdev_t *dev, const char *ifname)
{
    size_t n = strlen(ifname);

    if (n >= sizeof dev->ifname)
        n = sizeof dev->ifname - 1;

    memcpy(dev->ifname, ifname, n);
    dev->ifname[n] = '\0';
}

int netdev_open(netdev_t *dev, const char *ifname, uint32_t ip,
                uint32_t netmask, uint32_t mtu, bool tap)
{
    memset(dev, 0, sizeof *dev);
    dev->fd = -1;
    dev->is_tap = tap;
    dev->ip = ip;
    dev->netmask = netmask;
    dev->mtu = mtu;
    dev_ifname(dev, ifname);

    char ipb[INET_ADDRSTRLEN];
    log_info("tun: opening %s device '%s' for %s",
             tap ? "TAP" : "TUN", ifname, ip_str(ip, ipb, sizeof ipb));

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        log_error("tun: open(/dev/net/tun): %s -- need root and the tun module",
                  strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = (tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
    dev_ifname(dev, ifname);
    strncpy(ifr.ifr_name, ifname, sizeof ifr.ifr_name - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("tun: TUNSETIFF: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * The kernel may hand back a different name if the requested one was
     * already taken (e.g. tun0 vs tap0 naming rules).
     */
    dev_ifname(dev, ifr.ifr_name);
    dev->fd = fd;

    /* Bring the interface up. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        log_error("tun: socket: %s", strerror(errno));
        netdev_close(dev);
        return -1;
    }

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, dev->ifname, sizeof ifr.ifr_name - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("tun: SIOCGIFFLAGS: %s", strerror(errno));
        close(s);
        netdev_close(dev);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("tun: SIOCSIFFLAGS (setting IFF_UP): %s", strerror(errno));
        close(s);
        netdev_close(dev);
        return -1;
    }

    struct ifreq mreq = ifr;
    mreq.ifr_mtu = (int)mtu;
    if (ioctl(s, SIOCSIFMTU, &mreq) < 0) {
        log_warn("tun: SIOCSIFMTU(%u): %s -- continuing with kernel default",
                 mtu, strerror(errno));
    }

    /* Read back the MAC the kernel assigned. */
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, dev->ifname, sizeof ifr.ifr_name - 1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(dev->mac, ifr.ifr_hwaddr.sa_data, 6);
    else
        dev->mac[0] = 0x02;   /* locally administered fallback */

    close(s);

    char macb[24];
    dev->up = true;
    log_info("tun: '%s' is up, mtu=%u, mac=%s",
             dev->ifname, mtu, eth_fmt_mac(dev->mac, macb, sizeof macb));
    return 0;
}

int netdev_selftest(netdev_t *dev)
{
    /*
     * Build a SYN by hand and write it to the device.  On a TAP interface
     * this is an Ethernet frame; on TUN it is a bare IPv4 packet.  It is
     * aimed at our own address so the kernel (which is still attached to the
     * device) will answer it and prove the path works end to end before the
     * userspace stack is trusted with it.
     */
    char ipb[INET_ADDRSTRLEN];
    log_info("tun: self-test SYN -> %s", ip_str(dev->ip, ipb, sizeof ipb));

    uint8_t pkt[64];
    memset(pkt, 0, sizeof pkt);

    uint32_t src = dev->ip;
    uint32_t dst = dev->ip;

    if (dev->is_tap) {
        eth_hdr_t *eth = (eth_hdr_t *)pkt;
        memcpy(eth->dst, ETH_BROADCAST, 6);
        memcpy(eth->src, dev->mac, 6);
        eth->ethertype = htons(ETHERTYPE_IP);

        ip_hdr_t *iph = (ip_hdr_t *)(pkt + ETH_HDR_LEN);
        ip_build(iph, src, dst, IP_PROTO_TCP, 0x1234, TCP_HDR_MIN_LEN,
                 USSTACK_TTL_DEFAULT);

        tcp_hdr_t *th = (tcp_hdr_t *)(pkt + ETH_HDR_LEN + IP_HDR_MIN_LEN);
        th->src_port = htons(40000);
        th->dst_port = htons(9);          /* discard: usually closed -> RST */
        th->seq = htonl(0);
        th->ack = 0;
        th->offset_flags = 0x50;
        th->flags = TH_SYN;
        th->window = htons(65535);

        ip_finalize(iph, TCP_HDR_MIN_LEN);
        int rc = netdev_tx(dev, pkt, ETH_HDR_LEN + IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN);
        return rc < 0 ? -1 : 0;
    }

    /* TUN: bare IPv4 packet. */
    ip_hdr_t *iph = (ip_hdr_t *)pkt;
    ip_build(iph, src, dst, IP_PROTO_TCP, 0x1234, TCP_HDR_MIN_LEN,
             USSTACK_TTL_DEFAULT);

    tcp_hdr_t *th = (tcp_hdr_t *)(pkt + IP_HDR_MIN_LEN);
    th->src_port = htons(40000);
    th->dst_port = htons(9);
    th->seq = htonl(0);
    th->ack = 0;
    th->offset_flags = 0x50;
    th->flags = TH_SYN;
    th->window = htons(65535);

    ip_finalize(iph, TCP_HDR_MIN_LEN);
    return netdev_tx(dev, pkt, IP_HDR_MIN_LEN + TCP_HDR_MIN_LEN) < 0 ? -1 : 0;
}

void netdev_close(netdev_t *dev)
{
    if (dev->fd >= 0) {
        close(dev->fd);
        dev->fd = -1;
    }
    if (dev->up)
        log_info("tun: closing '%s' (rx=%llu pkts, tx=%llu pkts)",
                 dev->ifname,
                 (unsigned long long)dev->rx_packets,
                 (unsigned long long)dev->tx_packets);
    dev->up = false;
}

int netdev_rx(netdev_t *dev, uint8_t *buf, size_t cap, int timeout_ms)
{
    if (dev->fd < 0)
        return -1;

    if (timeout_ms >= 0) {
        struct pollfd pfd = { .fd = dev->fd, .events = POLLIN };
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc == 0)
            return -2;                      /* timeout */
        if (rc < 0) {
            if (errno == EINTR)
                return -2;
            log_error("tun: poll: %s", strerror(errno));
            dev->rx_errors++;
            return -1;
        }
    }

    ssize_t n = read(dev->fd, buf, cap);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return -2;
        log_error("tun: read: %s", strerror(errno));
        dev->rx_errors++;
        return -1;
    }
    if (n == 0)
        return 0;                           /* EOF / device closed */

    dev->rx_packets++;
    dev->rx_bytes += (uint64_t)n;
    return (int)n;
}

int netdev_tx(netdev_t *dev, const void *buf, size_t len)
{
    if (dev->fd < 0)
        return -1;

    /* write(2) on a TUN device is atomic for a whole packet. */
    ssize_t n = write(dev->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Interface queue full: drop rather than block the stack. */
            log_warn("tun: tx queue full, dropped %zu bytes", len);
            dev->tx_errors++;
            return -1;
        }
        log_error("tun: write: %s", strerror(errno));
        dev->tx_errors++;
        return -1;
    }

    dev->tx_packets++;
    dev->tx_bytes += (uint64_t)n;
    return (int)n;
}