/*
 * main.c -- device bring-up, the event loop and the interactive CLI.
 *
 * The loop is deliberately simple: poll the TUN device with a timeout equal to
 * the nearest TCP timer deadline, drain whatever arrives, run the timers, then
 * service the console.  Nothing in the protocol layers blocks, which is what
 * lets one thread carry many connections.
 */
#define _POSIX_C_SOURCE 200809L

#include "net.h"
#include "tcp_socket.h"
#include "ping.h"
#include "log.h"
#include "clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>

#define RX_BUF_SIZE (USSTACK_MTU_DEFAULT + 128)
#define LINE_SIZE   512

typedef struct {
    netstack_t  stack;
    netdev_t    dev;
    bool        dev_open;
    bool        stdin_open;

    ping_ctx_t  ping;
    bool        ping_active;
    uint32_t    ping_deadline_ms;
    uint32_t    ping_next_send_ms;
    uint32_t    ping_lost;      /* requests still outstanding when the run ends */
    int         ping_count;

    tcp_pcb_t  *listener;
    tcp_pcb_t  *client;
    tcp_pcb_t  *peer;
    bool        quit;
} app_t;

static app_t g_app;
static volatile sig_atomic_t g_interrupted;

/* ------------------------------------------------------------------ */
/* argument parsing                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *ifname;
    uint32_t    ip;
    uint32_t    netmask;
    uint32_t    mtu;
    bool        tap;
    log_level_t level;
    bool        selftest;
} options_t;

static void usage(const char *argv0)
{
    printf(
"userspace-tcpip " USSTACK_VERSION " -- a TCP/IP stack in userspace\n"
"\n"
"usage: %s [options]\n"
"\n"
"options:\n"
"  -i, --iface NAME     TUN/TAP interface to create (default tap0)\n"
"  -a, --addr IP         our IPv4 address (default 10.0.0.1)\n"
"  -n, --netmask MASK    netmask (default 255.255.255.0)\n"
"  -m, --mtu N           MTU, %d..%d (default %d)\n"
"  -t, --tun             use TUN (bare IPv4) instead of TAP (Ethernet)\n"
"  -L, --log-level N     0=error 1=warn 2=info 3=debug 4=trace (default 2)\n"
"  -s, --selftest        write one SYN and exit\n"
"  -h, --help            this message\n"
"\n"
"requires root (or CAP_NET_ADMIN) and /dev/net/tun\n",
    argv0, 576, USSTACK_MTU_DEFAULT, USSTACK_MTU_DEFAULT);
}

static bool parse_options(int argc, char **argv, options_t *o)
{
    memset(o, 0, sizeof *o);
    o->ifname = "tap0";
    o->mtu = USSTACK_MTU_DEFAULT;
    o->tap = true;
    o->level = LOG_LEVEL_INFO;

    if (inet_pton(AF_INET, "10.0.0.1", &o->ip) != 1)
        return false;
    if (inet_pton(AF_INET, "255.255.255.0", &o->netmask) != 1)
        return false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if ((!strcmp(a, "-i") || !strcmp(a, "--iface")) && i + 1 < argc) {
            o->ifname = argv[++i];
        } else if ((!strcmp(a, "-a") || !strcmp(a, "--addr")) && i + 1 < argc) {
            if (inet_pton(AF_INET, argv[++i], &o->ip) != 1) {
                fprintf(stderr, "bad address\n");
                return false;
            }
        } else if ((!strcmp(a, "-n") || !strcmp(a, "--netmask")) && i + 1 < argc) {
            if (inet_pton(AF_INET, argv[++i], &o->netmask) != 1) {
                fprintf(stderr, "bad netmask\n");
                return false;
            }
        } else if ((!strcmp(a, "-m") || !strcmp(a, "--mtu")) && i + 1 < argc) {
            o->mtu = (uint32_t)strtoul(argv[++i], NULL, 10);
            if (o->mtu < 576 || o->mtu > USSTACK_MTU_DEFAULT) {
                fprintf(stderr, "MTU must be between 576 and %d\n",
                        USSTACK_MTU_DEFAULT);
                return false;
            }
        } else if (!strcmp(a, "-t") || !strcmp(a, "--tun")) {
            o->tap = false;
        } else if ((!strcmp(a, "-L") || !strcmp(a, "--log-level")) && i + 1 < argc) {
            o->level = (log_level_t)atoi(argv[++i]);
        } else if (!strcmp(a, "-s") || !strcmp(a, "--selftest")) {
            o->selftest = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "unknown option '%s'\n", a);
            usage(argv[0]);
            return false;
        }
    }
    return true;
}

static void on_signal(int sig)
{
    (void)sig;
    g_interrupted = 1;
}

/* ------------------------------------------------------------------ */
/* console helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Split on spaces and tabs, in place.  strtok_r is avoided because it is not
 * in C11 and because it overwrites the separators -- which would destroy the
 * payload of a `send` command.
 */
static int tokenize(char *line, char **tok, int max)
{
    int n = 0;
    char *p = line;

    while (*p && n < max) {
        while (*p == ' ' || *p == '\t')
            *p++ = '\0';
        if (!*p)
            break;

        tok[n++] = p;

        while (*p && *p != ' ' && *p != '\t')
            p++;
    }

    return n;
}

static void print_banner(app_t *app)
{
    char ipb[INET_ADDRSTRLEN], nm[INET_ADDRSTRLEN], mb[24];

    printf("userspace-tcpip %s -- TCP/IP implemented in userspace\n",
           USSTACK_VERSION);
    printf("  device : %s (%s), mtu=%u, mac=%s\n",
           app->dev.ifname, app->dev.is_tap ? "TAP/ethernet" : "TUN/ip",
           app->dev.mtu, eth_fmt_mac(app->dev.mac, mb, sizeof mb));
    printf("  address: %s / %s\n",
           ip_str(app->stack.laddr, ipb, sizeof ipb),
           ip_str(app->stack.netmask, nm, sizeof nm));
    printf("  type 'help' for commands, 'quit' to exit\n\n");
    fflush(stdout);
}

static void cmd_help(void)
{
    printf(
"commands:\n"
"  help                  this list\n"
"  ifconfig              interface and stack configuration\n"
"  ping <ip> [count]     send ICMP echo requests\n"
"  arp                   show the ARP cache\n"
"  listen <port>         listen for TCP connections\n"
"  accept                accept a pending connection\n"
"  connect <ip> <port>   open a TCP connection\n"
"  send <text>           send text on the current connection\n"
"  recv                  read whatever has arrived\n"
"  close                 close the current connection\n"
"  sockets               list every control block\n"
"  sock <n>              select connection n\n"
"  stats                 stack counters\n"
"  trace                 toggle packet tracing\n"
"  quit                  exit\n");
    fflush(stdout);
}

/* The connection that send/recv/close act on. */
static tcp_pcb_t *current_conn(app_t *app)
{
    if (app->peer && app->peer->state != TCP_CLOSED)
        return app->peer;
    if (app->client && app->client->state != TCP_CLOSED)
        return app->client;
    return NULL;
}

static void cmd_sockets(app_t *app)
{
    printf("\n%-4s %-22s %-22s %-12s %s\n", "#", "local", "remote",
           "state", "tx/rx");

    int i = 0;
    for (tcp_pcb_t *p = tcp_first(&app->stack); p; p = p->next, i++) {
        char lb[INET_ADDRSTRLEN], rb[INET_ADDRSTRLEN];
        char l[64], r[64];

        snprintf(l, sizeof l, "%s:%u", ip_str(p->laddr, lb, sizeof lb),
                 p->lport);

        if (p->raddr && p->rport)
            snprintf(r, sizeof r, "%s:%u", ip_str(p->raddr, rb, sizeof rb),
                     p->rport);
        else
            snprintf(r, sizeof r, "*:*");

        printf("%-4d %-22s %-22s %-12s %llu/%llu%s\n", i, l, r,
               tcp_state_str(p->state),
               (unsigned long long)p->bytes_sent,
               (unsigned long long)p->bytes_recv,
               p->err ? "  error" : "");
    }
    printf("\n");
    fflush(stdout);
}

static void cmd_arp(app_t *app)
{
    printf("\n%-16s %-18s %s\n", "IP address", "MAC address", "age");

    size_t n = arp_count(&app->stack.arp);

    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        const arp_entry_t *e = arp_get(&app->stack.arp, i);
        if (!e)
            continue;

        char ipb[INET_ADDRSTRLEN], mb[24];
        printf("%-16s %-18s %llums\n",
               ip_str(e->ip, ipb, sizeof ipb),
               eth_fmt_mac(e->mac, mb, sizeof mb),
               (unsigned long long)(log_uptime_ms() - e->updated_ms));
    }

    printf("\n%zu entries, %llu lookups, %llu hits, %llu misses\n",
           n, (unsigned long long)app->stack.arp.lookups,
           (unsigned long long)app->stack.arp.hits,
           (unsigned long long)app->stack.arp.misses);
    printf("\n");
    fflush(stdout);
}

static void cmd_stats(app_t *app)
{
    netstack_t *s = &app->stack;
    netdev_t *d = &app->dev;

    printf("\nlink layer\n");
    printf("  rx %llu packets / %llu bytes, tx %llu packets / %llu bytes\n",
           (unsigned long long)d->rx_packets, (unsigned long long)d->rx_bytes,
           (unsigned long long)d->tx_packets, (unsigned long long)d->tx_bytes);
    printf("  rx errors %llu, tx errors %llu\n",
           (unsigned long long)d->rx_errors,
           (unsigned long long)d->tx_errors);

    printf("\nip\n");
    printf("  rx %llu datagrams, tx %llu datagrams, dropped %llu\n",
           (unsigned long long)s->rx_ip, (unsigned long long)s->tx_ip,
           (unsigned long long)s->rx_dropped);

    printf("\narp\n");
    printf("  requests %llu, deferred datagrams %llu, entries %zu\n",
           (unsigned long long)s->arp_requests,
           (unsigned long long)s->arp_deferred, arp_count(&s->arp));

    printf("\nicmp\n");
    printf("  echo requests received %llu, replies sent %llu\n",
           (unsigned long long)s->icmp_echo_rx,
           (unsigned long long)s->icmp_echo_tx);

    uint64_t sent = 0, recv = 0, rtx = 0, segs = 0, dup = 0;
    int live = 0;

    printf("\ntcp\n");
    for (tcp_pcb_t *p = tcp_first(s); p; p = p->next) {
        sent += p->bytes_sent;
        recv += p->bytes_recv;
        rtx += p->bytes_retrans;
        segs += p->segs_sent;
        dup += p->dupacks_in;
        if (p->state != TCP_CLOSED)
            live++;
    }
    printf("  %d live control blocks\n", live);
    printf("  sent %llu bytes in %llu segments\n",
           (unsigned long long)sent, (unsigned long long)segs);
    printf("  received %llu bytes\n", (unsigned long long)recv);
    printf("  retransmitted %llu bytes, duplicate ACKs %llu\n",
           (unsigned long long)rtx, (unsigned long long)dup);
    printf("\n");
    fflush(stdout);
}

static void cmd_ifconfig(app_t *app)
{
    char ipb[INET_ADDRSTRLEN], nm[INET_ADDRSTRLEN], mb[24];

    printf("\n%s: flags=UP MTU=%u\n", app->dev.ifname, app->dev.mtu);
    printf("  type   : %s\n", app->dev.is_tap ? "TAP (ethernet frames)"
                                              : "TUN (IPv4 packets)");
    printf("  address: %s\n", ip_str(app->stack.laddr, ipb, sizeof ipb));
    printf("  netmask: %s\n", ip_str(app->stack.netmask, nm, sizeof nm));
    printf("  mac    : %s\n", eth_fmt_mac(app->dev.mac, mb, sizeof mb));
    printf("  rx %llu / tx %llu\n\n",
           (unsigned long long)app->dev.rx_packets,
           (unsigned long long)app->dev.tx_packets);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* command dispatch                                                   */
/* ------------------------------------------------------------------ */

static void handle_command(app_t *app, char *line)
{
    /*
     * tokenize() writes NULs over the separators, so keep a pristine copy for
     * commands whose payload is the whole rest of the line.
     */
    char raw[LINE_SIZE];
    snprintf(raw, sizeof raw, "%s", line);

    char *tok[8];
    int n = tokenize(line, tok, 8);
    if (!n)
        return;

    const char *cmd = tok[0];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "?")) {
        cmd_help();

    } else if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) {
        app->quit = true;

    } else if (!strcmp(cmd, "ifconfig")) {
        cmd_ifconfig(app);

    } else if (!strcmp(cmd, "stats")) {
        cmd_stats(app);

    } else if (!strcmp(cmd, "arp")) {
        cmd_arp(app);

    } else if (!strcmp(cmd, "sockets")) {
        cmd_sockets(app);

    } else if (!strcmp(cmd, "trace")) {
        log_level_t l = log_get_level();
        log_set_level(l >= LOG_LEVEL_TRACE ? LOG_LEVEL_INFO : LOG_LEVEL_TRACE);
        printf("packet tracing %s\n",
               log_get_level() == LOG_LEVEL_TRACE ? "on" : "off");
        fflush(stdout);

    } else if (!strcmp(cmd, "sock") && n >= 2) {
        int want = atoi(tok[1]);
        int i = 0;

        for (tcp_pcb_t *p = tcp_first(&app->stack); p; p = p->next, i++) {
            if (i == want) {
                app->peer = app->client = p;
                printf("selected socket %d\n", i);
                tcp_pcb_dump(p);
                break;
            }
        }
        fflush(stdout);

    } else if (!strcmp(cmd, "ping") && n >= 2) {
        uint32_t peer;
        if (inet_pton(AF_INET, tok[1], &peer) != 1) {
            printf("ping: '%s' is not an IPv4 address\n", tok[1]);
            fflush(stdout);
            return;
        }

        int count = (n >= 3) ? atoi(tok[2]) : 4;
        if (count < 1)
            count = 1;

        app->ping_count = count;
        ping_start(&app->stack, &app->ping, peer, 56, USSTACK_TTL_DEFAULT);
        app->ping_active = true;
        app->ping_next_send_ms = 0;
        app->ping_deadline_ms = (uint32_t)log_uptime_ms() + 10000;

        printf("PING %s: %d packets of 56 bytes\n", tok[1], count);
        fflush(stdout);

    } else if (!strcmp(cmd, "listen") && n >= 2) {
        uint16_t port = (uint16_t)atoi(tok[1]);

        tcp_pcb_t *l = tcp_new(&app->stack, 0);
        if (!l) {
            printf("listen: out of memory\n");
            fflush(stdout);
            return;
        }
        if (tcp_bind(l, port) < 0) {
            printf("listen: port %u already in use\n", port);
            fflush(stdout);
            return;
        }
        if (tcp_listen(l) < 0) {
            printf("listen: failed\n");
            fflush(stdout);
            return;
        }

        app->listener = l;
        printf("listening on port %u; use 'accept' when a peer arrives\n",
               port);
        fflush(stdout);

    } else if (!strcmp(cmd, "accept")) {
        tcp_pcb_t *c = tcp_accept(app->listener);
        if (!c) {
            printf("accept: no connection waiting\n");
            fflush(stdout);
            return;
        }
        app->peer = c;
        tcp_pcb_dump(c);
        printf("accepted\n");
        fflush(stdout);

    } else if (!strcmp(cmd, "connect") && n >= 3) {
        uint32_t raddr;
        if (inet_pton(AF_INET, tok[1], &raddr) != 1) {
            printf("connect: '%s' is not an IPv4 address\n", tok[1]);
            fflush(stdout);
            return;
        }

        uint16_t port = (uint16_t)atoi(tok[2]);
        tcp_pcb_t *p = tcp_connect(&app->stack, raddr, port);
        if (!p) {
            printf("connect: failed\n");
            fflush(stdout);
            return;
        }

        app->client = p;
        printf("connecting to %s:%u from local port %u\n",
               tok[1], port, p->lport);
        fflush(stdout);

    } else if (!strcmp(cmd, "send")) {
        tcp_pcb_t *p = current_conn(app);
        if (!p) {
            printf("send: no open connection\n");
            fflush(stdout);
            return;
        }

        /* The payload is everything after the verb, spaces intact. */
        const char *sp = strchr(raw, ' ');
        const char *text = sp ? sp + 1 : "";
        if (!*text)
            text = "(empty)";

        int rc = tcp_send(p, text, strlen(text));
        if (rc < 0)
            printf("send: %s\n", strerror(-rc));
        else
            printf("queued %d byte(s)\n", rc);
        fflush(stdout);

    } else if (!strcmp(cmd, "recv")) {
        tcp_pcb_t *p = current_conn(app);
        if (!p) {
            printf("recv: no open connection\n");
            fflush(stdout);
            return;
        }

        uint8_t buf[4096];
        int rc = tcp_recv(p, buf, sizeof buf);

        if (rc < 0) {
            printf("recv: error %d (%s)\n", -rc, strerror(-rc));
        } else if (rc == 0) {
            printf("peer closed the connection\n");
        } else {
            printf("%d byte(s):\n", rc);
            for (int i = 0; i < rc; i++) {
                if (buf[i] == '\n')
                    putchar('\n');
                else if (isprint(buf[i]))
                    putchar(buf[i]);
                else
                    printf("\\x%02x", buf[i]);
            }
            putchar('\n');
        }
        fflush(stdout);

    } else if (!strcmp(cmd, "close")) {
        tcp_pcb_t *p = current_conn(app);
        if (!p) {
            printf("close: no open connection\n");
            fflush(stdout);
            return;
        }
        tcp_close(p);
        printf("close requested (state %s)\n", tcp_state_str(p->state));
        fflush(stdout);

    } else {
        printf("unknown command '%s' -- try 'help'\n", cmd);
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------ */
/* background work                                                    */
/* ------------------------------------------------------------------ */

static void on_icmp_reply(void *ctx, uint16_t id, uint16_t seq, size_t len)
{
    app_t *app = (app_t *)ctx;
    ping_on_reply(&app->stack, &app->ping, id, seq, len);
}

static void finish_ping(app_t *app, uint32_t now)
{
    /*
     * Anything still outstanding when the run ends was lost.  This is the only
     * place loss is accounted for, which keeps the arithmetic in one spot.
     */
    for (int i = 0; i < PING_MAX_INFLIGHT; i++)
        if (app->ping.slots[i].sent)
            app->ping_lost++;

    ping_report(&app->ping, app->ping_lost);
    app->ping_active = false;
    (void)now;
}

static bool ping_outstanding(const ping_ctx_t *ctx)
{
    for (int i = 0; i < PING_MAX_INFLIGHT; i++)
        if (ctx->slots[i].sent)
            return true;
    return false;
}

static void service_ping(app_t *app)
{
    if (!app->ping_active)
        return;

    uint32_t now = (uint32_t)log_uptime_ms();

    /*
     * Pace requests by the round-trip time of the previous one.  Without this
     * the whole count would go out in a single burst, which measures nothing
     * useful.
     */
    if ((uint32_t)app->ping.sent < (uint32_t)app->ping_count &&
        now >= app->ping_next_send_ms) {
        uint32_t interval = app->ping.last_rtt_ms
                          ? (uint32_t)app->ping.last_rtt_ms : 1000;
        ping_tick(&app->stack, &app->ping);
        app->ping_next_send_ms = now + interval;
    }

    bool done = (uint32_t)app->ping.sent >= (uint32_t)app->ping_count;

    if (done && !ping_outstanding(&app->ping)) {
        finish_ping(app, now);
        return;
    }

    if (now >= app->ping_deadline_ms) {
        finish_ping(app, now);
    }
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    options_t opt;

    if (!parse_options(argc, argv, &opt))
        return 1;

    log_init();
    log_set_level(opt.level);

    app_t *app = &g_app;

    if (netdev_open(&app->dev, opt.ifname, opt.ip, opt.netmask, opt.mtu,
                    opt.tap) < 0)
        return 1;
    app->dev_open = true;

    net_init(&app->stack, &app->dev);
    net_set_icmp_reply_hook(&app->stack, on_icmp_reply, app);

    if (opt.selftest) {
        int rc = netdev_selftest(&app->dev);
        net_shutdown(&app->stack);
        netdev_close(&app->dev);
        return rc;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    print_banner(app);

    uint8_t rxbuf[RX_BUF_SIZE];
    char line[LINE_SIZE];
    app->stdin_open = true;

    while (!app->quit && !g_interrupted) {
        /*
         * Wake for whichever comes first: a packet from the device, the
         * nearest TCP timer deadline, or console input.
         */
        int timeout = net_poll_timeout_ms(&app->stack);
        if (timeout > 200)
            timeout = 200;

        struct pollfd pfds[2];
        nfds_t nfds = 0;
        int dev_idx = -1, stdin_idx = -1;

        if (app->dev_open && app->dev.fd >= 0) {
            pfds[nfds].fd = app->dev.fd;
            pfds[nfds].events = POLLIN;
            dev_idx = (int)nfds++;
        }
        if (app->stdin_open) {
            pfds[nfds].fd = STDIN_FILENO;
            pfds[nfds].events = POLLIN;
            stdin_idx = (int)nfds++;
        }

        int rc = (nfds > 0) ? poll(pfds, nfds, timeout) : 0;

        if (rc < 0 && errno != EINTR) {
            log_error("poll: %s", strerror(errno));
            break;
        }

        if (rc > 0 && dev_idx >= 0 && (pfds[dev_idx].revents & POLLIN)) {
            int n = netdev_rx(&app->dev, rxbuf, sizeof rxbuf, 0);

            if (n > 0) {
                log_hexdump(LOG_LEVEL_TRACE, "raw rx", rxbuf, (size_t)n);
                net_rx(&app->stack, rxbuf, (size_t)n);
            } else if (n == 0) {
                log_error("tun: device closed, stopping");
                app->dev_open = false;
            }
        }

        /* Timers: retransmissions, persist probes, TIME-WAIT expiry. */
        net_tick(&app->stack);

        if (rc > 0 && stdin_idx >= 0 && (pfds[stdin_idx].revents & POLLIN)) {
            if (fgets(line, (int)sizeof line, stdin)) {
                size_t len = strlen(line);
                while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                handle_command(app, line);
            } else {
                /* EOF: stop polling stdin or the loop would spin on it. */
                app->stdin_open = false;
                printf("(stdin closed -- still running, ^C to quit)\n");
                fflush(stdout);
            }
        }

        service_ping(app);
    }

    printf("\nshutting down\n");
    net_shutdown(&app->stack);
    if (app->dev_open)
        netdev_close(&app->dev);
    return 0;
}