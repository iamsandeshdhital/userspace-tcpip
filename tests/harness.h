/*
 * harness.h -- an in-memory virtual network for the tests.
 *
 * Two stacks are wired back to back through a queue of frames, with optional
 * packet loss and duplication.  That makes it possible to test the whole
 * protocol stack -- Ethernet, ARP, IP, TCP -- with no kernel device, no root,
 * and full control over time, which is what lets the retransmission tests be
 * deterministic instead of timing-dependent.
 */
#ifndef USSTACK_TEST_HARNESS_H
#define USSTACK_TEST_HARNESS_H

#include "net.h"
#include "tcp_socket.h"

#define WIRE_MAX_QUEUE 256
#define WIRE_FRAME_MAX (USSTACK_MTU_DEFAULT + ETH_HDR_LEN + 16)

typedef struct {
    uint8_t data[WIRE_FRAME_MAX];
    size_t  len;
    int     dst;          /* 0 = deliver to stack A, 1 = stack B */
} wire_pkt_t;

/* One endpoint's transmit hook context. */
typedef struct {
    struct wire *w;
    int          side;
} wire_side_t;

typedef struct wire {
    netstack_t  sa, sb;
    netdev_t    dev_a, dev_b;      /* unused; the stacks run device-less */

    uint32_t    ip_a, ip_b;
    uint32_t    mask;
    uint8_t     mac_a[6], mac_b[6];

    wire_side_t side_a, side_b;

    wire_pkt_t  q[WIRE_MAX_QUEUE];
    int         head;
    int         count;

    int         drop_next;         /* frames to discard on arrival at the wire */
    int         drop_toward_b;     /* 1 = only drop frames heading to B */
    int         dup_next;          /* frames to deliver twice */

    uint64_t    now_ms;
    uint32_t    delivered;
    uint32_t    dropped;
} wire_t;

/* Set up two stacks (A = 10.0.0.1, B = 10.0.0.2 by default) and the wire. */
void     wire_init(wire_t *w, bool tap);
void     wire_free(wire_t *w);

/* Move time forward, running timers on both stacks at each step. */
void     wire_advance(wire_t *w, uint64_t ms, uint32_t step_ms);

/* Deliver everything currently queued.  Returns the number of frames moved. */
uint32_t wire_flush(wire_t *w);

/* Pump the wire and the timers together until `deadline_ms`. */
uint32_t wire_run_until(wire_t *w, uint64_t deadline_ms, uint32_t step_ms);

/* Inject loss/dup. */
void     wire_drop_next(wire_t *w, int frames, int toward_b);
void     wire_dup_next(wire_t *w, int frames);

/* Direct injection: hand a frame to one stack as if it had been received. */
void     wire_inject(wire_t *w, int side, const uint8_t *frame, size_t len);

/* Look up the first control block matching a state. */
tcp_pcb_t *wire_find_state(netstack_t *s, tcp_state_t st);
tcp_pcb_t *wire_find_conn(netstack_t *s, uint16_t rport);

/* ---------------- single-stack helpers ---------------- */

/* A device-less stack with a capture buffer standing in for the NIC. */
typedef struct {
    netstack_t *stack;
    uint8_t     buf[32][WIRE_FRAME_MAX];
    size_t      len[32];
    size_t      count;
} capture_t;

/*
 * Build a complete IPv4 datagram carrying TCP, with a correct header checksum
 * and a correct TCP checksum over the pseudo-header.  Used to feed crafted
 * segments into a stack.
 */
size_t harness_tcp_packet(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                          uint16_t sport, uint16_t dport,
                          uint32_t seq, uint32_t ack,
                          uint8_t flags, uint16_t window,
                          const void *payload, size_t len);

/* The same, for an ICMP echo request. */
size_t harness_icmp_echo(uint8_t *out, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t id, uint16_t seq, size_t payload_len);

/* TCP checksum over a pseudo-header plus a segment, for verification. */
uint16_t harness_tcp_csum(uint32_t src_ip, uint32_t dst_ip,
                          const uint8_t *seg, size_t len);

/* Route a stack's output into a capture buffer instead of a device. */
void harness_attach_capture(netstack_t *s, capture_t *c);

/* Assert helpers. */
extern int g_test_failures;
extern int g_test_assertions;
extern const char *g_current_test;

void test_fail(const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_test_assertions++;                                                 \
        if (!(cond))                                                         \
            test_fail(__FILE__, __LINE__, "CHECK failed: %s", #cond);         \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                       \
    do {                                                                     \
        g_test_assertions++;                                                 \
        long long _a = (long long)(actual);                                  \
        long long _e = (long long)(expected);                                \
        if (_a != _e)                                                        \
            test_fail(__FILE__, __LINE__,                                    \
                      "%s: expected %lld, got %lld", #actual, _e, _a);        \
    } while (0)

#define CHECK_EQ_HEX(actual, expected)                                       \
    do {                                                                     \
        g_test_assertions++;                                                 \
        unsigned long long _a = (unsigned long long)(actual);                \
        unsigned long long _e = (unsigned long long)(expected);              \
        if (_a != _e)                                                        \
            test_fail(__FILE__, __LINE__,                                    \
                      "%s: expected 0x%llx, got 0x%llx", #actual, _e, _a);    \
    } while (0)

#define CHECK_STR(actual, expected)                                          \
    do {                                                                     \
        g_test_assertions++;                                                 \
        if (strcmp((actual), (expected)) != 0)                                \
            test_fail(__FILE__, __LINE__, "%s: expected \"%s\", got \"%s\"", \
                      #actual, (expected), (actual));                        \
    } while (0)

/* Test entry points. */
void test_checksum(void);
void test_ringbuf(void);
void test_ip(void);
void test_arp(void);
void test_icmp(void);
void test_tcp_header(void);
void test_tcp_handshake(void);
void test_tcp_teardown(void);
void test_tcp_retransmit(void);
void test_tcp_out_of_order(void);
void test_tcp_window(void);
void test_tcp_loopback(void);

#endif /* USSTACK_TEST_HARNESS_H */