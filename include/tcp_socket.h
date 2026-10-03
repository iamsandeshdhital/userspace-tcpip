/*
 * tcp_socket.h -- TCP protocol control block and state machine.
 *
 * References: RFC 793 (protocol), RFC 1122 (requirements), RFC 7323 (window
 * scaling), RFC 6298 (retransmission timers), RFC 5681 (fast retransmit).
 *
 * Sequence-number variables, per RFC 793 section 3.3:
 *
 *   SND.UNA  first unacknowledged sequence number   (snd_una)
 *   SND.NXT  next sequence number to be sent          (snd_nxt)
 *   SND.WND  peer's advertised receive window         (snd_wnd)
 *   RCV.NXT  next sequence number expected             (rcv_nxt)
 *   RCV.WND  our advertised receive window             (computed from rx_buf)
 *
 * Buffer invariants -- these two rules are what make the design work:
 *
 *   1. tx_buf holds the bytes in [tx_base_seq, tx_base_seq + rb_used()).
 *      Bytes are removed ONLY when the peer acknowledges them.  Therefore
 *      (snd_nxt - tx_base_seq) is exactly the offset of the next unsent byte,
 *      and every offset < that stays valid for retransmission.
 *
 *   2. rx_buf holds the bytes the peer has sent us that we have not yet
 *      consumed.  Its free space IS RCV.WND: advert1ising more than we can
 *      store is how you get flow control wrong, so the two are the same
 *      number by construction.
 *
 * One more subtlety: a SYN or FIN occupies one sequence number but no buffer
 * byte.  So `txq_bytes` counts payload bytes plus one for each SYN/FIN still
 * unacknowledged, while tx_buf advances only for payload.
 */
#ifndef USSTACK_TCP_SOCKET_H
#define USSTACK_TCP_SOCKET_H

#include "common.h"
#include "tcp.h"
#include "ringbuf.h"

#include <errno.h>

/*
 * netstack_t is owned by net.h.  Only forward-declared here so that the two
 * headers do not include each other; the protocol engine takes the stack as
 * `struct netstack *` and the hot paths take a plain void * so that the
 * protocol layer never needs the device layer's type.
 */
struct netstack;

/* Connection states. */
typedef enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
    TCP_STATE_MAX
} tcp_state_t;

/* Control-block flags. */
#define TF_PASSIVE      (1u << 0)  /* connection came from a LISTEN socket   */
#define TF_SENT_FIN     (1u << 1)  /* our FIN has gone out and is unacked   */
#define TF_GOT_FIN      (1u << 2)  /* peer's FIN received; app has not read */
#define TF_NEED_FIN     (1u << 3)  /* app closed, FIN not yet sent           */
#define TF_TIMESTAMP    (1u << 4)  /* timestamps negotiated                  */
#define TF_FAST_RETRANS (1u << 5)  /* currently fast-retransmitting          */

/*
 * One entry of the retransmission queue, ordered oldest (lowest sequence
 * number) first.  Keeping explicit metadata -- rather than rescanning the
 * send buffer -- gives per-segment timers, exponential backoff and
 * duplicate-ACK counting somewhere to live.
 */
typedef struct tcp_txseg {
    struct tcp_txseg *next;
    uint32_t seq;        /* sequence number of the first byte            */
    uint32_t len;        /* payload length                               */
    uint8_t  flags;      /* SYN/FIN/PSH carried with this data           */
    uint32_t off;        /* offset of the payload within tx_buf.data     */
    uint32_t rtx_count;  /* retransmissions so far                       */
    uint64_t sent_ms;    /* when the current attempt went out            */
    uint64_t rto_ms;     /* per-segment retransmission timeout           */
} tcp_txseg_t;

/* A buffered out-of-order segment awaiting its missing prefix. */
typedef struct tcp_ooo {
    struct tcp_ooo *next;
    uint32_t seq;
    uint32_t len;
    uint8_t *data;       /* owned copy of the payload */
} tcp_ooo_t;

/* Duplicate ACKs needed before fast retransmit (RFC 5681). */
#define TCP_MAX_DUP_ACK 3

struct tcp_pcb {
    struct tcp_pcb *next;          /* global control-block list */
    struct tcp_pcb *accept_next;   /* listener's pending-accept chain */
    struct netstack *stack;        /* owning stack; every timer/output needs it */

    /* Four-tuple identity.  Ports in host order, addresses network order. */
    uint16_t lport;
    uint16_t rport;
    uint32_t laddr;
    uint32_t raddr;

    tcp_state_t state;
    uint32_t    flags;

    /* Sequence variables. */
    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t snd_wnd;        /* peer's window, already scaled (RFC 7323) */

    uint32_t rcv_nxt;        /* next sequence number expected from peer */

    /* Options. */
    uint16_t mss_local;      /* maximum payload we are willing to receive */
    uint16_t mss_remote;     /* maximum payload the peer will accept       */
    uint8_t  wscale_local;   /* shift applied to OUR advertised window     */
    uint8_t  wscale_remote;  /* shift applied to the peer's window         */

    /* Buffers. */
    ringbuf_t tx_buf;
    ringbuf_t rx_buf;
    uint32_t  tx_base_seq;   /* sequence number of tx_buf.data[0] */

    /* Retransmission queue. */
    tcp_txseg_t *txq_head;
    tcp_txseg_t *txq_tail;
    uint32_t     txq_bytes;  /* sequence-space bytes currently unacked */

    /* Receive reassembly. */
    tcp_ooo_t *ooo_head;

    /* RTT estimation and retransmission timing (RFC 6298). */
    uint64_t srtt_ms;
    uint64_t rttvar_ms;
    uint64_t rto_ms;
    bool     rtt_sampled;

    /* Timers.  0 means "not running". */
    uint64_t retransmit_deadline_ms;
    uint64_t persist_deadline_ms;
    uint64_t timewait_deadline_ms;
    uint64_t created_ms;

    /* Fast retransmit bookkeeping. */
    uint32_t dupack_count;
    uint32_t recover;        /* snd_nxt when the loss was detected */
    uint8_t  next_ack;

    /* Statistics and application-visible status. */
    int      err;            /* sticky: ECONNRESET, EPIPE, ... */
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint64_t bytes_retrans;
    uint64_t segs_sent;
    uint64_t segs_retrans;
    uint64_t dupacks_in;

    /* Listener bookkeeping. */
    struct tcp_pcb *accept_head;
    struct tcp_pcb *accept_tail;
};

/* ---------------- application API (all non-blocking) ---------------- */

/* Create an unbound control block.  `lport` of 0 means "any". */
tcp_pcb_t *tcp_new(struct netstack *s, uint16_t lport);

/* Unlink from the stack and release.  net_shutdown() walks the list with this. */
void tcp_pcb_destroy(tcp_pcb_t *p);

/* Claim a local port.  Returns 0, or -EADDRINUSE. */
int tcp_bind(tcp_pcb_t *p, uint16_t lport);

/* Start listening.  Returns 0, or -EADDRINUSE/-EINVAL. */
int tcp_listen(tcp_pcb_t *p);

/* Initiate an active open.  Returns the pcb, or NULL on failure. */
tcp_pcb_t *tcp_connect(struct netstack *s, uint32_t raddr, uint16_t rport);

/* Pop an established child of a listener, or NULL if none is pending. */
tcp_pcb_t *tcp_accept(tcp_pcb_t *listener);

/*
 * Close.  Sends a FIN if the connection is still writable, and tears the
 * socket down once the exchange completes.
 */
void tcp_close(tcp_pcb_t *p);

/* Queue up to `len` bytes.  Returns bytes accepted, or a negative errno. */
int tcp_send(tcp_pcb_t *p, const void *data, size_t len);

/* Copy up to `len` received bytes out.  Returns 0 on orderly shutdown. */
int tcp_recv(tcp_pcb_t *p, void *buf, size_t len);

/* Is there room in the send buffer right now? */
size_t tcp_send_space(const tcp_pcb_t *p);
size_t tcp_recv_avail(const tcp_pcb_t *p);

/* ---------------- protocol engine ---------------- */

/*
 * Hand a TCP segment to the protocol engine.  The enclosing IP addresses are
 * passed explicitly because the segment's own header does not carry them, yet
 * they are needed both to verify the checksum pseudo-header and to identify
 * the connection.
 */
void tcp_input(void *stack, uint32_t src_ip, uint32_t dst_ip,
               const uint8_t *seg, size_t len);

void tcp_send_pending(void *stack, tcp_pcb_t *p);
void tcp_timer_tick(void *stack, uint64_t now_ms);
int  tcp_next_timeout_ms(void *stack);

/* Iteration for diagnostics: first/last control block in the stack. */
tcp_pcb_t *tcp_first(struct netstack *s);

/* ---------------- diagnostics ---------------- */

const char *tcp_state_str(tcp_state_t s);
void        tcp_pcb_dump(const tcp_pcb_t *p);

#endif /* USSTACK_TCP_SOCKET_H */