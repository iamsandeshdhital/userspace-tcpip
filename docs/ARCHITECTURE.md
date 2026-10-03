# Architecture

How a byte becomes a connection, and why the code is split the way it is.

## The shape of the thing

```
                 ┌──────────────────────────────────────────┐
   read()/write()│  main.c     event loop + console          │
        ▲        ├──────────────────────────────────────────┤
        │        │  net.c       framing, ARP, IP, transmit  │
        │        ├──────────────────────────────────────────┤
        │        │  tcp_socket.c  state machine, windows,   │
        │        │               timers, retransmission     │
        │        │  tcp.c        segment parse and build    │
        │        ├──────────────────────────────────────────┤
        │        │  ip.c  icmp.c  arp.c  ethernet.c         │
        │        │  checksum.c  ringbuf.c                   │
        │        ├──────────────────────────────────────────┤
        └────────│  tun.c       the ONLY file that knows   │
                 │             about the kernel             │
                 └──────────────────────────────────────────┘
```

`tun.c` is the entire kernel interface. Everything above it deals in byte
buffers, which is what makes the test suite possible: swap the device for a
capture buffer and the whole stack runs in memory.

## The receive path

A frame arrives from the device:

```
net_rx
  └─ TAP only: strip the 14-byte Ethernet header, check the destination MAC
       ├─ ethertype 0x0806 ─> arp_input
       │                       learn the sender's address (any sender, always)
       │                       answer a request for our own address
       │                       on learning: replay anything that was waiting
       └─ ethertype 0x0800 ─> ip_input
                               validate: version, IHL, total_length,
                                          header checksum, fragments
                               is the destination ours?
                               ├─ ICMP ─> echo request ─> echo reply
                               ├─ TCP  ─> tcp_input
                               └─ else ─> ICMP protocol unreachable
```

## The transmit path

A protocol module wants to send an IPv4 datagram:

```
tcp_output / icmp_send_*
  └─ ip_build        fill in the IPv4 header
     ip_finalize     set total_length, compute the header checksum
        └─ net_tx
           ├─ TUN:  write the bare datagram
           └─ TAP:  resolve the destination MAC via ARP
                    ├─ known?  prepend the Ethernet header, write
                    └─ unknown? broadcast a request and PARK the datagram
```

### Why the ARP queue matters

A TAP device is a real Ethernet endpoint, so before anything can be sent to a
neighbour its link-layer address must be known. On a cold cache that is not
true — and the first packet to a new host is a TCP SYN.

Dropping it would mean a client could never connect to a host it had not
already spoken to. So the datagram is parked in a short queue
(`net_pend_t` in `netstack_t`) and replayed by `net_arp_resolved()` the moment
the address arrives. Eight slots is plenty: anything queued is waiting on a
sub-millisecond ARP round trip, and TCP will retransmit anything that matters
far longer than that.

## TCP: the two buffer invariants

Everything in the protocol engine follows from two rules about buffers.

### 1. The send buffer is trimmed only on acknowledgement

`tx_buf` holds the bytes in the range

```
[ tx_base_seq , tx_base_seq + rb_used(tx_buf) )
```

Bytes leave the ring **only** when the peer acknowledges them. Two
consequences fall out of this for free:

- the offset of the next unsent byte is `snd_nxt - tx_base_seq`, so
  "how much is left to send" needs no separate cursor;
- every offset before that stays valid, which is why the retransmission queue
  can store a 32-bit offset into the ring instead of copying the payload.
  A queued range stays readable until it is acknowledged, and acknowledgement
  is exactly when it is dropped.

So a retransmission is: read the bytes back out of the ring at a known offset
and put them on the wire again. No duplicate storage, and no way for the two
copies to disagree.

### 2. The receive buffer's free space *is* the advertised window

`rcv_wnd` is not a number the code maintains; it is computed from
`rb_avail(&p->rx_buf)` every time a segment goes out:

```c
static uint16_t advertised_window(const tcp_pcb_t *p)
{
    uint32_t avail = rb_avail(&p->rx_buf);
    if (p->wscale_local == 0)
        return (uint16_t)MIN(avail, 0xFFFFu);
    uint32_t scaled = avail >> p->wscale_local;
    if (avail > 0 && scaled == 0) scaled = 1;   /* never round down to zero */
    return (uint16_t)MIN(scaled, 0xFFFFu);
}
```

Making the promise and keeping it the same expression is the point. There is
no way for the two to drift apart, because there is only one of them.

### The effective send window

What a sender may put on the wire is the smaller of two limits:

```c
MIN( peer's advertised window ,  our free send-buffer space )
```

The first is flow control. The second stops the stack accepting more data than
it could still retransmit if the path died.

## Sequence number arithmetic

Sequence numbers wrap. Every comparison therefore goes through RFC 1982
serial arithmetic rather than `<`:

```c
#define SEQ_LT(a, b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
```

This is why `tcp_socket.c` never compares sequence numbers directly. Any such
comparison would be correct for the first few packets and wrong after the
wrap.

## The retransmission queue

Each transmission gets an explicit entry:

```c
typedef struct tcp_txseg {
    uint32_t seq;        /* first sequence number          */
    uint32_t len;        /* payload length                 */
    uint8_t  flags;      /* SYN/FIN/PSH riding along       */
    uint32_t off;        /* offset into tx_buf.data        */
    uint32_t rtx_count;  /* retransmissions so far         */
    uint64_t sent_ms;    /* when this attempt went out     */
    uint64_t rto_ms;     /* this segment's own timeout     */
} tcp_txseg_t;
```

A SYN or FIN consumes one sequence number but no buffer byte, so the queue
tracks bytes in flight as `len + (SYN ? 1 : 0) + (FIN ? 1 : 0)`. `txq_bytes`
is what the window is checked against.

Keeping this metadata explicit rather than rescanning the send buffer is what
gives per-segment timers, exponential backoff, duplicate-ACK counting and
Karn's algorithm somewhere to live.

### The one rule about retransmitting

A retransmission must go out through `tcp_transmit()` — build the bytes, send
them — and **not** through `tcp_output()`, which also queues. Calling
`tcp_output()` from the retransmission path enqueues a second copy of a
segment that is already in the queue, which double-counts the bytes in flight
and grows the queue without bound. This was a real bug during development; see
`KNOWN_ISSUES.md`.

## Timers

The protocol engine never reads a clock. It asks the stack for the time, and
the stack asks the clock:

```c
uint64_t net_now(const netstack_t *s);   /* -> s->now_ms, or mono_ms() */
```

That single indirection is what lets the test suite advance time by fiat. A
retransmission timeout becomes an assertion instead of a `sleep()`.

| timer | purpose |
| --- | --- |
| `retransmit_deadline_ms` | oldest unacknowledged segment's RTO |
| `persist_deadline_ms` | probing for a zero window to reopen |
| `timewait_deadline_ms` | 2·MSL linger before the socket may go |

`tcp_next_timeout_ms()` reports the nearest of these, and the main loop uses it
as its `poll()` timeout, so an idle stack costs nothing.

### Zero windows are not congestion

If the peer advertises a zero window, the retransmission timer must **not**
treat the outstanding data as lost — retransmitting into a closed window only
wastes the peer's buffer and can deepen the stall. The timer backs off and the
persist timer takes over, sending a single byte periodically to provoke a
window update. The test suite checks this: a connection stalled on a zero
window performs zero retransmissions.

## Testability as a design constraint

Every I/O path is indirect:

```c
typedef void (*net_tx_hook_t)(void *ctx, const uint8_t *frame, size_t len);
```

With a real device attached, `net_tx` writes to the TUN fd. With a hook
attached, it appends to a buffer or enqueues onto the virtual wire. Nothing
else changes — same code path, same checksums, same state machine. That is why
the integration test can push 48 KiB through a link that drops and duplicates
frames and still assert the result is byte-exact.