# Protocol notes

The decisions worth explaining, with RFC references. Where something is a
deliberate simplification it says so, and why.

---

## Checksums (RFC 1071)

The Internet checksum is the one's complement of the one's complement sum of
the data read as 16-bit big-endian words. Three properties are relied on:

**Addition is commutative and associative.** So a checksum can be accumulated
incrementally across buffers that live in different places. TCP needs exactly
this: a 12-byte pseudo-header followed by a segment in a different buffer.

**An odd trailing byte is padded on the right.** Implemented by holding the
lone byte in `csum_state_t.odd` and combining it with the *next* chunk's first
byte, so chunking never changes the answer. The test suite checks exactly that,
by summing the same buffer in several different chunkings.

**Verification re-runs the sum with the checksum field in place.** A correct
packet folds to `0xFFFF`, which is `0` after complementing. That is what
`csum16_verify()` tests.

A checksum of zero must go out as `0xFFFF`, because `0x0000` in the IPv4 header
means "no checksum". `csum_final()` performs that substitution.

The test suite checks the RFC 1071 worked example (`00 01 f2 03 f4 f5 f6 f7` →
`0x220d`) rather than only checking the implementation against itself, which
would pass just as happily if the whole thing were wrong.

## TCP checksum pseudo-header

```
  +--------+--------+--------+--------+
  | source address        (4)      |
  +--------+--------+--------+--------+
  | destination address   (4)      |
  +--------+--------+--------+--------+
  | zero  | protocol     (1)  (1)  |
  +--------+--------+--------+--------+
  | TCP length            (2)      |
  +--------+--------+--------+--------+
```

Including the addresses and protocol means a segment cannot be replayed against
a different connection, or a TCP segment injected into some other protocol's
stream. `harness_tcp_csum()` in the tests verifies that changing either address
changes the checksum, which is the entire point of the construct.

The addresses are not in the segment, so `tcp_input()` receives them from the
enclosing IPv4 header. They are needed for both the checksum and the four-tuple
lookup.

## Sequence number arithmetic (RFC 1982)

Sequence numbers are 32 bits and wrap. A comparison like `seq < rcv_nxt` is
correct until the wrap, then silently wrong. Every comparison goes through:

```c
#define SEQ_LT(a, b)  ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <  0)
```

Taking the difference as a signed 32-bit value gives the right answer for any
distance below 2^31, which RFC 1982 guarantees as long as the window never
exceeds that — true here, since the buffers are 64 KiB.

`SEQ_GT`, `SEQ_LEQ` and `SEQ_GEQ` are the same trick. `tcp_socket.c` uses
these and nothing else for sequence comparisons.

## Window scaling (RFC 7323)

A 16-bit window caps a connection at 64 KiB of unacknowledged data, which caps
throughput at `64 KiB / RTT`. At 40 ms round-trip time that is about 13 Mbit/s
— a hard ceiling no amount of bandwidth helps with.

Scaling lets a receiver advertise more than 65535 by sending
`real_window >> shift`, and the sender recovers the real figure by shifting
left. Both sides advertise a shift of 7, giving a ceiling of 64 KiB << 7 = 8
MiB, even though the buffers only ever hold 64 KiB.

Three rules the implementation follows:

- **Only the SYN may carry the option.** An offer in any later segment is
  ignored (section 2.3).
- **The advertised value is derived from buffer space**, never tracked
  separately. See `ARCHITECTURE.md`.
- **A non-empty buffer must never be advertised as zero.** A zero window tells
  the peer to stop; if the peer is also waiting to read, that deadlocks.

A shift count above 14 is clamped, since the field is 4 bits and RFC 7323
caps the useful range.

## Retransmission timing (RFC 6298)

```
  first sample:   SRTT = R,  RTTVAR = R/2
  later samples:  RTTVAR = (1-β)·RTTVAR + β·|SRTT − R|
                  SRTT   = (1-α)·SRTT   + α·R
  timeout:        RTO = SRTT + max(G, K·RTTVAR)      K = 4, G = 1ms
```

Clamped to a 200 ms floor and a 60 s ceiling. On each retransmission the
per-segment timeout doubles, up to that ceiling.

### Karn's algorithm

Only a segment that has never been retransmitted yields an RTT sample. Timing a
retransmission measures the acknowledgement of the *retry* while attributing it
to the original, which produces an RTO that is wrong precisely when the path is
already misbehaving.

So `txq_ack()` samples only from entries with `rtx_count == 0`, and only the
first sample ever taken. This is why the timeout lives on each queue entry
rather than on the connection: entries can age independently.

The cost is that a connection whose every segment was retransmitted never
learns its RTT and stays at the initial value. That is the deliberate
conservative choice.

### The initial value is not 3 seconds

RFC 6298 suggests `RTO = 3` seconds initially. That is far too slow for a local
network or a modern path with per-packet reordering. The stack starts at 1
second and quickly converges via the estimator.

## Fast retransmit (RFC 5681)

Three duplicate ACKs indicate loss rather than reordering: four segments have
arrived out of order, and waiting for a fourth ACK to arrive before the sender
concludes otherwise would defeat the point.

Three ACKs trigger an immediate resend of the oldest unacknowledged segment
without consulting the timer. Each further duplicate ACK while in fast recovery
sends one more segment, since it is evidence that another segment reached the
peer.

**This only works if out-of-order segments are accepted.** That was the subject
of bug #2 in `KNOWN_ISSUES.md`: while `seq_acceptable()` rejected anything
ahead of `RCV.NXT`, no duplicate ACKs could ever be generated and fast
retransmit could never fire from data at all.

`recover` records `SND.NXT` at the moment loss is detected, so recovery exits
once new data has been sent past the loss point.

## Zero windows and the persist timer

A zero window means the receiver has no buffer space. It is **flow control,
not congestion**, and the two must be treated differently:

- Treating it as loss means retransmitting into a closed window, which wastes
  the peer's buffer and can make the stall worse.
- Treating it as normal means waiting forever if the peer's application never
  reads.

The resolution is a persist timer: when the window is zero, the retransmission
timer backs off and the persist timer sends a single byte periodically. The
peer's acknowledgement reveals whether the window has reopened. A zero-length
probe would elicit no useful information, so one byte is sent when there is
data to send.

This is the one place where the stack deliberately violates the "never
retransmit into a closed window" rule, and only to discover that the window is
still closed.

## Out-of-order reassembly

Out-of-order segments go on a singly-linked list sorted by sequence number,
each holding an owned copy of its payload.

When in-order data arrives it may have filled a gap, so `ooo_drain()` walks the
list and moves anything now starting at `RCV.NXT` into the receive buffer. It
also handles three cases that are easy to get wrong:

- a segment entirely behind `RCV.NXT` is discarded;
- a segment straddling `RCV.NXT` is trimmed, with the stale prefix removed by
  `memmove`;
- a segment that only partly fits is kept queued with the remainder, rather than
  being truncated and lost.

Overlapping new segments are dropped if already covered. This is not full
RFC 793 reassembly with per-sequence holes; it is a compact list that is
correct for the cases that occur and does not implement the specified
overwrite-preference rules.

## RST generation (RFC 793 section 3.10.7.1)

A segment that matches no connection must be answered, or the peer waits
forever:

- If the segment carried an **ACK**, the RST is sent **without** an ACK, with
  `SEQ = SEG.ACK`. The peer's ACK number is a sequence number we can use; ours
  would be meaningless because no connection exists.
- Otherwise the RST is sent **with** an ACK, acknowledging
  `SEG.SEQ + SEG.LEN`. There is nothing to echo, so we acknowledge the segment
  instead.

A segment that *is* a RST never gets a RST in reply — answering would risk a
reset storm.

## Retransmission budget

After twelve retransmissions of the same segment the connection is declared
dead: an RST is sent and the socket is torn down with `ETIMEDOUT`. With the RTO
starting at 200 ms and doubling to a 60 s ceiling, this takes several minutes on
a truly dead path. That is the right trade for a protocol whose job is to
deliver data reliably, and the wrong one for a responsive application; the
value is a single constant, `TCP_MAX_RETRANSMITS`.

## Deliberate simplifications

### Immediate ACKs, not delayed

RFC 5681 asks for a delayed ACK on most segments and an immediate one every
second segment or on out-of-order arrival. This stack acknowledges immediately.

Correctness does not need the delay, and an immediate ACK keeps the receive
path obvious to follow, which matters more in code whose purpose is to be read.
The cost is real: roughly twice the ACK traffic on a bulk transfer. The receive
path is the natural place to add it.

### The timestamp option is a stub

Timestamps are negotiated and sent, and the value is echoed back verbatim in
`TSecr` rather than carrying the peer's actual timestamp. Real timestamps drive
PAWS (RFC 7323 section 5.4), which defends against old duplicate segments
wrapping the sequence space. Without that protection the stack is more
vulnerable to a blind injection attack than a modern TCP implementation.

### No congestion control

There is a send window and no `cwnd`. The stack will fill the path as fast as
the peer's window and its own buffer allow.

This is the largest gap. Congestion control is not a detail of TCP, it is most
of why TCP is the protocol that shaped the internet. A sender with no `cwnd`
behaves like a UDP flood from its own point of view. Reno is around 60 lines
(slow start, congestion avoidance, fast recovery, multiplicative decrease);
CUBIC is a few hundred more. Until one exists, treat throughput numbers from
this stack as meaningless.

### SACK is permitted but never sent

The SYN offers SACK-permitted and the option is parsed, but no SACK blocks
appear in data segments. Recovery therefore relies on cumulative
acknowledgements alone, which is correct but slower with reordering — a single
lost segment forces everything after it to be resent.

### No IP fragmentation

DF is set on every datagram sent, and fragments are refused on receipt. MSS
negotiation keeps segments within the path MTU, so this is workable on a
path where fragmentation is not needed. It is not sufficient across a path
that genuinely requires it, and no ICMP Fragmentation Needed is sent.