# Known issues

Honest accounting of what is wrong, what is missing, and what was fixed during
development. Given that **this code has never been compiled**, assume the
list of latent bugs is longer than what is written here.

---

## Found and fixed while writing

These were caught by re-reading the code while writing the tests, not by
running it.

### 1. Retransmissions duplicated their queue entry — *serious*

`tcp_output()` did three things: build and send the segment, advance
`SND.NXT`, and enqueue it for retransmission. Both the timeout path and the
fast-retransmit path called it, so every retransmission pushed a **second**
entry for a segment already in the queue.

Consequences: `txq_bytes` double-counted, so the effective send window closed
by half on each retry; the queue grew without bound; and the duplicated entry
would be retired only when its sequence number was acknowledged, keeping a
stale `off` alive.

Fixed by splitting the function. `tcp_transmit()` builds and sends.
`tcp_output()` calls it, then does the bookkeeping. Retransmissions now go
through `tcp_transmit()` and update the existing entry in place.

### 2. `seq_acceptable` rejected every out-of-order segment — *serious*

The implementation only handled the RFC 793 cases where a segment starts at or
before `RCV.NXT`. A segment entirely ahead of `RCV.NXT` but inside the window
was rejected — and that segment is what *out-of-order delivery looks like*.

This broke the two features that depend on it. Reassembly could never begin,
because the first out-of-order segment was discarded before reaching the
queue. And fast retransmit could never trigger from data, because duplicate
ACKs only arise when out-of-order segments are accepted.

Fixed by adding the missing case. All four RFC cases are now covered
explicitly and commented.

### 3. ICMP echo replies were four bytes too long and misaligned the payload

`icmp_len` arrives as the length of the whole ICMP message, but the code
treated it as a payload length and added `ICMP_HDR_LEN` again — inflating
every reply by four bytes, and copying four bytes too many from the request.
The checksum verified, so the corruption would not have been caught by
validation; it would have surfaced as a corrupted reply payload.

Fixed by treating `icmp_len` consistently as the whole message.

### 4. The retransmission timer stayed armed after the queue emptied

The timer was armed once and cleared only when it fired with nothing
outstanding. So between the handshake and the first data segment it was still
pointing at a deadline derived from the SYN. When data was then sent, the
timer was not re-armed, and the RTO was measured from the wrong instant —
firing early or late depending on timing.

Fixed: `txq_ack()` now re-points the deadline at the new queue head, or clears
it, and `tcp_output()` arms the timer only when the segment it just queued
became the head.

### 5. The accept queue and the global list shared a link field

A passive connection was appended to its listener's accept queue with
`p->accept_tail->next = c` and then linked into the stack's control-block list
with `pcb_link()`, which overwrote `c->next`. The two lists corrupted each
other: `accept()` returned connections that were not in the queue, and
`net_shutdown()` freed the wrong objects.

Fixed by adding a separate `accept_next` field.

### 6. Address derivation read out of bounds

`tcp_input()` derived the peer address from the segment buffer with
`rd32_be(buf - 12)` — reading four bytes before the segment, into whatever the
caller happened to have on the stack, and then assigning those values as
connection identity.

Fixed properly: `tcp_input()` now takes `src_ip` and `dst_ip` from the
enclosing IPv4 header, which is the only place they legitimately exist. They
are needed both to verify the checksum pseudo-header and to identify the
connection.

### 7. The first ACK of the handshake counted as a duplicate ACK

A pure ACK that acknowledged nothing and had nothing outstanding — the third
leg of the handshake, specifically — incremented `dupack_count`. With a
pre-existing count this could trigger fast retransmit on a connection that had
lost nothing.

Fixed by requiring something to be outstanding before an ACK may be counted as
a duplicate.

---

## Still latent

These are suspected from inspection, not observed.

### TCP does not check that the peer's advertised MSS is sane

`negotiate_options()` uses the peer's MSS as given. A peer announcing an MSS
below one TCP header's worth would produce zero-length data segments and a
send loop that never advances. RFC 1122 requires a floor of 256.

### No congestion control

There is a send window but no `cwnd`. Without one the stack will happily fill a
congested path as fast as the peer's window allows. This is the single largest
functional gap relative to real TCP; see `PROTOCOL_NOTES.md`.

### `advertised_window` rounds a small window up to 1 rather than to 65535

With `wscale_local == 7` and only a few hundred bytes of buffer free, the
advertised value becomes 1. The peer scales it back to 128 and stalls. Not a
correctness bug — just severe under-utilisation at the tail of a transfer, and
a window of 1 is close enough to a deadlock that it is worth fixing properly
(advertise the scale only once the buffer can justify it).

### TIME-WAIT sockets match incoming segments

`tcp_find_pcb()` deliberately does not skip TIME-WAIT, so that a retransmitted
FIN is re-acknowledged and the timer restarted. But a data segment arriving
for a socket in TIME-WAIT will also be acknowledged, which should produce a
RST instead. Low impact; noted rather than fixed.

### Fragmented IP datagrams are dropped without an ICMP response

`ip_validate()` returns `IP_ERR_FRAGMENT` and the packet is discarded. An RFC
1122 host should send ICMP Fragmentation Needed instead. Out of scope given
that DF is set on everything sent.

### No route table

A packet whose destination is not local is dropped, and there is no forwarding.
Appropriate for an endpoint stack, but it means `net.c` will silently drop
anything aimed elsewhere.

### The pending-ARP queue can fill up

Eight slots. If eight datagrams to distinct unresolvable hosts are queued, the
ninth is dropped with a warning. A real implementation would keep one queue per
destination, or resolve on a timer.

### `tcp_recv` sends a window update on every read

Conservative and correct, but a chatty caller produces an ACK per call. A
delayed-ACK or window-update-coalescing scheme would be better.

### Stack buffers are large on the heap-light paths

`tcp_output()` puts a 1500-byte segment buffer and a 1500-byte packet buffer on
the stack, and the retransmission paths add another 1500. Three kilobytes of
stack per call is fine for a dedicated thread and worth revisiting if this ever
runs in a small-stack context.

---

## Not implemented

Deliberately out of scope; listed so nobody assumes otherwise.

- Congestion control (Reno, CUBIC, anything)
- Selective acknowledgement in recovery — SACK is permitted in the handshake
  but no SACK blocks are sent
- ECN / explicit congestion notification
- IPv6
- UDP
- IP fragmentation and reassembly
- IP forwarding
- TLS, and therefore any real HTTP or HTTPS
- Timestamp option echo: the value is echoed back verbatim rather than carrying
  a real echo of the peer's timestamp