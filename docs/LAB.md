# Lab

Experiments to run against the console once this builds and passes `make test`.
Each one should be checked with `tcpdump` so you are comparing your
implementation against the kernel's rather than against your assumptions.

```sh
sudo tcpdump -i tap0 -n -e -vvv
```

---

## 1. Does the device even work?

```sh
sudo ./usstack --selftest
sudo tcpdump -i tap0 -n -e -vvv
```

Expect one Ethernet frame carrying a bare SYN to `10.0.0.1:9`, and — because the
kernel still owns the device — an RST coming back from the kernel's own TCP.

If nothing appears, `/dev/net/tun` is missing or you are not root. Check
`lsmod | grep tun`.

## 2. Watch the three-way handshake

```sh
sudo ./usstack -L 4          # trace: every segment, hexdumped
# then:
listen 8080
```

From another terminal:

```sh
python3 -c "
import socket
s = socket.create_connection(('10.0.0.2', 8080))
s.sendall(b'hello from the kernel\n')
print(s.recv(100))
"
```

Compare against `tcpdump -i tap0 -n -e -vvv`. Check:

- the SYN carries MSS, SACK-permitted, timestamps and window scale
- `win` in the SYN-ACK is small (about 512) because the window is scaled by 7
- the sequence numbers are not 0, 1, 2 — they are randomised
- the window scale is *not* present on the ACK

Turn on `trace` in the console and confirm your own hexdump of the SYN-ACK
matches `tcpdump`'s byte for byte.

## 3. Ping

```sh
ping 10.0.0.2 4
```

Check that each request is echoed with `id` and `seq` intact and the payload
unchanged. Then compare against the kernel:

```sh
sudo ./usstack --tun --iface tun9 --addr 10.9.0.1
# and in another terminal, ping 10.9.0.1 from the host
```

Note the difference in the generated ICMP: yours is fixed-size and predictable,
whereas the kernel's varies its payload to avoid fingerprinting.

## 4. Sliding window — watch it close

Send a large file from the kernel side and watch your receive window in
`tcpdump`:

```sh
dd if=/dev/zero bs=1k count=500 | nc 10.0.0.1 8080
```

Then type `recv` repeatedly in your console. Observe:

- `win` in the incoming segments shrinking toward zero as your buffer fills
- your ACK's `win` jumping back up each time you read
- `sockets` showing `rcv_wnd` tracking the free space

The interesting failure to look for is `win 0` followed by a stall. If you see
one, you have the deadlock described in `KNOWN_ISSUES.md`: a window scaled down
to 1 instead of rounded up.

## 5. Kill a segment mid-transfer

The most informative experiment. With a large transfer running, look at your
own trace and note the sequence number of a data segment. Then drop it:

```sh
sudo iptables -A INPUT -i tap0 -p tcp --tcp-flags ACK ACK \
     --tcp-window 65535 -j DROP
```

Remove it again with `iptables -D` on the same line.

You should see, within about one RTO:

- three duplicate ACKs from your stack, each with the same `ack` number
- an immediate retransmission of the missing segment — no timer involved
- no further duplicate ACKs, and the transfer completes

Then repeat with the *first four* segments dropped instead of one. Four losses
produce no duplicate ACKs at all, so recovery must come from the retransmission
timer. Watch the trace for the RTO doubling: 200 ms, 400, 800, 1600.

## 6. Duplicate everything

```sh
sudo tc qdisc add dev tap0 root netem duplicate 20%
```

Now 20% of packets arrive twice. A correct receiver delivers each byte exactly
once. Verify with:

```
recv
```

— the output must be the right length and the right contents, with no repeated
bytes and no gaps. This is a better test of reassembly than any unit test,
because it hits the overlap-trimming paths continuously.

## 7. Add latency and see what happens to throughput

```sh
sudo tc qdisc add dev tap0 root netem delay 40ms
```

Re-run the 500 KiB transfer and time it.

The window is 64 KiB, so ceiling throughput is `64 KiB / 40 ms` ≈ 13 Mbit/s.
Remove the delay with `sudo tc qdisc del dev tap0 root` and watch throughput
climb — this is window scaling doing its job, and it is a good demonstration of
why a 16-bit window is not enough for a fast path.

## 8. Break the connection

With a connection open, kill the peer:

```sh
sudo pkill nc
```

What happens next is worth tracing carefully. With no graceful close, you have
either a black-holed path or a peer that answers with RST. Watch for:

- `ECONNRESET` immediately, if the peer's kernel sent RST
- otherwise the retransmission timer firing with an exponential backoff
- eventually `ETIMEDOUT` after the retry budget is exhausted

The first case is instant and correct. The second is the one that takes minutes
by design.

## 9. Close from both sides

```sh
send goodbye
close
```

While the connection is in `CLOSE-WAIT`, you can still send — that is the whole
point of a half-close. Try `send` again before you `close`. Watch the state
progress through `FIN-WAIT-1` → `FIN-WAIT-2` → `TIME-WAIT` and confirm with
`tcpdump` that you see `CLOSING` in between: the two FINs cross, which is why
that state exists at all.

Then let `TIME-WAIT` expire and watch the socket disappear from `sockets`.

## 10. What the kernel thinks of you

While a connection is open:

```sh
ss -tin
```

Compare the kernel's view of your advertised window, its congestion control
algorithm, and its RTT estimate against your `sockets` and `stats` output. They
will not match — your stack has no `cwnd` and estimates RTT differently — and
seeing exactly how they differ is a good summary of what is missing.

---

## Things to try that should *not* work

Good tests of robustness. Each should be dropped cleanly, not crash.

```sh
# fragmented IP
sudo hping3 -f -S 10.0.0.1

# a SYN to a port nobody listens on (expect RST)
sudo hping3 -S -p 9999 10.0.0.1

# a TCP segment with a deliberately broken checksum
sudo hping3 -S --badcksum 10.0.0.1

# garbage on the wire
sudo python3 -c "
import socket
s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.sendto(bytes(range(256))*2, ('tap0', 0))
"
```

Each of these should be dropped with a warning at `log-level 2` or higher, and
should leave the stack still able to serve a good connection afterwards. Run
`sockets` before and after to confirm nothing was corrupted.