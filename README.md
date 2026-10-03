# userspace-tcpip

A TCP/IP stack written from scratch in C, running entirely in user space on
top of a Linux **TUN/TAP** virtual network device.

There is no kernel networking underneath. The process opens `/dev/net/tun`,
grabs a virtual NIC, and then does the work itself: Ethernet framing, ARP,
IPv4, ICMP, and TCP with a real state machine, sliding-window flow control,
round-trip-time estimation, fast retransmit, and out-of-order reassembly.

```
   your process          this program                       the kernel
   ------------          -------------                       --------
   tcp_send()  -->   TCP: state machine, windows      -->  /dev/net/tun
   tcp_recv()  <--   IP, ICMP, ARP, Ethernet framing  <--  (a virtual cable)
```

---

## ⚠️ Status: written, not yet compiled

**This code has never been compiled or executed.** It was written without a C
toolchain available, so it is unverified. Expect compile errors on the first
build, and expect to find and fix logic bugs afterwards.

A GitHub Actions workflow (`.github/workflows/ci.yml`) builds and runs the
suite on every push, so the first build happens within a minute of pushing —
on a Linux runner, which is the only place this can be built anyway.

What that means concretely:

- The test suite in `tests/` is written but **has never been run**. It is the
  thing to run first.
- Bug fixes made during writing are noted in `docs/KNOWN_ISSUES.md`, along
  with the ones that are still latent.
- Nothing here should be put on a network you care about until it passes
  `make test` and has been reviewed.

---

## Building

Requires Linux, GCC (or Clang), and a C11 compiler.

```sh
make                 # builds usstack and usstack-tests
make test            # builds and runs the protocol test suite
make asan            # reruns the suite under AddressSanitizer + UBSan
```

The test suite needs no privileges and no network device. The `usstack`
binary does: it needs root (or `CAP_NET_ADMIN`) and `/dev/net/tun`.

```sh
sudo modprobe tun
make run
```

## Running the stack

```sh
# a TAP device on 10.0.0.1/24 (default)
sudo ./usstack

# or plain TUN, bare IPv4 packets, custom address and MTU
sudo ./usstack --tun --iface tun7 --addr 10.7.0.1 --mtu 1400
```

Then wire something up to the other end:

```sh
# on the same machine
sudo ip link set tap0 up
sudo ip addr add 10.0.0.2/24 dev tap0
sudo ip route add 10.0.0.0/24 dev tap0
```

and from the console:

```
help                  show commands
ifconfig              interface and stack configuration
ping 10.0.0.2 4       ICMP echo requests
listen 8080           listen for TCP connections
connect 10.0.0.2 80    open a TCP connection
send hello there      queue bytes for the peer
recv                  read whatever arrived
sockets               list every control block and its state
stats                 counters for each layer
trace                 toggle full packet tracing with hexdumps
quit                  exit
```

`trace` is where the interesting part is: every segment in and out, with its
checksum-bearing header hexdumped.

## Options

| flag | meaning | default |
| --- | --- | --- |
| `-i`, `--iface` | TUN/TAP interface name | `tap0` |
| `-a`, `--addr` | our IPv4 address | `10.0.0.1` |
| `-n`, `--netmask` | netmask | `255.255.255.0` |
| `-m`, `--mtu` | MTU, 576–1500 | `1500` |
| `-t`, `--tun` | use TUN (bare IP) rather than TAP (Ethernet) | TAP |
| `-L`, `--log-level` | 0 error … 4 trace | `2` |
| `-s`, `--selftest` | write one SYN and exit | — |

---

## What is actually implemented

**Ethernet / ARP** — DIX framing, a 32-entry ageing ARP cache that learns from
any sender, request and reply handling, and a deferred-transmission queue so
that the first packet to an unknown host is held rather than dropped.

**IPv4** — header build and validation (version, IHL, `total_length`,
checksum, fragments), address classification including subnet broadcast, and
ICMP Destination Unreachable for unhandled protocols. No forwarding: this is
an endpoint, not a router. No fragmentation: it sets DF and refuses fragments.

**ICMP** — echo request and reply, with `id`/`seq` preserved; unreachable
errors quoting the offending header plus eight payload bytes.

**TCP** — all eleven states; three-way handshake for both passive and active
opens; simultaneous open; RST generation for segments that match no
connection; per-segment retransmission with RFC 6298 SRTT/RTTVAR estimation,
Karn's algorithm and exponential backoff; fast retransmit on three duplicate
ACKs; window scaling (RFC 7323) with the advertised window derived directly
from receive-buffer space; the persist timer for zero-window stalls; SACK
permitted; out-of-order reassembly with trimming of stale prefixes; TIME-WAIT.

### What is *not* implemented

Congestion control (there is a window, but no `cwnd`), SACK-based recovery,
ECN, IPv6, UDP, IP fragmentation and reassembly, IP forwarding, and TLS —
which is to say, nothing that would let it actually carry HTTPS traffic yet.

## Layout

```
include/     protocol headers, one per layer
src/
  checksum.c   the Internet checksum (RFC 1071)
  ringbuf.c    the byte ring behind both TCP buffers
  ethernet.c   link-layer framing and MAC formatting
  arp.c        address resolution
  ip.c         IPv4 header construction and validation
  icmp.c       echo and unreachable
  tcp.c        segment parsing and option encoding
  tcp_socket.c the protocol engine: state machine, windows, timers
  net.c        the stack: framing, ARP, IP demultiplexing, transmit path
  tun.c        the only file that talks to the kernel
  ping.c       an echo client built on ICMP
  main.c       device bring-up, the event loop, the console
tests/       a virtual wire plus a suite that drives the real stack
docs/        architecture, protocol notes, known issues
```

`tun.c` is the only file that includes Linux headers. Everything else is
portable, which is why the test suite can build and run the entire protocol
stack with no device and no privileges.

## How it is tested

The suite wires two complete stacks back to back through an in-memory queue of
frames that can lose, delay and duplicate packets. Time is virtual, so a
retransmission timeout is triggered by advancing a counter rather than by
sleeping — the tests are deterministic.

That makes it possible to assert the things that actually matter:

- the checksum against RFC 1071's worked example, not just against itself
- a full 64 KiB transfer arriving byte-exact and in order **over a link that
  drops and duplicates frames**
- three-way handshakes, including that the first packet on a cold ARP cache is
  an ARP request rather than a SYN
- retransmission recovery by timer *and* by fast retransmit, separately
- a receive buffer that is never overrun no matter what the peer sends
- a segment outside the window refused rather than buffered

```sh
make test
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — how a byte becomes a
  connection, and why the pieces are split the way they are
- [`docs/PROTOCOL_NOTES.md`](docs/PROTOCOL_NOTES.md) — the specific decisions
  and deliberate simplifications, with RFC references
- [`docs/KNOWN_ISSUES.md`](docs/KNOWN_ISSUES.md) — what is wrong or missing,
  including bugs found and fixed during writing
- [`docs/LAB.md`](docs/LAB.md) — experiments to run against the console once it
  builds

## License

MIT. See [LICENSE](LICENSE).