# PyTCP
**The TCP/IP stack written in Python**
<br>

[![GitHub release](https://img.shields.io/github/v/release/ccie18643/PyTCP)](https://github.com/ccie18643/PyTCP/releases)
[![OS](https://img.shields.io/badge/os-Linux-blue)](https://kernel.org)
[![Supported Versions](https://img.shields.io/pypi/pyversions/PyTCP.svg)](https://pypi.org/project/PyTCP)
[![GitHub License](https://img.shields.io/badge/license-GPL--3.0-yellowgreen)](https://github.com/ccie18643/PyTCP/blob/master/LICENSE)
[![CI](https://github.com/ccie18643/PyTCP/actions/workflows/ci.yml/badge.svg)](https://github.com/ccie18643/PyTCP/actions/workflows/ci.yml)

[![GitHub watchers](https://img.shields.io/github/watchers/ccie18643/PyTCP.svg?style=social&label=Watch&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/watchers/)
[![GitHub forks](https://img.shields.io/github/forks/ccie18643/PyTCP.svg?style=social&label=Fork&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/network/)
[![GitHub stars](https://img.shields.io/github/stars/ccie18643/PyTCP.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/ccie18643/PyTCP/stargazers/)

<br>

**PyTCP is a TCP/IP stack written in pure Python.** It runs in user space, attached to a Linux TAP/TUN interface, and implements the protocol layers itself rather than calling the host stack. It can be embedded in-process as a library, or run as a **daemon** that out-of-process clients drive over an AF_UNIX control boundary — the way a Linux process talks to the kernel.

The stack covers Ethernet II and IEEE 802.3 framing, ARP, IPv4 and IPv6 (extension headers and fragmentation), ICMPv4 and ICMPv6, IPv6 Neighbor Discovery and SLAAC, IPv4 and IPv6 multicast group membership (IGMP / MLD), DHCPv4 and DHCPv6 clients, UDP, and RFC 9293 TCP. The TCP implementation includes the full finite state machine, congestion control (CUBIC, NewReno, PRR, HyStart++), SACK and RACK-TLP loss recovery, and RFC 5961 hardening. It exchanges traffic with other hosts on the local segment and over the Internet.

The project's goal is a pure-Python stack that is feature-equivalent to the Linux kernel network stack. RFC text is the primary authority; where a spec is silent or offers a choice, PyTCP follows Linux. Host-stack parity is the current scope; router-grade forwarding is planned.

Behaviour is covered by roughly 13,400 unit and integration tests and tracked against more than 125 per-RFC adherence audits kept in the repository under `docs/rfc/`.

The stack has zero runtime dependencies (standard library only) and exposes a Berkeley-sockets-style API so it can be used in place of the standard socket layer. It is organised as three independently-published, strictly-layered packages — each usable on its own:

- **[`net_addr`](packages/net_addr/README.md)** ([PyPI](https://pypi.org/project/PyTCP-net_addr/)) — address value types: IPv4 / IPv6 / MAC, networks, masks, ACL wildcards, interface-addresses.
- **[`net_proto`](packages/net_proto/README.md)** ([PyPI](https://pypi.org/project/PyTCP-net_proto/)) — protocol packet parse / assemble / validate.
- **[`pytcp`](packages/pytcp/README.md)** ([PyPI](https://pypi.org/project/PyTCP/)) — the running stack: subsystems, sockets, routing FIB, ARP / ND caches, RX / TX rings.

Contributions are welcome.

---


### Features

#### Stack & sockets (engineering, non-RFC)

 - Zero-copy packet parser and assembler (buffer-protocol / memoryview based).
 - `net_addr` value-type library for MAC / IPv4 / IPv6 addresses, networks, masks, ACL wildcards and interface-addresses - immutable, hashable, `@final` leaves, one `NetAddrError` tree; no Python standard-library dependency.
 - Importable as a zero-runtime-dependency library (stdlib only), split into three independent packages: `net_addr`, `net_proto`, `pytcp`.
 - Event-driven millisecond-resolution timer (heap-based deadline scheduler, no polling tick).
 - Runtime-tunable sysctl registry mirroring the Linux `/proc/sys/net/` surface (boot-time and live overrides).
 - RTNETLINK-style control-plane APIs (the Phase-3 kernel/userspace boundary): link (`ip link` — MAC / MTU / state / counters), address (`ip addr`), route (`ip route` — host-mode FIB), neighbor (`ip neighbor`), and read-only `/proc/net`-style introspection snapshots.
 - Runtime interface add / remove on a multi-homed host (RTNETLINK `RTM_NEWLINK` / `RTM_DELLINK`, with the address / route / neighbor / session teardown cascade); free-threaded (no-GIL) safe via per-interface single-writer state + lock-guarded global tables.
 - Per-protocol packet-flow stat counters; TX-path feedback so send failures reach sockets.
 - Homegrown high-performance logger (no third-party logging dependency).
 - Berkeley-sockets-style API for TCP / UDP / RAW / `AF_PACKET`: `fileno()`/eventfd + `selectors` integration, blocking & non-blocking modes, errno-mapped `OSError`, `getaddrinfo` family, common `setsockopt` options, `IP_RECVERR`/`MSG_ERRQUEUE` error queue.
 - Runs as a **daemon**: out-of-process clients open real (SCM_RIGHTS-passed) socket fds and drive the control APIs over an AF_UNIX boundary, either through the explicit `pytcp.client` API or a **1:1 stdlib-`socket` drop-in** (`import pytcp.socket as socket`) that runs off-the-shelf blocking and `asyncio` programs unmodified, with DNS resolved through the stack.
 - Single `pytcp` CLI multitool (zero-dependency): `daemon` / `ss` / `link` / `addr` / `route` / `neigh` / `sysctl` control-plane tools plus `ping` / `host` / `nc` / `traceroute` / `tcpdump` (a daemon-native capture that decodes both ingress and the stack's own egress).
 - Loopback interface (`lo`): 127.0.0.0/8 · ::1 and own-address local delivery, traffic looping inside the stack with no wire frames.
 - Native `unittest` suite (~13,400 unit + integration tests); per-RFC adherence audits in `docs/rfc/`.

#### Ethernet

 - Ethernet II framing with EtherType demux, broadcast and multicast mapping (RFC 894)
 - Inbound IEEE 802.3 / LLC + SNAP support (RFC 1042)

#### ARP

 - ARP resolution with a neighbor cache, replies and queries (RFC 826, RFC 1122)
 - IPv4 Address Conflict Detection — probe, announce, defend (RFC 5227)
 - IANA-correct ARP codepoint handling (RFC 5494)

#### IPv4

 - IPv4 with options parsing, inbound reassembly and outbound fragmentation (RFC 791, RFC 815)
 - Multiple host addresses; private, special-purpose and broadcast address handling (RFC 1918, RFC 6890, RFC 919, RFC 922)
 - ECN, DSCP and Router Alert support (RFC 3168, RFC 2474, RFC 6398)
 - IPv4 link-local autoconfiguration (RFC 3927)
 - IPv4 multicast group membership — host-side IGMPv1 / v2 / v3, with v1/v2 querier-version fallback, source-specific multicast and per-socket source filters (RFC 1112, RFC 2236, RFC 3376)

#### ICMPv4

 - Echo, Destination Unreachable, Time Exceeded and Parameter Problem, with RFC-correct generation gating and rate-limiting (RFC 792, RFC 1122)
 - Obsolete message types correctly omitted (RFC 6633, RFC 6918)

#### IPv6

 - IPv6 with the full extension-header chain and TLV options (RFC 8200)
 - Inbound reassembly and outbound fragmentation, with fragmentation hardening (RFC 5722, RFC 6946, RFC 7739)
 - Unique-local and special-purpose addressing (RFC 4193, RFC 8190)
 - Flow-label generation (RFC 6437)
 - Default source-address selection (RFC 6724); Path MTU Discovery (RFC 8201); node requirements (RFC 8504)

#### ICMPv6 / Neighbor Discovery

 - Full ICMPv6 message set including Packet Too Big (RFC 4443)
 - Stateless Address Autoconfiguration: link-local, DAD, RA prefixes and lifetimes (RFC 4862)
 - Stable opaque and temporary (privacy) addresses (RFC 7217, RFC 8981)
 - Optimistic DAD, Enhanced DAD and Gratuitous NA (RFC 4429, RFC 7527, RFC 9131)
 - Neighbor Discovery with a NUD cache and Router Solicitation backoff (RFC 4861, RFC 7559)
 - Multicast Listener Discovery — MLDv2 listener with MLDv1 compatibility fallback (RFC 3810, RFC 2710)

#### UDP

 - UDP with full host-requirements conformance (RFC 768, RFC 1122)
 - Zero-checksum UDP over IPv6 (RFC 6935)
 - Ephemeral-port randomisation (RFC 6056)
 - Echo / Discard / Daytime example services

#### TCP

 - Complete TCP: full finite state machine and reliable bulk transfer (RFC 9293, RFC 1122)
 - Modern congestion control — CUBIC, NewReno, PRR, HyStart++, ABE, IW10 (RFC 9438, RFC 6582, RFC 6937, RFC 9406, RFC 8511, RFC 6928)
 - Advanced loss recovery — SACK, D-SACK, RACK-TLP, F-RTO, limited transmit (RFC 2018, RFC 2883, RFC 8985, RFC 5682, RFC 3042)
 - RFC-correct RTO with Karn's algorithm and backoff (RFC 6298, RFC 8961)
 - Window Scale, Timestamps, PAWS, MSS and TCP Fast Open (RFC 7323, RFC 6691, RFC 7413)
 - ECN and Accurate ECN (RFC 3168, RFC 9768)
 - Blind-attack and ICMP-attack hardening, randomised ISS and ports, robust TIME-WAIT (RFC 5961, RFC 5927, RFC 6528, RFC 1337, RFC 6191)
 - Keep-alive, zero-window probing, silly-window-syndrome avoidance, Nagle

#### DHCPv4 client

 - Full DHCPv4 client: lease acquisition, RENEW / REBIND / DECLINE, INIT-REBOOT with a persistent lease cache (RFC 2131, RFC 1542)
 - Detecting Network Attachment and client-ID handling (RFC 4436, RFC 6842, RFC 4361)
 - Classless Static Routes installed into the FIB, with Router-option suppression and RFC 3396 option concatenation (RFC 3442, RFC 3396)

#### DHCPv6 client

 - DHCPv6 client: stateful SOLICIT / ADVERTISE / REQUEST / REPLY with IA_NA, and stateless INFORMATION-REQUEST, triggered by the Router Advertisement M/O flags (RFC 8415)
 - DUID, Elapsed Time, Rapid Commit, server-preference selection, alternate-server fallback, and the RENEW / REBIND / RELEASE / DECLINE lease lifecycle (RFC 8415)
 - Addresses assigned through the Address API with DAD; a DAD conflict declines the lease and re-solicits

---


### Principle of operation and the test setup

The PyTCP stack depends on a Linux TAP/TUN interface. The TAP interface is a virtual interface that,
on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux
bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by
programmatically sending and receiving packets to/from it.

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network
setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the
PyTCP stack to your local network at the same time.

```console
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux TCP/IP stack]
                                            |
                                            |--(tap7) <---> [PyTCP TCP/IP stack]
```

After the example program (either client or service) starts the stack, it can communicate with it
via simplified BSD Sockets like API interface. There is also the possibility of sending packets
directly by calling one of the internal ```_phtx_*()``` methods on the ```PacketHandler```.

---


### Cloning PyTCP from the GitHub repository

In most cases, PyTCP should be cloned directly from the [GitHub repository](https://github.com/ccie18643/PyTCP),
as this type of installation provides full development and testing environment.

```shell
git clone https://github.com/ccie18643/PyTCP
```

After cloning, we can run one of the included examples:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the ```sudo make bridge``` command to create the 'br0' bridge if needed.
 - Run the ```sudo make tap7``` command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the ```make venv``` command to create the virtual environment for development and testing.
 - Run ```. venv/bin/activate``` command to activate the virtual environment.
 - Execute any example, e.g., ```python -m examples_legacy.stack``` (see the ```examples_legacy/``` directory; pass ```--help``` for options).
 - Hit Ctrl-C to stop it.

Stack parameters are configured per run via the ```stack.init(...)``` keyword arguments and the runtime sysctl registry (see ```pytcp/stack/```), not a static config file.

---


### Installing PyTCP from the PyPi repository

PyTCP can also be installed as a regular module from the [PyPi repository](https://pypi.org/project/PyTCP/).

```console
python -m pip install PyTCP
```

After installation, please ensure the TAP interface is operational and added to the bridge.

```console
sudo ip tuntap add name tap7 mode tap
sudo ip link set dev tap7 up
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up
sudo ip link set dev tap7 master br0
```

PyTCP is consumed in-process as a library through the ```pytcp.stack```
lifecycle API (```stack.init(...)``` → ```stack.start()``` →
```stack.stop()```) and the ```pytcp.runtime.socket```
Berkeley-sockets-style API. The subsystems run in their own threads; after
```start()``` control returns to your code. Out-of-process, a **daemon**
exposes the same surfaces over an AF_UNIX boundary — driven by the
daemon-backed ```pytcp.socket``` 1:1 stdlib-`socket` drop-in, the explicit
```pytcp.client``` API, or the ```pytcp``` CLI multitool.

For a complete, runnable in-process reference — opening the TAP/TUN file
descriptor, calling ```stack.init(...)```, and driving the stack — see
[```examples_legacy/stack.py```](examples_legacy/stack.py) and the other
programs in the [```examples_legacy/```](examples_legacy/) directory. For
daemon-backed applications over the drop-in (async FTP, TCP/UDP echo,
multicast discovery, ping), see [```examples/```](examples/).

---


### Examples

All output below is captured from a live stack on a Linux `tap7`
interface. Most wire captures are the **stack's own** — the daemon
decodes its own traffic through the shipped `pytcp tcpdump` engine (an
internal AF_PACKET socket bound before the stack starts, so it sees
autoconfiguration from the first frame), no external tool involved. Each
line is:

```text
time(s)   Out|In   <decoded frame>
```

`Out` is a frame the stack transmits, `In` one it receives; the decoded
form mirrors Linux `tcpdump` (`IP src.port > dst.port: …`, `ARP,
Request/Reply …`, ICMP type + id/seq, `frag id:len@offset` for IPv4
fragments). Three captures are explicitly marked as taken with an
**external** `tshark` instead — ACD and DHCP because they run over a raw
AF_PACKET link socket the in-stack tap does not observe (and DHCP needs a
real server), and the packet-loss run because `tshark`'s
retransmission / SACK analysis annotations make the recovery legible.
RFC back-off delays (RFC 5227 ACD, RFC 4862 DAD) are visible in the
timestamps.

Every example is produced by the bundled `tools/capture` runner
and is reproducible. With the TAP/bridge up and the venv built —

```bash
sudo make bridge && sudo make tap7 && make venv
```

— run any example with the exact command listed under it (loss is
random, so a `--loss` run differs every time; everything else is
deterministic). The general form is
`sudo PYTHONPATH=. venv/bin/python -m tools.capture [GLOBAL OPTS] <scenario>`;
`python -m tools.capture --help` lists every scenario and option.

#### Kernel / userspace split — out-of-process socket clients

PyTCP can run as a **daemon**: a normal in-process stack that also
listens on an AF_UNIX control socket, so a **separate process** can open
sockets and drive the control APIs through `pytcp.client` — the way a
Linux process talks to the kernel. The client never boots the stack.

Start the daemon (it owns the TAP interface). The first-class entry point
ships in the package — `python -m pytcp.daemon` (or the `pytcpd` console
script after install); it defaults the socket to `$XDG_RUNTIME_DIR/pytcp.sock`:

```bash
sudo make bridge && sudo make tap7 && make venv
sudo PYTHONPATH=. venv/bin/python -m pytcp.daemon --ipc-socket /tmp/pytcp.sock
# or, with the example runner (adds stats / multi-interface / SIGUSR1):
make daemon            # examples_legacy/stack.py --ipc-socket /tmp/pytcp.sock
```

Then, from any other process, open a TCP socket *through the daemon* and
echo off a remote server — note the client imports `pytcp.client`, not
`pytcp.stack` / `pytcp.socket`, and calls no `stack.init()`:

```python
from pytcp.client import connect
from pytcp.socket import AddressFamily, SocketType

with connect(socket_path="/tmp/pytcp.sock") as client:
    sock = client.socket(AddressFamily.INET4, SocketType.STREAM)
    sock.connect(("10.0.1.1", 7))   # a real, selectable fd backs this socket
    sock.send(b"hello")
    print(sock.recv(5))
    sock.close()
```

The bundled [`examples_legacy/client__tcp_echo_ipc.py`](examples_legacy/client__tcp_echo_ipc.py)
is exactly this — an out-of-process echo client — alongside the
in-process subsystem form in
[`examples_legacy/client__tcp_echo.py`](examples_legacy/client__tcp_echo.py). The same
`client.socket(...)` factory returns UDP / raw / AF_PACKET sockets, and
`client.sysctl` / `.route` / `.link` / `.address` / `.neighbor` /
`.membership` mirror the in-process control APIs across the boundary.

For off-the-shelf programs, `pytcp.socket` is a **1:1 stdlib-`socket`
drop-in** over the same daemon — an app adopts it by changing one import
line (`import pytcp.socket as socket`). It supports blocking **and**
non-blocking / `select` / `asyncio` use, `connect_ex`, faithful
`errno`/exception reconstruction, `makefile`/`dup`, and DNS resolved
through the daemon's own stack; real stdlib `http.client` and `asyncio`
servers/clients run over it unchanged. The runnable apps — async FTP,
TCP/UDP echo, multicast service discovery, ping — live in
[`examples/`](examples/). And a single **`pytcp` CLI** drives the whole
thing: `pytcp daemon start/stop/status`, the control-plane introspectors
`pytcp ss / link / addr / route / neigh / sysctl`, and the network tools
`pytcp ping / host / nc / traceroute`, and `pytcp tcpdump` — a
daemon-native packet capture that decodes each frame with `net_proto`
and shows both directions, including the stack's own replies.

#### Stack startup — IPv6 SLAAC + DAD, MLDv2, IPv4 ACD

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture boot
```

On start the stack autoconfigures itself: it derives an IPv6
link-local address and runs Duplicate Address Detection, reports its
multicast groups via MLDv2, solicits routers, builds a global
address from the Router Advertisement and DADs that too, then runs
RFC 5227 conflict detection for its IPv4 address.

Stack log:

```text
0000.05 | STACK | ICMPv6 ND DAD - Starting process for fe80::7bde:94e9:3254:9daf
0001.28 | STACK | ICMPv6 ND DAD - No duplicate address detected for fe80::7bde:94e9:3254:9daf
0001.28 | STACK | Successfully claimed IPv6 address fe80::7bde:94e9:3254:9daf/64
0001.28 | STACK | Sent out ICMPv6 ND Router Solicitation
0001.28 | STACK | ICMPv6 ND DAD - Starting process for 2603:808c:2800:4301:7d08:ba99:95db:c5
0002.78 | STACK | Successfully claimed IPv6 address 2603:808c:2800:4301:7d08:ba99:95db:c5/64
0006.21 | STACK | Sent out ARP Announcement for 192.168.1.77
0008.21 | STACK | Successfully claimed IPv4 address 192.168.1.77
```

Wire capture — the stack decoding its **own** boot traffic through the
`pytcp tcpdump` engine (no external capture tool; an internal AF_PACKET
socket is bound before the stack starts, so it sees autoconfiguration
from the first frame). `Out` is a frame the stack emits, timestamps
rebased to the first:

```text
   0.000 Out IP6 :: > ff02::1:ff1a:de43: ICMPv6 ND Neighbor Solicitation, target fe80::e3e3:135:2b1a:de43, opts [nonce (0xd8737c9e8df3)], len 32 (24+8)
   1.001 Out IP6 fe80::e3e3:135:2b1a:de43 > ff02::16: IPv6_HBH, length 36
   1.002 Out IP6 fe80::e3e3:135:2b1a:de43 > ff02::2: ICMPv6 ND Router Solicitation, opts [slla 02:00:00:77:77:77], len 16 (8+8)
   1.500 Out IP6 :: > ff02::1:ffeb:5194: ICMPv6 ND Neighbor Solicitation, target 2603:808c:2800:4301:d1f3:6f60:7feb:5194, opts [nonce (0x90d9fc6ab3ea)], len 32 (24+8)
   5.519 Out IP6 fe80::e3e3:135:2b1a:de43 > fe80::c51:f947:495a:cc54: ICMPv6 ND Neighbor Advertisement, flags -S-, target fe80::e3e3:135:2b1a:de43, opts [tlla 02:00:00:77:77:77], len 32 (24+8)
   9.339 Out IP6 fe80::e3e3:135:2b1a:de43.546 > ff02::1:2.547: UDP, length 46
```

(The `IPv6_HBH` lines are the MLDv2 Multicast Listener Reports — ICMPv6
carried under a Hop-by-Hop Router-Alert header; the `.546 > …547` datagram
is the DHCPv6 Solicit. The stack's IPv4 ACD ARP Probe/Announcement is not
shown here: ACD runs over a raw AF_PACKET link socket that bypasses the
egress capture tap.)

#### ARP Probe / Announcement (RFC 5227 Address Conflict Detection)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture arp-acd
```

The stack defends each configured IPv4 address: it sends three ARP
**Probes** (sender `0.0.0.0`), and if no host objects, claims the
address with two ARP **Announcements** (sender = target).

Wire capture with an **external** tool (`tshark -i tap7 -f arp`) — unlike
the other captures on this page, ACD runs over a raw AF_PACKET link
socket (as Linux's `sd-ipv4acd` does), a TX path that bypasses the
stack's own in-line egress tap, so the in-stack `pytcp tcpdump` cannot
observe it:

```text
0.00   ARP   0.0.0.0 → 192.168.1.77        ARP Probe — Who has 192.168.1.77?
1.83   ARP   0.0.0.0 → 192.168.1.77        ARP Probe — Who has 192.168.1.77?
3.38   ARP   0.0.0.0 → 192.168.1.77        ARP Probe — Who has 192.168.1.77?
6.44   ARP   192.168.1.77 → 192.168.1.77   ARP Announcement for 192.168.1.77
8.45   ARP   192.168.1.77 → 192.168.1.77   ARP Announcement for 192.168.1.77
```

Probe vs. Announcement, decoded (`tshark -V`):

```text
ARP Probe         Opcode: request   Sender IP: 0.0.0.0        Target IP: 192.168.1.77
ARP Announcement  Opcode: request   Sender IP: 192.168.1.77   Target IP: 192.168.1.77
```

#### ARP resolution and ICMP Echo

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-icmp-echo
```

A host on the segment pings the stack. The host's Echo Request arrives
before the stack knows the host's MAC, so the stack queues its reply,
resolves the *host's* MAC via ARP, then flushes the queued reply — all
captured by the stack itself, both directions (`In` = the host, `Out` =
the stack):

Wire capture — the stack's own `pytcp tcpdump`, decoded in-stack:

```text
   0.000 In IP 192.168.1.10 > 192.168.1.77: ICMPv4 Echo Request, id 21698, seq 1, len 64 (8+56)
   0.001 Out ARP, Request who-has 192.168.1.10 tell 192.168.1.77
   0.001 In ARP, Reply 192.168.1.10 is-at a2:4b:a1:00:92:56
   0.002 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4 Echo Reply, id 21698, seq 1, len 64 (8+56)
   1.001 In IP 192.168.1.10 > 192.168.1.77: ICMPv4 Echo Request, id 21698, seq 2, len 64 (8+56)
   1.002 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4 Echo Reply, id 21698, seq 2, len 64 (8+56)
   2.003 In IP 192.168.1.10 > 192.168.1.77: ICMPv4 Echo Request, id 21698, seq 3, len 64 (8+56)
   2.003 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4 Echo Reply, id 21698, seq 3, len 64 (8+56)
```

From the pinging host:
`3 packets transmitted, 3 received, 0% packet loss; rtt min/avg/max/mdev = 1.041/1.334/1.894/0.395 ms`.

#### ICMPv6 Echo over IPv6 (Neighbor Discovery + ping6)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip6-icmp-echo
```

The IPv6 counterpart: a host on a ULA pings the stack's IPv6 address.
The host first resolves the stack with ICMPv6 Neighbor Discovery — its
Neighbor Solicitation carries the host's own link-layer address (`slla`),
so the stack learns the host from it and answers the Echo directly:

Wire capture — the stack's own `pytcp tcpdump`, decoded in-stack
(rebased to the host's Neighbor Solicitation; the ND option payloads —
source / target link-layer addresses — are decoded too):

```text
   0.000 In IP6 fd00:1::1 > ff02::1:ff00:77: ICMPv6 ND Neighbor Solicitation, target fd00:1::77, opts [slla a2:4b:a1:00:92:56], len 32 (24+8)
   0.000 Out IP6 fd00:1::77 > fd00:1::1: ICMPv6 ND Neighbor Advertisement, flags -S-, target fd00:1::77, opts [tlla 02:00:00:77:77:77], len 32 (24+8)
   0.001 In IP6 fd00:1::1 > fd00:1::77: ICMPv6 Echo Request, id 21697, seq 1, len 64 (8+56)
   0.001 Out IP6 fd00:1::77 > fd00:1::1: ICMPv6 Echo Reply, id 21697, seq 1, len 64 (8+56)
   1.000 In IP6 fd00:1::1 > fd00:1::77: ICMPv6 Echo Request, id 21697, seq 2, len 64 (8+56)
   1.001 Out IP6 fd00:1::77 > fd00:1::1: ICMPv6 Echo Reply, id 21697, seq 2, len 64 (8+56)
   2.014 In IP6 fd00:1::1 > fd00:1::77: ICMPv6 Echo Request, id 21697, seq 3, len 64 (8+56)
   2.015 Out IP6 fd00:1::77 > fd00:1::1: ICMPv6 Echo Reply, id 21697, seq 3, len 64 (8+56)
```

From the pinging host:
`3 packets transmitted, 3 received, 0% packet loss; rtt min/avg/max/mdev = 0.921/1.325/2.113/0.556 ms`.

#### Monkeys over TCP

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-tcp-monkeys
```

PyTCP ships a daemon-backed async TCP echo server
(`examples/tcp_echo_server__async.py`, bound to the stack through the
drop-in `pytcp.socket`). As a quick end-to-end check a host `nc` streams
an ASCII-art "monkey" as the payload and the server echoes it back over
the TCP connection — the original "monkeys delivered via TCP" demo, now
reproducible as plain text. Connecting to the server returns its banner,
then the monkey makes the full round trip through the stack's TCP path
intact; sending `quit` asks the server to close, and PyTCP performs the
graceful active close itself:

```text
$ { printf 'malpi\n'; sleep 3; printf 'quit\n'; } | nc 192.168.1.77 7
***CLIENT OPEN / SERVICE OPEN***
                                       ______AAAA_______________AAAA______
                                             VVVV               VVVV
                                             (__)               (__)
                                              \ \               / /
               .="=.                           \ \              / /
             _/.-.-.\_    _                     > \   .="=.   / <
            ( ( o o ) )   ))                     > \ /     \ / <
             |/  "  \|   //                       > \\_o_o_// <
              \'---'/   //                         > ( (_) ) <
              /`---`\  ((                           >|     |<
             / /_,_\ \  \\                         / |\___/| \
             \_\_'__/ \  ))                        / \_____/ \
             /`  /`~\  |//                         /         \
            /   /    \  /                           /   o   \
        ,--`,--'\/\    /                             ) ___ (
         '-- "--'  '--'                             / /   \ \
                                                   ( /     \ )
                                                   ><       ><
                                                  ///\     /\\\
                                                  '''       '''
***CLIENT OPEN, SERVICE CLOSING***
```

On the wire — the stack's own `pytcp tcpdump`, decoded in-stack (`Out` is
the stack, `In` is the host), rebased to the SYN. The SYN-ACK is the
stack's first frame to the host, so it is queued pending ARP resolution
and flushed once the host's MAC is learned — and the egress tap captures
it on the flush, exactly as Linux `dev_queue_xmit_nit` does:

```text
   0.000 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [S], length 0
   0.002 Out ARP, Request who-has 192.168.1.10 tell 192.168.1.77
   0.003 In ARP, Reply 192.168.1.10 is-at a2:4b:a1:00:92:56
   0.003 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [S.], length 0
   0.003 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [.], length 0
   0.004 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [P.], length 6
   0.007 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [.], length 1448
   0.010 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [P.], length 146
   2.999 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [P.], length 5
   3.001 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [P.], length 35
   3.004 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [F.], length 0
   3.044 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [.], length 0
   6.000 In IP 192.168.1.10.42816 > 192.168.1.77.7: Flags [F.], length 0
   6.000 Out IP 192.168.1.77.7 > 192.168.1.10.42816: Flags [.], length 0
```

(`Flags`: `S` SYN, `.` ACK, `P` PSH, `F` FIN. Pure-ACK `In` segments
between the shown frames are elided for brevity.)

The stack negotiates MSS / SACK-permitted / window-scale /
timestamps on the handshake, resolves the peer's MAC via ARP
mid-handshake, segments the echoed monkeys to the MSS, tracks the
peer's cumulative ACKs, and on `quit` performs the RFC 9293 §3.6
active close — FIN, peer ACK, peer FIN, FIN ACK — a complete TCP
connection opened, used, and gracefully torn down entirely by
pure-Python code.

#### Monkeys over TCP — over IPv6

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip6-tcp-monkeys
```

The same demo, unchanged, over IPv6 (the server bound to a ULA; the
host resolves it with ICMPv6 Neighbor Discovery instead of ARP). The
IPv6 MSS is 20 bytes smaller than IPv4's (the larger fixed header), so
the first echo segment is 1428 vs 1448 bytes. The stack captures the
whole thing itself — note the Neighbor Solicitation the stack sends
mid-handshake to resolve the peer for its SYN-ACK, and the queued
SYN-ACK (`[S.]`) flushed and captured once the peer answers:

```text
   0.000 In IP6 fd00:1::1.35970 > fd00:1::77.7: Flags [S], length 0
   0.001 Out IP6 fd00:1::77 > ff02::1:ff00:1: ICMPv6 ND Neighbor Solicitation, target fd00:1::1, opts [slla 02:00:00:77:77:77], len 32 (24+8)
   0.002 In IP6 fd00:1::1 > fd00:1::77: ICMPv6 ND Neighbor Advertisement, flags -SO, target fd00:1::1, opts [tlla a2:4b:a1:00:92:56], len 32 (24+8)
   0.002 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [S.], length 0
   0.003 In IP6 fd00:1::1.35970 > fd00:1::77.7: Flags [P.], length 6
   0.006 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [.], length 1428
   0.009 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [P.], length 166
   2.998 In IP6 fd00:1::1.35970 > fd00:1::77.7: Flags [P.], length 5
   3.000 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [P.], length 35
   3.004 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [F.], length 0
   3.046 In IP6 fd00:1::1.35970 > fd00:1::77.7: Flags [.], length 0
   5.999 In IP6 fd00:1::1.35970 > fd00:1::77.7: Flags [F.], length 0
   6.000 Out IP6 fd00:1::77.7 > fd00:1::1.35970: Flags [.], length 0
```

#### Monkeys over UDP — IPv4 fragmentation

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-udp-monkeys
```

The same ASCII monkeys, echoed over the UDP service. The reply
(~1.5 KB) exceeds the 1500-byte link MTU, so the stack
IPv4-fragments it — the classic "IP fragmentation" demo, captured
for real.

```text
$ printf 'malpi\n' | nc -u 192.168.1.77 7
                                       ______AAAA_______________AAAA______
                                             VVVV               VVVV
                                             (__)               (__)
                                              \ \               / /
               .="=.                           \ \              / /
             _/.-.-.\_    _                     > \   .="=.   / <
            ( ( o o ) )   ))                     > \ /     \ / <
             |/  "  \|   //                       > \\_o_o_// <
              \'---'/   //                         > ( (_) ) <
              /`---`\  ((                           >|     |<
             / /_,_\ \  \\                         / |\___/| \
             \_\_'__/ \  ))                        / \_____/ \
             /`  /`~\  |//                         /         \
            /   /    \  /                           /   o   \
        ,--`,--'\/\    /                             ) ___ (
         '-- "--'  '--'                             / /   \ \
                                                   ( /     \ )
                                                   ><       ><
                                                  ///\     /\\\
                                                  '''       '''
```

On the wire — the stack's own `pytcp tcpdump`, decoded in-stack
(`frag <id>:<len>@<offset>`, `+` = More Fragments; rebased to the
request):

```text
   0.000 In IP 192.168.1.10.39262 > 192.168.1.77.7: UDP, length 6
   0.001 Out ARP, Request who-has 192.168.1.10 tell 192.168.1.77
   0.002 In ARP, Reply 192.168.1.10 is-at a2:4b:a1:00:92:56
   0.002 Out IP 192.168.1.77 > 192.168.1.10: UDP, frag 1:1480@0+
   0.002 Out IP 192.168.1.77 > 192.168.1.10: UDP, frag 1:89@1480
```

The oversized UDP reply is split into two IPv4 fragments sharing one IP
id (`1`); the peer's kernel reassembles them and `nc -u` prints the
monkey. The first fragment is held in the per-neighbour queue until the
ARP reply resolves the peer's MAC (RFC 1122 §2.3.2.2), then both
fragments are flushed in order — and the egress tap captures the queued
first fragment on the flush, so the stack sees its own complete output.

#### Monkeys over UDP — over IPv6

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip6-udp-monkeys
```

The same oversized echo over IPv6. IPv6 fragments differently from
IPv4: the base header is never modified — the source inserts a
**Fragment extension header** (RFC 8200 §4.5), and only the source may
fragment. The stack resolves the peer via ICMPv6 Neighbor Discovery
(NS → NA — the stack sends the NS itself, mid-flow, to resolve the peer
for its reply), then emits the ~1.5 KB reply as two `IPv6_Frag`
fragments — captured and decoded by the stack itself:

```text
   0.000 In IP6 fd00:1::1.33143 > fd00:1::77.7: UDP, length 6
   0.001 Out IP6 fd00:1::77 > ff02::1:ff00:1: ICMPv6 ND Neighbor Solicitation, target fd00:1::1, opts [slla 02:00:00:77:77:77], len 32 (24+8)
   0.002 In IP6 fd00:1::1 > fd00:1::77: ICMPv6 ND Neighbor Advertisement, flags -SO, target fd00:1::1, opts [tlla a2:4b:a1:00:92:56], len 32 (24+8)
   0.002 Out IP6 fd00:1::77 > fd00:1::1: IPv6_Frag, length 1456
   0.002 Out IP6 fd00:1::77 > fd00:1::1: IPv6_Frag, length 129
```

(`IPv6_Frag` is the Fragment extension header — the decoder reports the
per-fragment payload length; the two fragments, 1456 + 129 bytes,
reassemble to the ~1.5 KB reply, which the peer's kernel puts back
together so `nc -u` prints the monkey.)

#### Inbound IPv4 reassembly (oversized ping)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-icmp-frag-rx --count 1
```

The receive-side counterpart of the fragmentation demos. The host sends
a 4000-byte `ping`, which its kernel splits into three IPv4 fragments.
The stack **reassembles** them into one Echo Request, then replies with a
4000-byte Echo Reply that it **itself fragments** into three — all
captured and decoded by the stack itself, both directions:

```text
   0.000 In IP 192.168.1.10 > 192.168.1.77: ICMPv4, frag 60131:1480@0+
   0.000 In IP 192.168.1.10 > 192.168.1.77: ICMPv4, frag 60131:1480@1480+
   0.000 In IP 192.168.1.10 > 192.168.1.77: ICMPv4, frag 60131:1048@2960
   0.001 Out ARP, Request who-has 192.168.1.10 tell 192.168.1.77
   0.002 In ARP, Reply 192.168.1.10 is-at a2:4b:a1:00:92:56
   0.002 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4, frag 1:1480@0+
   0.002 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4, frag 1:1480@1480+
   0.002 Out IP 192.168.1.77 > 192.168.1.10: ICMPv4, frag 1:1048@2960
```

The three inbound fragments (id `60131`) reassemble to one Echo Request;
the stack's reply is re-fragmented under its own IP id (`1`). Offsets are
in bytes — `0`, `1480`, `2960` — and the final fragment of each group
carries no `+`. From the pinging host:
`1 packets transmitted, 1 received, 0% packet loss`
(`4008 bytes from 192.168.1.77` — the full 4000-byte payload made the
round trip, reassembled on both ends).

#### DHCPv4 client lease

**Reproduce** (needs a DHCPv4 server reachable on the bridge):

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-dhcp
```

With no static IPv4 configured, the stack runs its DHCPv4 client:
the full DORA exchange (Discover → Offer → Request → ACK), and
then — because the address is unverified — RFC 5227 Address
Conflict Detection on the *DHCP-assigned* address before it is
used. A randomized RFC 2131 initial-desync delay (~6.8 s here)
precedes the first Discover.

Wire capture with an **external** tool (`tshark`): this scenario needs a
real DHCPv4 server on the segment, and its trailing ACD Probes /
Announcements go over the raw-socket path the in-stack tap does not see
(as in the ACD section above):

```text
0.000   DHCP  0.0.0.0 → 255.255.255.255       DHCP Discover   xid 0x3207aee
0.000   DHCP  192.168.1.1 → 255.255.255.255   DHCP Offer      xid 0x3207aee   (offers 192.168.1.145)
3.002   DHCP  0.0.0.0 → 255.255.255.255       DHCP Request    xid 0x3207aee   (requesting 192.168.1.145)
3.002   DHCP  192.168.1.1 → 255.255.255.255   DHCP ACK        xid 0x3207aee   (lease 3600 s)
3.810   ARP   0.0.0.0 → 192.168.1.145         ARP Probe — Who has 192.168.1.145?   (RFC 5227 ACD on the leased address)
5.599   ARP   0.0.0.0 → 192.168.1.145         ARP Probe — Who has 192.168.1.145?
6.891   ARP   0.0.0.0 → 192.168.1.145         ARP Probe — Who has 192.168.1.145?
10.252  ARP   192.168.1.145 → 192.168.1.145   ARP Announcement for 192.168.1.145
12.252  ARP   192.168.1.145 → 192.168.1.145   ARP Announcement for 192.168.1.145
```

Stack log:

```text
0015.05 | DHCP4 | Initial desync delay: 6.83s
0021.89 | DHCP4 | TX - DHCPv4 Request ... [message_type Discover ...]
0021.89 | DHCP4 | RX - DHCPv4 Reply ... yiaddr 192.168.1.145 ... [message_type Offer, server_id 192.168.1.1 ...]
0024.89 | DHCP4 | TX - DHCPv4 Request ... [message_type Request, server_id 192.168.1.1, req_ip_addr 192.168.1.145 ...]
0024.89 | DHCP4 | RX - DHCPv4 Reply ... [message_type ACK, lease_time 3600 ...]
0032.14 | DHCP4 | Lease acquired: 192.168.1.145/24 (lease_time=3600s, server=192.168.1.1)
```

#### TCP under packet loss — retransmission & recovery

**Reproduce** (asserts the connection still completes — exits
non-zero if it does not):

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture \
  --loss 20 --expect-wire '\[FIN, ACK\]' ip4-tcp-monkeys
# … → [PASS] wire: /\[FIN, ACK\]/ , exit 0
```

Every example above runs on a clean bridge, so the loss-recovery
machinery never fires. Driven through a `tc netem loss 20%`
qdisc, the same TCP monkeys exchange has segments dropped in both
directions — and the stack recovers: it retransmits its own
segments on RTO, the peer SACKs the holes, and the connection
still completes and closes cleanly (no RST). One representative
run (loss is random — every run drops different packets; the
invariant is that it *completes*), captured with an **external** tool
(`tshark`, whose retransmission / duplicate-ACK / SACK analysis
annotations make the recovery legible), rebased to the SYN:

```text
0.000  TCP  192.168.1.10 → 192.168.1.77   [SYN]                 Seq=0 MSS=1460 SACK_PERM WS=1024
0.003  TCP  192.168.1.77 → 192.168.1.10   [SYN,ACK]             Seq=0 Ack=1
0.003  TCP  192.168.1.10 → 192.168.1.77   [ACK]
0.006  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]             open banner, Len 33
0.035  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]             [TCP Retransmission] Seq=1 Len 33  (banner drop → RTO resend)
0.035  TCP  192.168.1.10 → 192.168.1.77   [ACK]                 [Previous segment not captured] SACK SLE=1 SRE=34
0.036  TCP  192.168.1.77 → 192.168.1.10   [ACK]                 [TCP Dup ACK]
0.208  TCP  192.168.1.10 → 192.168.1.77   [PSH,ACK]             [TCP Retransmission] "malpi\n" request resent
0.211  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]             monkeys, segment 1
0.279  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]             [TCP Retransmission] Seq=1482 Len 113  monkeys seg 2 resent
0.279  TCP  192.168.1.10 → 192.168.1.77   [ACK]                 SACK SLE=1482 SRE=1595
3.210  TCP  192.168.1.10 → 192.168.1.77   [PSH,ACK]             "quit\n" request
4.001  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]             [TCP Retransmission] "SERVICE CLOSING" banner resent
4.004  TCP  192.168.1.77 → 192.168.1.10   [FIN,ACK]             PyTCP active close
4.044  TCP  192.168.1.10 → 192.168.1.77   [ACK]                 peer acks the FIN
6.000  TCP  192.168.1.10 → 192.168.1.77   [FIN,ACK]             peer closes its half
6.001  TCP  192.168.1.77 → 192.168.1.10   [ACK]                 connection fully closed (no RST)
```

`--loss` (and `--delay-ms` / `--reorder` / `--duplicate` /
`--corrupt`) plus the `--expect-log` / `--expect-wire` /
`--expect-client` assertions are global options that go before
*any* scenario, so any capture can be turned into a loss /
latency e2e check.
