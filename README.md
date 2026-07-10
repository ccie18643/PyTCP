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
interface bridged to a LAN — PyTCP's own log plus a `tshark` wire
capture. RFC back-off delays (RFC 5227 ACD, RFC 4862 DAD) are
visible in the timestamps.

Every wire block uses the same columns:

```text
time(s)   PROTO   src → dst   summary
```

`src → dst` is the IPv4/IPv6 source → destination; for ARP it is
the ARP-payload **sender → target**. `—` marks IPv6 ND/MLD frames
whose link-local/multicast endpoints are named in the summary
instead (the `boot` capture did not record them as columns).

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

Wire capture (`tshark -i tap7`, rebased to the first frame; IPv6
ND/MLD endpoints are now real columns, not `—`):

```text
0.000  ARP     0.0.0.0 → 192.168.1.77                    Who has 192.168.1.77?   (ARP Probe)
0.177  ICMPv6  :: → ff02::1:ff54:9daf                    Neighbor Solicitation for fe80::7bde:94e9:3254:9daf   (link-local DAD)
1.178  ICMPv6  fe80::7bde:94e9:3254:9daf → ff02::16      Multicast Listener Report Message v2
1.179  ICMPv6  fe80::7bde:94e9:3254:9daf → ff02::2       Router Solicitation from 02:00:00:77:77:77
1.679  ICMPv6  :: → ff02::1:ffdb:c5                      Neighbor Solicitation for 2603:808c:2800:4301:7d08:ba99:95db:c5   (SLAAC GUA DAD)
6.107  ARP     192.168.1.77 → 192.168.1.77               ARP Announcement for 192.168.1.77
6.180  ICMPv6  fe80::7bde:94e9:3254:9daf → fe80::2e0:67ff:fe26:88cb   Neighbor Advertisement fe80::7bde:94e9:3254:9daf (sol) is at 02:00:00:77:77:77
8.108  ARP     192.168.1.77 → 192.168.1.77               ARP Announcement for 192.168.1.77
```

#### ARP Probe / Announcement (RFC 5227 Address Conflict Detection)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture arp-acd
```

The stack defends each configured IPv4 address: it sends three ARP
**Probes** (sender `0.0.0.0`), and if no host objects, claims the
address with two ARP **Announcements** (sender = target).

Wire capture (`tshark -i tap7 -f arp`):

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

A host on the segment pings the stack. Having learned the stack's MAC
from its ARP Announcement, the host sends the Echo Request directly;
the stack then resolves the *host's* MAC via ARP before replying:

Wire capture (`tshark -i tap7`, rebased to the first Echo Request):

```text
0.000  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626e, seq=1, ttl=64
0.001  ARP   192.168.1.77 → 192.168.1.10   Who has 192.168.1.10? Tell 192.168.1.77
0.001  ARP   192.168.1.10 → 192.168.1.77   192.168.1.10 is at a2:4b:a1:00:92:56
0.001  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626e, seq=1, ttl=64
1.001  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626e, seq=2, ttl=64
1.002  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626e, seq=2, ttl=64
2.032  ICMP  192.168.1.10 → 192.168.1.77   Echo (ping) request   id=0x626e, seq=3, ttl=64
2.033  ICMP  192.168.1.77 → 192.168.1.10   Echo (ping) reply     id=0x626e, seq=3, ttl=64
```

From the pinging host:
`3 packets transmitted, 3 received, 0% packet loss; rtt min/avg/max/mdev = 0.693/0.873/1.185/0.221 ms`.

#### ICMPv6 Echo over IPv6 (Neighbor Discovery + ping6)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip6-icmp-echo
```

The IPv6 counterpart: a host on a ULA pings the stack's IPv6
address. The host sends the Echo Request directly; the stack
resolves the *host* with ICMPv6 Neighbor Discovery (Neighbor
Solicitation → Neighbor Advertisement) before replying:

Wire capture (`tshark -i tap7`, rebased to the first Echo
Request; unrelated LAN router/host traffic filtered out):

```text
0.000  ICMPv6  fd00:1::1 → fd00:1::77        Echo (ping) request   id=0x626f, seq=1, hlim=64
0.001  ICMPv6  fd00:1::77 → ff02::1:ff00:1   Neighbor Solicitation for fd00:1::1   (from 02:00:00:77:77:77)
0.001  ICMPv6  fd00:1::1 → fd00:1::77        Neighbor Advertisement — fd00:1::1 is at a2:4b:a1:00:92:56
0.001  ICMPv6  fd00:1::77 → fd00:1::1        Echo (ping) reply     id=0x626f, seq=1, hlim=255
1.001  ICMPv6  fd00:1::1 → fd00:1::77        Echo (ping) request   id=0x626f, seq=2, hlim=64
1.002  ICMPv6  fd00:1::77 → fd00:1::1        Echo (ping) reply     id=0x626f, seq=2, hlim=255
2.044  ICMPv6  fd00:1::1 → fd00:1::77        Echo (ping) request   id=0x626f, seq=3, hlim=64
2.045  ICMPv6  fd00:1::77 → fd00:1::1        Echo (ping) reply     id=0x626f, seq=3, hlim=255
```

(`tshark`'s heuristic dissector tags the Echo payload as
"HiPerConTracer" — a harmless false positive; the frames are plain
ICMPv6 Echo.)

From the pinging host:
`3 packets transmitted, 3 received, 0% packet loss; rtt min/avg/max/mdev = 0.680/0.882/1.276/0.278 ms`.

#### Monkeys over TCP

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-tcp-monkeys
```

PyTCP ships a matching TCP echo client and service
(`examples_legacy/client__tcp_echo.py` / `examples_legacy/service__tcp_echo.py`).
As a quick end-to-end check the client streams two ASCII-art
"monkeys" as the payload and the service echoes them back over the
TCP connection — the original "two monkeys delivered via TCP" demo,
now reproducible as plain text. Connecting to the service returns
its banner, then the monkeys make the full round trip through the
stack's TCP path intact; sending `quit` asks the service to close,
and PyTCP performs the graceful active close itself:

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

On the wire (`tshark -i tap7`, rebased to the SYN) — the full
RFC 9293 exchange, handshake through graceful close:

```text
0.000  TCP  192.168.1.10 → 192.168.1.77   [SYN]       Seq=0 MSS=1460 SACK_PERM WS=1024 TSopt
0.002  ARP  192.168.1.77 → 192.168.1.10   Who has 192.168.1.10? Tell 192.168.1.77
0.002  ARP  192.168.1.10 → 192.168.1.77   192.168.1.10 is at a2:4b:a1:00:92:56
0.002  TCP  192.168.1.77 → 192.168.1.10   [SYN,ACK]   Seq=0 Ack=1 MSS=1460 SACK_PERM WS=128 TSopt
0.002  TCP  192.168.1.10 → 192.168.1.77   [ACK]       Seq=1 Ack=1
0.002  TCP  192.168.1.10 → 192.168.1.77   [PSH,ACK]   len 6      "malpi\n"  (request)
0.005  TCP  192.168.1.77 → 192.168.1.10   [ACK]       len 1448   banner + monkeys, segment 1 (full MSS)
0.005  TCP  192.168.1.10 → 192.168.1.77   [ACK]       Ack=1449
0.007  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]   len 146    monkeys, segment 2
0.007  TCP  192.168.1.10 → 192.168.1.77   [ACK]       Ack=1595
2.999  TCP  192.168.1.10 → 192.168.1.77   [PSH,ACK]   len 5      "quit\n"  (request)
3.000  TCP  192.168.1.77 → 192.168.1.10   [PSH,ACK]   len 35     "SERVICE CLOSING" banner
3.000  TCP  192.168.1.10 → 192.168.1.77   [ACK]       Ack=1630
3.003  TCP  192.168.1.77 → 192.168.1.10   [FIN,ACK]              PyTCP active close
3.044  TCP  192.168.1.10 → 192.168.1.77   [ACK]       Ack=1631   peer acks the FIN
6.000  TCP  192.168.1.10 → 192.168.1.77   [FIN,ACK]              peer closes its half
6.001  TCP  192.168.1.77 → 192.168.1.10   [ACK]       Ack=13     connection fully closed (no RST)
```

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

The same demo, unchanged, over IPv6 (the service bound to a ULA;
the host resolves it with ICMPv6 Neighbor Discovery instead of
ARP). The IPv6 MSS is 1440 (vs 1460 on IPv4 — the 20-byte-larger
fixed header). Same handshake, echo, and RFC 9293 §3.6 graceful
close:

```text
0.000  ICMPv6  fd00:1::1 → ff02::1:ff00:77   Neighbor Solicitation for fd00:1::77   (from a2:4b:a1:00:92:56)
0.001  ICMPv6  fd00:1::77 → fd00:1::1         Neighbor Advertisement — fd00:1::77 is at 02:00:00:77:77:77
0.001  TCP     fd00:1::1 → fd00:1::77         [SYN]       Seq=0 MSS=1440 SACK_PERM WS=1024 TSopt
0.003  TCP     fd00:1::77 → fd00:1::1         [SYN,ACK]   Seq=0 Ack=1 MSS=1440 SACK_PERM WS=128 TSopt
0.003  TCP     fd00:1::1 → fd00:1::77         [ACK]       Seq=1 Ack=1
0.003  TCP     fd00:1::1 → fd00:1::77         [PSH,ACK]   len 6      "malpi\n"  (request)
0.006  TCP     fd00:1::77 → fd00:1::1         [ACK]       len 1428   banner + monkeys, segment 1 (full MSS)
0.006  TCP     fd00:1::1 → fd00:1::77         [ACK]       Ack=1429
0.008  TCP     fd00:1::77 → fd00:1::1         [PSH,ACK]   len 166    monkeys, segment 2
0.008  TCP     fd00:1::1 → fd00:1::77         [ACK]       Ack=1595
2.999  TCP     fd00:1::1 → fd00:1::77         [PSH,ACK]   len 5      "quit\n"  (request)
3.001  TCP     fd00:1::77 → fd00:1::1         [PSH,ACK]   len 35     "SERVICE CLOSING" banner
3.001  TCP     fd00:1::1 → fd00:1::77         [ACK]       Ack=1630
3.005  TCP     fd00:1::77 → fd00:1::1         [FIN,ACK]              PyTCP active close
3.045  TCP     fd00:1::1 → fd00:1::77         [ACK]       Ack=1631   peer acks the FIN
6.001  TCP     fd00:1::1 → fd00:1::77         [FIN,ACK]              peer closes its half
6.002  TCP     fd00:1::77 → fd00:1::1         [ACK]       Ack=13     connection fully closed (no RST)
```

(`tshark` labels the port-7 data segments "ECHO" — a heuristic;
they are plain TCP.)

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

On the wire (`tshark -i tap7`, rebased to the request; the
summary carries the IPv4 fragmentation fields — IP-id, MF,
frag-offset):

```text
0.000  UDP  192.168.1.10 → 192.168.1.77   id=0x9655 MF=0 off=0     UDP "malpi\n" request (14 B)
0.001  ARP  192.168.1.77 → 192.168.1.10   Who has 192.168.1.10? Tell 192.168.1.77
0.001  ARP  192.168.1.10 → 192.168.1.77   192.168.1.10 is at a2:4b:a1:00:92:56
0.001  UDP  192.168.1.77 → 192.168.1.10   id=0x0001 MF=1 off=0     fragment 1 — UDP header + first 1480 B
0.002  UDP  192.168.1.77 → 192.168.1.10   id=0x0001 MF=0 off=185   fragment 2 — final 89 B (offset 185×8 = 1480)
```

The oversized UDP datagram is split into two IPv4 fragments sharing
one IP id; the peer's kernel reassembles them and `nc -u` prints
the monkeys. The first datagram is held in the per-neighbour queue
until the ARP reply resolves the peer's MAC (RFC 1122 §2.3.2.2),
then both fragments are flushed in order — a fragmented datagram
delivered to a cold neighbour, lost by neither the DF bit nor a
single-slot queue.

#### Monkeys over UDP — over IPv6

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip6-udp-monkeys
```

The same oversized echo over IPv6. IPv6 fragments differently from
IPv4: the base header is never modified — the source inserts a
**Fragment extension header** (RFC 8200 §4.5), and only the source
may fragment. The stack resolves the peer via ICMPv6 Neighbor
Discovery (NS → NA), then emits the ~1.5 KB reply as two IPv6
fragments sharing one identification:

```text
0.000  UDP     fd00:1::1 → fd00:1::77        "malpi\n" request
0.001  ICMPv6  fd00:1::77 → ff02::1:ff00:1   Neighbor Solicitation for fd00:1::1   (from 02:00:00:77:77:77)
0.001  ICMPv6  fd00:1::1 → fd00:1::77        Neighbor Advertisement — fd00:1::1 is at a2:4b:a1:00:92:56
0.002  IPv6    fd00:1::77 → fd00:1::1        Fragment header: off=0 more=1 ident=0xc6713a45 next=UDP  (fragment 1)
0.002  UDP     fd00:1::77 → fd00:1::1        final fragment — reassembles to the 1569-byte datagram
```

(`tshark` labels the port-7 datagrams "ECHO" — a heuristic; they
are plain UDP. The 1561-byte reply + 8-byte UDP header = 1569 B,
over the 1500-byte link MTU, so the stack splits it across the two
fragments above.)

#### Inbound IPv4 reassembly (oversized ping)

**Reproduce:**

```bash
sudo PYTHONPATH=. venv/bin/python -m tools.capture ip4-icmp-frag-rx --count 1
```

The receive-side counterpart of the fragmentation demos. The host
sends a 4000-byte `ping`, which its kernel splits into three IPv4
fragments. The stack **reassembles** them into one Echo Request,
then replies with a 4000-byte Echo Reply that it **itself
fragments** into three:

```text
0.000  IPv4  192.168.1.10 → 192.168.1.77   id=0xf29f MF=1 off=0    Echo Request — fragment 1/3
0.000  IPv4  192.168.1.10 → 192.168.1.77   id=0xf29f MF=1 off=185  fragment 2/3   (off 185×8 = 1480 B)
0.000  IPv4  192.168.1.10 → 192.168.1.77   id=0xf29f MF=0 off=370  fragment 3/3 → reassembles to Echo Request id=0x6271, seq=1
0.001  ARP   192.168.1.77 → 192.168.1.10   Who has 192.168.1.10? Tell 192.168.1.77
0.001  ARP   192.168.1.10 → 192.168.1.77   192.168.1.10 is at a2:4b:a1:00:92:56
0.002  IPv4  192.168.1.77 → 192.168.1.10   id=0x0001 MF=1 off=0    Echo Reply — fragment 1/3
0.002  IPv4  192.168.1.77 → 192.168.1.10   id=0x0001 MF=1 off=185  fragment 2/3
0.002  IPv4  192.168.1.77 → 192.168.1.10   id=0x0001 MF=0 off=370  fragment 3/3 → Echo Reply id=0x6271, seq=1
```

From the pinging host:
`1 packets transmitted, 1 received, 0% packet loss; rtt min/avg/max/mdev = 2.048/2.048/2.048/0.000 ms`
(`4008 bytes from 192.168.1.77` — the full 4000-byte payload made
the round trip, reassembled on both ends).

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
precedes the first Discover:

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
invariant is that it *completes*), rebased to the SYN:

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
