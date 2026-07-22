# PyTCP

Pure-Python, zero-dependency TCP/IP stack — Ethernet through
RFC 9293 TCP — running in user space on a TAP/TUN interface, run as a
daemon that off-the-shelf programs drive unmodified through a 1:1
stdlib-`socket` drop-in, plus a `pytcp` CLI multitool.

```python
from pytcp import socket, stack
```

## What it is

A full, RFC-grounded TCP/IP stack implemented entirely in Python:
Ethernet II / 802.3 (LLC/SNAP), ARP, IPv4 / IPv6 (with Hop-by-Hop /
Destination-Options / Routing / Fragment extension headers),
ICMPv4 / ICMPv6 (incl. Neighbor Discovery, MLDv2 with MLDv1 fallback,
and IGMP IPv4 multicast group membership), DHCPv4 and DHCPv6 clients,
UDP, and a RFC 9293 TCP with a real FSM, congestion control
(Reno / NewReno / CUBIC), SACK / timestamps / window-scaling, and a
BSD-sockets facade. It runs on a TAP/TUN interface in user space — no
kernel module, no privileged data path. It runs as a **daemon** that
out-of-process clients drive over an AF_UNIX control boundary — the
kernel/userspace split described below. (It can also be embedded
in-process as a library, but that path is unsupported.)

The project's north star is **feature-equivalence with the Linux
host network stack**: where an RFC is unambiguous PyTCP follows it,
and where it is silent or offers a menu PyTCP picks the Linux
choice. Per-RFC adherence is audited under
[`docs/rfc/`](https://github.com/ccie18643/PyTCP/tree/master/docs/rfc).

## The three distributions

PyTCP is strictly layered into three independently-published dists
(one invariant: project folder == import name):

| Distribution | Import | Role |
|---|---|---|
| [`PyTCP-net_addr`](https://pypi.org/project/PyTCP-net_addr/) | `net_addr` | Address value types (IPv4/IPv6/MAC, networks, masks, wildcards, interface-addresses). |
| [`PyTCP-net_proto`](https://pypi.org/project/PyTCP-net_proto/) | `net_proto` | Protocol packet parse / assemble / validate. |
| **`PyTCP`** | `pytcp` | The running stack: subsystems/threads, sockets, FIB, ARP/ND caches, RX/TX rings. |

Installing `PyTCP` pulls the other two automatically (lockstep
version pin).

## Runtime architecture

```
TAP/TUN fd ─> RxRing ─> PacketHandler (per protocol, RX) ─> Socket queues / ARP+ND caches / fragment store
           <─ TxRing <─ PacketHandler (per protocol, TX) <─ Socket send / ND / DHCP / ACD
```

- **`Subsystem` base** — every background service (RX/TX rings,
  neighbor caches, timer, DHCPv4 / DHCPv6 clients, link-local / ACD)
  extends `Subsystem` and runs its own thread with an event-driven
  loop.
- **Packet handlers** — RX and TX paths are composed from
  per-protocol sub-handlers (`packet_handler__<proto>__<rx|tx>.py`).
  Every branch bumps a per-protocol stat counter for observability.
- **Event-driven timer** — a heap-based deadline scheduler (no
  polling tick); subsystems register deadlines and are woken on the
  nearest one.
- **Per-interface model** — a `PacketHandler` *is* an interface. A
  multi-homed host runs one handler per interface; global tables
  (routing FIB, socket table, neighbor caches) are shared and
  lock-guarded.

### Free-threaded (no-GIL) safety

Per-interface state is partitioned (single-writer TX ring hand-off);
the shared global tables (`RouteTable`, `SocketTable`,
`InterfaceTable`) guard their compound (check-then-act) operations
with a small `threading.Lock` and hand readers consistent snapshots.
Single built-in dict/list ops are left lock-free (individually
atomic).

## Control-plane APIs (the Phase-3 kernel/userspace boundary)

Consumers talk to the stack only through sanctioned surfaces — never
by reaching into runtime internals — mirroring how a Linux process
talks to its kernel:

| API | Linux equivalent |
|---|---|
| `pytcp.runtime.socket` (in-process) / `pytcp.socket` daemon drop-in — BSD `socket()` factory + methods (TCP / UDP / raw / `AF_PACKET`) | `socket(2)` |
| `pytcp.stack.sysctl` — runtime-tunable policy registry | `/proc/sys/net/` |
| `pytcp.stack.link` — per-interface MAC / MTU / state / counters | `ip link` / `RTM_*LINK` |
| `pytcp.stack.address` — assign / remove IPv4 / IPv6 host addresses | `ip addr` / `RTM_*ADDR` |
| `pytcp.stack.route` — add / remove / list routes (FIB); `Route` / `RouteProtocol` / `RouteScope` | `ip route` / `RTM_*ROUTE` |
| `pytcp.stack.neighbor` — static ARP / ND entries, cache flush | `ip neighbor` / `RTM_*NEIGH` |
| read-only snapshots (route table, neighbor cache, socket list, counters) | `/proc/net/*`, `ss` |

### Lifecycle

`stack.init(...)` builds the singletons, `stack.add_interface(...)` /
`stack.remove_interface(...)` attach / detach interfaces at runtime
(RTNETLINK `RTM_NEWLINK` / `RTM_DELLINK` semantics, including the
address / route / neighbor / session teardown cascade), `stack.start()`
spawns the subsystem threads, and `stack.stop()` winds them down.
A stack can `init()` with zero interfaces and gain them later — the
daemon / multi-homed shape.

### Sockets

The in-process socket facade, `pytcp.runtime.socket`, mirrors the
stdlib `socket` module: a `socket(...)` factory returns `TcpSocket` /
`UdpSocket` / `RawSocket` / `PacketSocket` (plus an unprivileged
ICMP-Echo datagram socket, `SOCK_DGRAM`+`IPPROTO_ICMP`/`ICMPV6`, that
backs `pytcp ping`), with `bind` / `listen` /
`accept` / `connect` / `send` / `recv` / `close`, `fileno()` + eventfd
for `selectors` integration, blocking & non-blocking modes,
errno-mapped `OSError`, `getaddrinfo`, common `setsockopt` options,
IPv4/IPv6 multicast group membership and source-filter options
(`IP_ADD_MEMBERSHIP`, `IP_ADD_SOURCE_MEMBERSHIP`, `IPV6_JOIN_GROUP`, …),
and an `IP_RECVERR` / `MSG_ERRQUEUE` error queue. Stdlib-parity
constants (`AF_INET`, `SOCK_STREAM`, `IP_*`, `SO_*`, `MSG_*`) are
exposed as bare module names backed by `IntEnum`s.

The top-level **`pytcp.socket`** name is the daemon-backed **1:1
stdlib-`socket` drop-in** (see *Daemon mode* below): the same surface,
but each socket is opened on a running daemon and off-the-shelf code
adopts it by changing one import line.

## Daemon mode — out-of-process clients

The stack runs as a **daemon**: a normal in-process stack that also
listens on an AF_UNIX control socket, so a **separate process** opens
sockets and drives the control-plane APIs through `pytcp.client` —
exactly the way a Linux process talks to the kernel. The client never
boots the stack; it holds real, `selectors`-pollable socket fds handed
to it across the boundary via `SCM_RIGHTS`.

Start the daemon (it owns the TAP interface); the first-class entry
point ships in the package as `python -m pytcp.daemon` (or the `pytcpd`
console script after install), defaulting the control socket to
`$XDG_RUNTIME_DIR/pytcp.sock`:

```bash
python -m pytcp.daemon --ipc-socket /tmp/pytcp.sock
```

Then, from any other process — note it imports `pytcp.client`, boots
no stack, and calls no `stack.init()`:

```python
from pytcp.client import connect
from pytcp.socket import AddressFamily, SocketType

with connect(socket_path="/tmp/pytcp.sock") as client:
    sock = client.socket(AddressFamily.INET4, SocketType.STREAM)
    sock.connect(("10.0.1.1", 7))   # a real, selectable fd backs this socket
    sock.send(b"hello")
    print(sock.recv(5))
```

The same `client.socket(...)` factory returns UDP / raw / `AF_PACKET`
sockets, and `client.sysctl` / `.route` / `.link` / `.address` /
`.neighbor` / `.membership` mirror the control APIs across the boundary.

### The 1:1 stdlib-`socket` drop-in

For off-the-shelf programs that expect the standard `socket` module,
the top-level **`pytcp.socket`** package is a daemon-backed drop-in — an
app runs over the daemon by changing one import line
(`import pytcp.socket as socket`, or `sys.modules["socket"] =
pytcp.socket`). It covers blocking **and** non-blocking / `select` /
`selectors` use, `connect_ex` / `EINPROGRESS`, non-blocking `accept`,
faithful `errno` / exception reconstruction, `makefile` / `dup` /
`detach`, and DNS resolved *through* the daemon's own stack
(`getaddrinfo` / `gethostbyname`). Real stdlib `http.client` and
`asyncio` client/server programs run unmodified over it. The runnable
apps live in [`examples/`](https://github.com/ccie18643/PyTCP/tree/master/examples)
(async FTP, TCP/UDP echo, multicast discovery).

### The `pytcp` CLI multitool

A single zero-dependency `pytcp` command (console script; also
`python -m pytcp.cli`) manages and drives the daemon with
Linux-tool-lookalike subcommands: `pytcp stack start / stop`,
the control-plane introspectors `pytcp ss / link / address / route /
neighbor / sysctl` (faithful, parseable layouts), and the
batteries-included network tools `pytcp ping / host / nc / traceroute /
tcpdump` (the last a daemon-native capture that decodes both ingress and
egress).

## Install

```bash
pip install PyTCP
```

Brings in `PyTCP-net_proto` and `PyTCP-net_addr` — no other
runtime dependencies (the whole stack is stdlib-only).
Fully typed (ships `py.typed`, PEP 561); strict-mypy clean.

## Running the stack

Running needs one or more TAP/TUN interfaces (root for interface /
bridge setup). Bridged TAP interfaces (Ethernet) are created on the
`br0` bridge, so the bridge comes first:

```bash
make bridge                     # create the br0 bridge (sudo)
make tap7                       # create tap7, add it to br0 (sudo)
make tap9                       # create a second tap, tap9, on br0 (sudo)
sudo pytcp stack start -i tap7  # run the stack daemon on tap7
sudo pytcp stack start -i tap7 -i tap9   # multi-interface (repeat -i)
```

Point-to-point TUN interfaces (IP), each created pre-addressed and
needing no bridge, are also available — `make tun3`
(172.16.1.1/24, 2001:db8:1::1/64) and `make tun5`
(172.16.2.1/24, 2001:db8:2::1/64) set up the host side; run the stack on
one with `sudo pytcp stack start -i tun3`. A stack can `init()` with
zero interfaces and add / remove them at runtime, so any mix of taps and
tuns can be attached to one running stack.

The supported way to run PyTCP is as a daemon, driven out-of-process
through the daemon-backed `pytcp.socket` drop-in, the explicit
`pytcp.client` API, or the `pytcp` CLI. See
[`examples/`](https://github.com/ccie18643/PyTCP/tree/master/examples)
for daemon-backed applications over the drop-in. In-process embedding
via the `stack` lifecycle + `pytcp.runtime.socket` API still works but is
unsupported.

## Requirements

Python **3.14+**, Linux (TAP/TUN), POSIX.

## Current state (3.0.8)

- ~240 source modules. On top of the 3.0.7 kernel/userspace IPC layer
  (`ipc` AF_UNIX RPC + SCM_RIGHTS fd-passing, a `client` out-of-process
  mirror, a first-class `daemon` entry point), 3.0.8 adds the two
  user-facing layers on top of that boundary: the **1:1 stdlib-`socket`
  drop-in** (`pytcp.socket`, blocking + non-blocking / asyncio, DNS
  through the daemon) and the **`pytcp` CLI multitool** (`stack` /
  `ss` / `link` / `address` / `route` / `neighbor` / `sysctl` + `ping` /
  `host` / `nc` / `traceroute` / `tcpdump`), plus a **loopback interface**
  (`lo`, 127.0.0.0/8 · ::1, own-IP local delivery). The pytcp suite runs
  ~4,800 unit + integration tests (the full repo suite, across all
  three packages + examples, is ~13,450). Lint clean (codespell +
  isort + black + flake8 + mypy strict + pylint + pyright +
  import-linter).
- Host-stack feature-complete (North Star Phase 1), reachable
  in-process, over an out-of-process **daemon** boundary (AF_UNIX
  control plane + SCM_RIGHTS socket-fd passing for TCP / UDP / raw /
  `AF_PACKET`), and as a one-line stdlib-`socket` swap. Phase-2
  router/forwarding sits behind the `forward_or_deliver` seam as a
  stub. Authoring contracts in
  [`.claude/rules/pytcp.md`](https://github.com/ccie18643/PyTCP/blob/master/.claude/rules/pytcp.md); per-RFC
  adherence in [`docs/rfc/`](https://github.com/ccie18643/PyTCP/tree/master/docs/rfc).

## Changelog

See [`CHANGELOG.md`](https://github.com/ccie18643/PyTCP/blob/master/packages/pytcp/CHANGELOG.md).

## License

GPL-3.0-or-later. PyTCP by Sebastian Majewski.
