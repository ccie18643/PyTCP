# Changelog

All notable changes to **PyTCP** are recorded here. This package (the
running stack, daemon, socket surfaces, and `pytcp` CLI) is released in
lockstep with `PyTCP-net_proto` and `PyTCP-net_addr` — they share a
version. Releases before 3.0.8 are on the
[GitHub Releases page](https://github.com/ccie18643/PyTCP/releases).

## 3.0.9 — Unreleased

_Development in progress._ The Phase-2 router track — 3.0.9 turns the
multi-homed host into a router.

### Added

- **IGMPv3 / MLDv2 multicast-router querier.** An interface configured
  as a multicast router (`igmp.mc_forwarding` / `mld.mc_forwarding`)
  takes the querier role on its link, for both IPv4 (IGMP) and IPv6
  (MLD):
  - emits periodic **General Queries** — a startup burst (Startup Query
    Count / Interval) settling into the steady-state Query Interval;
  - runs **querier election** (RFC 3376 §6.6.2 / RFC 3810 §7.6.2, lowest
    interface address wins) with the Other Querier Present timeout that
    resumes the role when the elected querier goes silent;
  - learns **downstream reception state** from inbound Reports into a
    per-group membership table (filter mode + source list), pruned by
    the Group Membership / Multicast Address Listening Interval;
  - on a leave, sends **fast-leave** Group-Specific / Multicast-Address-
    Specific Queries (RFC 3376 §6.4.2 / RFC 3810 §7.6.3) that prune the
    group in the Last Member/Listener Query Time instead of the full
    interval.

  Read-only introspection via
  `PacketHandler.{igmp,mld}_querier_memberships()`.
- **Multicast forwarding — last-hop replication.** A transit multicast
  datagram that passes the Reverse Path Forwarding check is replicated
  out every interface with a downstream listener, for both families:
  scope filtering (IPv4 224.0.0.0/24 + TTL 1, IPv6 scope nibble ≤ 2 +
  Hop Limit 1), the RPF check against the unicast FIB, an on-demand
  egress set computed from the querier membership tables (honouring the
  INCLUDE / EXCLUDE source filter), and byte-identical re-emit to the
  group's Ethernet multicast MAC. A multicast-router interface receives
  multicast promiscuously. No multicast routing protocol (PIM / DVMRP)
  and no `MRT_*` mrouted API — last-hop only, the forwarding table is
  built purely from local querier state.
- **Querier sysctls** — per-interface `{igmp,mld}.mc_forwarding`, plus
  `{igmp,mld}.query_response_interval`, `.startup_query_interval`,
  `.startup_query_count`, and `igmp.last_member_query_interval` /
  `igmp.last_member_query_count` (`mld.last_listener_query_*`).

## 3.0.8 — 2026-07-23

The daemon-backed userspace. 3.0.7 split the stack into a daemon that
owns the interface and a thin client boundary; 3.0.8 builds the
user-facing layers on top: off-the-shelf Python network programs run
**unmodified** against a running daemon through a 1:1 stdlib-`socket`
drop-in, a full `pytcp` CLI multitool operates the stack, and a
stack-internal loopback interface lets one daemon talk to itself.

> **Daemon mode is now the official, supported way to run the stack.**
> Boot it with `sudo pytcp stack start -i tap7` (autoconfigures via
> DHCPv4) or `python -m pytcp.daemon` for a static address. In-process
> embedding still works but is explicitly unsupported.

### Added

- **Drop-in stdlib-`socket` replacement.** `from pytcp import socket`
  returns real, `selectors`-pollable descriptors backed by the daemon
  over its AF_UNIX control boundary. Blocking programs and `asyncio`
  servers/clients run unchanged — including non-blocking
  `connect` / `accept`, `getpeername` / `ENOTCONN` parity, `SO_ERROR`,
  honored `SO_RCVBUF`, `sendmsg` with `IP_TOS` / `IPV6_TCLASS` cmsg,
  and survival across a `sys.modules['socket']` swap.
- **`pytcp` CLI multitool** — one command over the daemon: `ping`,
  `host` (DNS lookup), `nc` (netcat), `traceroute` (UDP default, `-I`
  for ICMP), and `tcpdump`, plus `ss`, `link`, `address`, `route`,
  `neighbor`, and `sysctl` to introspect and drive the control plane.
  `stack start` / `stack stop` manage the daemon lifecycle;
  `python -m pytcp` runs the package directly.
- **Loopback interface** — a real `lo` inside the stack: locally
  destined IP TX is diverted onto a loopback ring and delivered back
  up, so a server and client sharing one daemon can talk over
  `127.0.0.1` / `::1` / their own address, end to end (including TCP).
- **Unprivileged ICMP-Echo (ping) socket** —
  `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` (the Linux `ping`
  datagram-socket model) with a raw-socket fallback, wired through the
  daemon, the drop-in, the in-process factory, and the `pytcp ping`
  engine.
- **Raw-socket Linux parity** — `SOCK_RAW` over the drop-in; IPv4 raw
  recv delivers the full IP packet; unbound raw RX receives a copy of
  all matching traffic; TTL / Hop-Limit delivered as cmsg; the
  mandatory ICMPv6 checksum auto-computed; egress-aware source
  selection for multi-homed hosts.
- **AF_PACKET egress tap + `pytcp tcpdump`** — an `AF_PACKET`-style
  egress tap (`dev_queue_xmit_nit` parity) captures outbound frames,
  including the ARP/ND queued-packet flush path and loopback traffic.
  `pytcp tcpdump` captures both directions daemon-native, decodes via
  **tshark** when available (built-in fallback for ICMPv4/v6 and IPv4
  fragments), and the daemon can capture **from boot** (`--capture` /
  `--capture-pcap`) to record its own autoconfiguration.

- **MLDv2 leave reporting** — leaving an IPv6 multicast group now emits
  a departure (a CHANGE_TO_INCLUDE State Change Report, or an MLDv1 Done
  in v1 compatibility mode), and stack shutdown gracefully leaves every
  joined group — the IPv6 analogue of the IGMP leave, closing the last
  host-conformance gap in the multicast plane.

- **TCP send/receive buffer sizing and auto-tuning.** `SO_RCVBUF` now
  drives the advertised receive window (grow-only on a mid-connection
  raise so the window's right edge is never retracted), and `SO_SNDBUF`
  bounds the send buffer with TCP byte-stream backpressure — a full
  buffer blocks honoring `SO_SNDTIMEO`, does a partial write, or returns
  `EAGAIN`. On top of that, Linux-style auto-tuning: receive-buffer
  Dynamic Right-Sizing grows the advertised window toward the
  bandwidth-delay product (`tcp_rcv_space_adjust`), and the send buffer
  grows with the congestion window (`tcp_sndbuf_expand`) — working on
  both timestamped and timestamp-less connections, with the receive
  window scale sized at SYN for the configured ceiling. New
  `tcp.rmem` / `tcp.wmem` (min/default/max) and `tcp.moderate_rcvbuf`
  sysctls make the buffer bounds and DRS operator-tunable
  (`net.ipv4.tcp_rmem` / `tcp_wmem` / `tcp_moderate_rcvbuf` parity). The
  conservative default buffer sizes are unchanged, so a connection that
  sets no option and no sysctl behaves exactly as before.

### Changed

- Examples reworked around the daemon (async TCP/UDP echo, FTP,
  multicast service discovery, ping) over the drop-in. The pre-3.0.7
  in-process `examples_legacy/` tree was removed; the README now leads
  with a daemon-first Quickstart.

### Fixed

- DHCPv4 client INIT / mid-recv paths are now responsive to `stop()`
  (no more wedged `pytcp stack start`).
- `pytcp ping` fails cleanly when the daemon is down.
- Graceful CRITICAL exit when an interface cannot be opened.

### Tooling

- `make lint` gate expanded: pyright gated, import-linter architectural
  contracts, 8 more mypy strict error codes, and a large pylint
  regression-guard allowlist; TYPE_CHECKING / circular-import cruft
  flattened via a Protocol-seam pattern.

### Compatibility

Requires Python 3.14+. Depends on `PyTCP-net_proto==3.0.8` and
`PyTCP-net_addr==3.0.8` (released in lockstep).
