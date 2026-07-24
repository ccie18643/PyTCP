# RFC 1122 §4.1 — Host Requirements for UDP

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 1122 (UDP section §4.1 only)                   |
| Title       | Requirements for Internet Hosts — Communication Layers |
| Author      | R. Braden (Editor)                             |
| Category    | Internet Standard (STD 3)                      |
| Date        | October 1989                                   |
| Source text | [`rfc1122.txt`](rfc1122.txt) §4.1 (pages 77-80) |

This document audits RFC 1122 §4.1's UDP-specific clauses
against the current PyTCP codebase. The full RFC 1122 is
already mirrored elsewhere (IPv4, ICMPv4, ARP families);
this record narrows to §4.1 and is the natural extension of
[RFC 768](../rfc768__udp/adherence.md). The audit was
performed by reading §4.1 fresh and inspecting
`packages/net_proto/net_proto/protocols/udp/`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__tx.py`,
and `packages/pytcp/pytcp/runtime/socket/udp__socket.py` directly. Sections
without normative content (§4.1.1 Introduction, §4.1.2
Protocol Walk-Through — "There are no known errors in the
specification of UDP", §4.1.5 Requirements Summary table)
are omitted; the Requirements Summary table is reproduced
in the Overall Assessment section as a row-by-row mapping.

---

## Top-line summary

PyTCP **meets** every MUST in §4.1 except one — the
"Sender Option to not generate checksum" MAY (4.1.3.4)
is not exposed at the socket layer, but as a MAY it is
not a conformance gap. Two SHOULDs and one MAY are
partial:

- §4.1.3.1 ICMP Port Unreachable: **met** — emitted with
  rate-limiting (RFC 1122 §3.2.2 generation gate already
  enforced).
- §4.1.3.5 "communicate chosen source address up to
  application layer": **met** — `getsockname()` returns
  the bound local address.
- §4.1.3.6 "Invalid IP source address must be discarded":
  met (filtered at the IP layer). PyTCP drops broadcast
  and multicast UDP sources via the IPv4 / IPv6 parser
  sanity checks before the UDP layer ever sees the
  packet. Directed-broadcast sources (e.g. `10.0.1.255`
  for a `/24`) are dropped in the IPv4 RX packet handler
  against the configured `_ip4_broadcast` table.
- §4.1.4 "MAY pass received TOS up to application layer":
  **met** — `IP_TOS` is settable on TX (per-socket
  override); the RX path surfaces the received TOS byte
  through `recvmsg` as an `IP_TOS` cmsg when
  `IP_RECVTOS` is set on the socket. The parallel IPv6
  surface (`IPV6_RECVTCLASS` / `IPV6_TCLASS` cmsg) is
  also wired per RFC 3542 §6.5.

| §       | Topic                                          | Status                                    |
|---------|------------------------------------------------|-------------------------------------------|
| §4.1.3.1 | UDP send Port Unreachable                     | met (with rate-limiting per §3.2.2)       |
| §4.1.3.2 | IP options pass-through (RX + TX)             | met (RX via recvmsg + IP_RECVOPTS; TX via setsockopt(IP_OPTIONS)) |
| §4.1.3.3 | Pass ICMP errors up to application            | met (notify_* socket callbacks for legacy data-path; full ICMP context — type / code / errno / offender / embedded datagram — surfaces via recvmsg(MSG_ERRQUEUE) when IP_RECVERR / IPV6_RECVERR is set) |
| §4.1.3.4 | Generate + check checksum (MUST)              | met                                        |
| §4.1.3.4 | Silently discard bad checksum                 | met                                        |
| §4.1.3.4 | Sender option to skip checksum (MAY)          | not implemented (MAY, no PyTCP consumer)   |
| §4.1.3.4 | Default is to checksum (MUST)                 | met (assembler always computes)           |
| §4.1.3.4 | Receiver option to require checksum (MAY)     | not implemented (MAY, no PyTCP consumer)   |
| §4.1.3.4 | Computed-zero-cksum → all-ones (MUST)         | met — both UDP TX paths substitute `0xFFFF` for a computed `0x0000` |
| §4.1.3.5 | Pass specific-destination addr to application | met (via PacketRx + UdpMetadata)          |
| §4.1.3.5 | Application can specify local IP / wildcard   | met (`bind()`)                             |
| §4.1.3.5 | Application notified of local IP used         | met (`getsockname()`)                      |
| §4.1.3.6 | Bad IP src addr silently discarded by UDP/IP  | met (limited-broadcast / multicast / reserved filtered at IP-layer parser; directed-broadcast filtered at IPv4 RX packet handler; unspecified filtered at UDP layer) |
| §4.1.3.6 | Only send valid IP source address             | met (TX source picked from host's `_ip4_ifaddr` / `_ip6_ifaddr`) |
| §4.1.4   | Application MUST set TTL, TOS, IP options     | met for TTL + TOS; not implemented for IP options |
| §4.1.4   | Pass received TOS up to application (MAY)     | met (recvmsg IP_TOS cmsg gated by IP_RECVTOS) |

---

## §4.1.3.1 Ports — ICMP Port Unreachable

> "If a datagram arrives addressed to a UDP port for which
>  there is no pending LISTEN call, UDP SHOULD send an ICMP
>  Port Unreachable message."

**Adherence:** met. The RX dispatch at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:180-230`
walks the socket table; on no match the path emits ICMPv4
or ICMPv6 Destination Unreachable (code = port) subject to
the `try_emit_icmp_error` host-requirements gate and the
outbound rate limiter. The IPv4 path bumps
`udp__no_socket_match__respond_icmp4_unreachable` /
`udp__no_socket_match__icmp4_unreachable_suppressed`; the
IPv6 path bumps the v6 counterparts. The "SHOULD" is
honoured by emission; the rate-limit gate is the
canonical exception (RFC 1122 §3.2.2 SHOULD allow
suppression).

---

## §4.1.3.2 IP Options

> "UDP MUST pass any IP option that it receives from the IP
>  layer transparently to the application layer.
>
>  An application MUST be able to specify IP options to be
>  sent in its UDP datagrams, and UDP MUST pass these
>  options to the IP layer."

**Adherence:** met. PyTCP plumbs the IPv4 options block
through the UDP socket API in both directions:

- **RX pass-through.** `UdpMetadata.ip4__options`
  (`packages/pytcp/pytcp/runtime/socket/udp__metadata.py`) carries the inbound
  IPv4 options object; the UDP RX handler populates it
  from `packet_rx.ip4.options` at
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`.
  Applications retrieve the raw options block via
  `recvmsg(ancbufsize > 0)` on a socket that has
  `setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)` enabled; the
  cmsg shape is `(IPPROTO_IP, IP_OPTIONS, raw_bytes)` —
  matching Linux's `<sys/socket.h>` ancillary-data format
  for IP_OPTIONS.

- **TX pass-through.** `setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)`
  (`packages/pytcp/pytcp/runtime/socket/__init__.py::_ipproto_ip_setsockopt`)
  validates the bytes block (≤ 40 bytes, 4-byte aligned,
  parseable as IPv4 options) and stores it on the socket
  as `_ip_options`. Subsequent `send()` / `sendto()` calls
  thread the parsed options through
  `_phtx_udp` → `_phtx_ip4` via the existing
  `ip4__options` parameter
  (`packet_handler__ip4__tx.py`). The outbound IPv4
  header carries the options; the assembler's hlen
  reflects them; the existing fragment-aware TX path
  copies them per RFC 791 §3.1 copy-flag rules.

The Linux socket-option numeric values are mirrored:
`IP_OPTIONS = 4`, `IP_RECVOPTS = 6`, `IP_RETOPTS = 7`
(deprecated alias).

The setsockopt validator rejects unaligned, oversize, and
malformed option blocks with `OSError(EINVAL)`, matching
Linux's setsockopt behaviour.

---

## §4.1.3.3 ICMP Messages

> "UDP MUST pass to the application layer all ICMP error
>  messages that it receives from the IP layer."

**Adherence:** met. The ICMPv4 / ICMPv6 RX dispatch hands
off transport-layer-targeted errors to the socket via the
`notify_*` callbacks:

- `notify_unreachable()` at
  `packages/pytcp/pytcp/runtime/socket/udp__socket.py:1033`
- `notify_time_exceeded(icmp_type, icmp_code)` at
  `udp__socket.py:1065`
- `notify_parameter_problem(icmp_type, icmp_code)` at
  `udp__socket.py:1093`
- `notify_pmtu(next_hop_mtu)` at `udp__socket.py:1213`

The classification happens in
`packages/pytcp/pytcp/protocols/icmp/icmp__inbound_classifier.py` and
`icmp__error_demux.py`; the dispatch routes to the
matching UDP socket via the embedded-datagram 4-tuple. The
Linux MSG_ERRQUEUE surface is wired: `setsockopt(IP_RECVERR, 1)`
or `setsockopt(IPV6_RECVERR, 1)` enables per-socket error
queueing; `recvmsg(flags=MSG_ERRQUEUE)` dequeues an entry
returning `(embedded_datagram, [cmsg], MSG_ERRQUEUE, offender_addr)`
where the cmsg payload is the packed Linux
`struct sock_extended_err` (`ee_errno`, `ee_origin`,
`ee_type`, `ee_code`, `ee_info` carrying next-hop MTU on
PMTU errors) followed by the offender's `sockaddr_in` /
`sockaddr_in6`. The errno is mapped per Linux's
`icmp_err_convert` table (`packages/pytcp/pytcp/runtime/socket/error_queue.py`).

The legacy BSD single-error surface
(`ConnectionRefusedError` on next `recv()` after a
Port-Unreachable) remains wired alongside the error
queue for backwards compatibility.

**Conformance verdict:** met at the protocol layer AND
the Linux application API (`IP_RECVERR` / `MSG_ERRQUEUE`
matches stdlib `socket.IP_RECVERR` / `socket.MSG_ERRQUEUE`
shape, so Python stdlib programs work unchanged).

---

## §4.1.3.4 UDP Checksums

> "A host MUST implement the facility to generate and
>  validate UDP checksums."

**Adherence:** met. `inet_cksum` at
`packages/net_proto/net_proto/lib/inet_cksum.py` is the canonical engine;
assembler at
`packages/net_proto/net_proto/protocols/udp/udp__assembler.py:79-83` computes
on TX; parser at
`packages/net_proto/net_proto/protocols/udp/udp__parser.py:91-94` verifies on
RX.

> "An application MAY optionally be able to control
>  whether a UDP checksum will be generated, but it MUST
>  default to checksumming on."

**Adherence:** the **MUST** is met — `udp__assembler.py`
unconditionally computes a checksum, so the default is
"on." The **MAY** (sender-side opt-out) is **not
implemented**; PyTCP has no `SO_NO_CHECK` socket option.
A MAY without a PyTCP consumer is not a gap.

> "If a UDP datagram is received with a checksum that is
>  non-zero and invalid, UDP MUST silently discard the
>  datagram."

**Adherence:** met. The parser's integrity check at
`udp__parser.py:91-94`:

```python
if int.from_bytes(self._frame[6:8]) != 0 and inet_cksum(...):
    raise UdpIntegrityError("The packet checksum must be valid.")
```

The RX dispatch at `packet_handler__udp__rx.py:113-119`
catches `UdpIntegrityError` (silent drop) and bumps
`udp__failed_parse__drop`. No ICMP error is generated,
matching the SHOULD-silent-discard.

> "An application MAY optionally be able to control
>  whether UDP datagrams without checksums should be
>  discarded or passed to the application."

**Adherence:** not implemented (MAY, no PyTCP consumer).
The current parser unconditionally accepts cksum=0 RX
("no checksum was generated"). Linux's `IP_NODEFRAG`-
adjacent `UDP_NO_CHECK6_RX` socket option would land here
if implemented; tracked in the
[RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md)
task.

> "If the transmitter really calculates a UDP checksum of
>  zero, it must transmit the checksum as all 1's
>  (65535)."

**Adherence:** met. Documented at length in the
[RFC 768 audit](../rfc768__udp/adherence.md) §"Fields —
Checksum"; both UDP serialization paths substitute
`0xFFFF` for a computed-zero checksum via the idiomatic
`(cksum or 0xFFFF)` short-circuit —
`udp__assembler.py:103` (multi-buffer `assemble`) and
`udp__base.py:104` (single-buffer `__buffer__`).

---

## §4.1.3.5 UDP Multihoming

> "When a UDP datagram is received, its specific-
>  destination address MUST be passed up to the application
>  layer."

**Adherence:** met. `UdpMetadata`
(`packages/pytcp/pytcp/runtime/socket/udp__metadata.py`) carries
`ip__local_address` populated from `packet_rx.ip.dst`
(`packet_handler__udp__rx.py:188`). `recvfrom()` at
`udp__socket.py:745` and the BSD `getsockname()` at
`packages/pytcp/pytcp/runtime/socket/__init__.py:2107` expose the
specific-destination address to the application.

> "An application program MUST be able to specify the IP
>  source address to be used for sending a UDP datagram or
>  to leave it unspecified (in which case the networking
>  software will choose an appropriate source address)."

**Adherence:** met. `bind((address, port))` at
`udp__socket.py:202` accepts either a specific local
address or the wildcard (`0.0.0.0` / `::`). When the
local address is unspecified, `pick_local_ip_address`
(imported at `udp__socket.py:49`) picks an appropriate
source from the host's `_ip4_ifaddr` / `_ip6_ifaddr` list
using the matching destination-prefix rule (RFC 6724-
inspired for v6; RFC 1122 §3.3.4.3 for v4).

> "There SHOULD be a way to communicate the chosen source
>  address up to the application layer (e.g., so that the
>  application can later receive a reply datagram only
>  from the corresponding interface)."

**Adherence:** met via `getsockname()`. After `bind()`
with a wildcard, the BSD-style call returns the picked
local address.

---

## §4.1.3.6 Invalid Addresses

> "A UDP datagram received with an invalid IP source
>  address (e.g., a broadcast or multicast address) must
>  be discarded by UDP or by the IP layer (see Section
>  3.2.1.3)."

**Adherence:** met (at the IP layer per the RFC's
disjunctive wording). PyTCP splits the invalid-source
discard between two layers:

- **Broadcast and multicast sources** are rejected at
  the **IP-layer parser** sanity checks:
  - `packages/net_proto/net_proto/protocols/ip4/ip4__parser.py::_validate_sanity`
    raises `Ip4SanityError` on
    `src.is_multicast`, `src.is_reserved`, and
    `src.is_limited_broadcast`. The packet handler
    catches the error, bumps `ip4__failed_parse__drop`,
    and silently discards.
  - `packages/net_proto/net_proto/protocols/ip6/ip6__parser.py::_validate_sanity`
    raises `Ip6SanityError` on `src.is_multicast`.
    Same drop path with `ip6__failed_parse__drop`.

  These filters fire **before** the UDP layer ever
  sees the packet — UDP-layer code never runs on a
  broadcast / multicast-source datagram. The RFC's
  "discarded by UDP or by the IP layer" disjunction
  permits this exact split.

- **Unspecified source** (`0.0.0.0` / `::`) is dropped
  at the **UDP layer** at
  `packet_handler__udp__rx.py:162-171`:

  ```python
  if packet_rx.ip.src.is_unspecified:
      self._packet_stats_rx.udp__ip_source_unspecified += 1
      return
  ```

  Kept at the UDP layer because legitimate use cases
  (DHCPv4 discovery with `src=0.0.0.0`) require IP-layer
  acceptance.

**Verified by**
`packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py::TestPacketHandlerUdpRxInvalidSourceAddress`
— parametric class with three cases (IPv4 limited
broadcast, IPv4 multicast, IPv6 multicast) asserting:
the UDP parser never runs (`udp__pre_parse == 0`), the
socket dispatch never fires, and the
`ip{4,6}__failed_parse__drop` counter bumps once.

- **Directed-broadcast sources** (e.g. `10.0.1.255` for
  a host on `10.0.1.0/24`) are dropped at the **IPv4
  RX packet handler**, immediately after the parser
  succeeds:

  ```python
  if packet_rx.ip4.src in self._if._ip4_broadcast:
      self._if._packet_stats_rx.ip4__src_directed_broadcast__drop += 1
      return
  ```

  See `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py:166-167`.
  The check uses the `_ip4_broadcast` property which
  walks `_ip4_ifaddr[].network.broadcast` for every
  configured subnet. Per-subnet awareness can't live
  in the parser (parsers are stateless) so the check
  lives in the handler.

> "When a host sends a UDP datagram, the source address
>  MUST be (one of) the IP address(es) of the host."

**Adherence:** met. The TX path picks the source from
`pick_local_ip_address` against the host's configured
address list. A `sendto()` with an explicit local address
not in the host list would fail at `bind()` time, so the
invariant holds by construction.

---

## §4.1.4 UDP/Application Layer Interface

> "The application interface to UDP MUST provide the full
>  services of the IP/transport interface described in
>  Section 3.4 of this document. Thus, an application
>  using UDP needs the functions of the GET_SRCADDR(),
>  GET_MAXSIZES(), ADVISE_DELIVPROB(), and RECV_ICMP()
>  calls described in Section 3.4."

**Adherence:** met. PyTCP's BSD-socket facade maps each
abstract RFC 1122 §3.4 routine to a concrete call:

- **GET_SRCADDR** → `getsockname()` at
  `packages/pytcp/pytcp/runtime/socket/__init__.py:2107` returns the local
  address (after wildcard bind, the picked source).
- **GET_MAXSIZES** → `getsockopt(IPPROTO_IP, IP_MTU)` and
  `getsockopt(IPPROTO_IPV6, IPV6_MTU)` return the effective
  Path-MTU for a connected socket — the cached value from
  `stack.pmtu_cache` (populated by the ICMPv4 / ICMPv6
  PMTUD callbacks) when present, otherwise
  `stack.interface_mtu`. Unconnected sockets raise
  `OSError(ENOTCONN)`, matching Linux 'ip(7)' / 'ipv6(7)'
  semantics. The options are getsockopt-only;
  setsockopt rejects them with `ENOPROTOOPT`.
- **ADVISE_DELIVPROB** → not exposed (PyTCP has no
  routing-failure-rate feedback mechanism; the closest
  proxy is `notify_pmtu` from inbound ICMP "Packet Too
  Big" / "Fragmentation Needed").
- **RECV_ICMP** → `notify_*` socket callbacks deliver
  ICMP errors per §4.1.3.3.

> "An application-layer program MUST be able to set the
>  TTL and TOS values as well as IP options for sending a
>  UDP datagram, and these values must be passed
>  transparently to the IP layer."

**Adherence:** met for TTL + TOS; not implemented for IP
options.

- **TTL** → `setsockopt(IPPROTO_IP, IP_TTL, value)` /
  `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, value)`
  wired at `packages/pytcp/pytcp/runtime/socket/__init__.py` (IP_TTL in
  `_ipproto_ip_setsockopt:856`; IPV6_UNICAST_HOPS in
  `_ipproto_ipv6_setsockopt:1156`). The TX
  path threads the per-socket override down to
  `_phtx_ip4(ip4__ttl=...)` / `_phtx_ip6(ip6__hop=...)`
  (`packet_handler__udp__tx.py:119-138`).
- **TOS** → `setsockopt(IPPROTO_IP, IP_TOS, value)` /
  `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, value)` wired
  alongside TTL; the TX path passes `ip__ecn` through
  (the DSCP bits live with TOS — full DSCP plumbing is
  half-shipped, tracked in the
  [RFC 2474 audit](../../ip4/rfc2474__dscp/adherence.md)).
- **IP options** → `setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)`
  sets the per-socket IPv4 options block; the TX path
  threads it through `_phtx_udp` to `_phtx_ip4` (see
  §4.1.3.2).

> "UDP MAY pass the received TOS up to the application
>  layer."

**Adherence:** met. PyTCP surfaces the received TOS
byte (computed as `(dscp << 2) | ecn` from the parsed
IPv4 header) through `recvmsg` as an `IP_TOS` cmsg
when `IP_RECVTOS` is set on the socket. The cmsg shape
mirrors Linux's `ip(7)`: a single byte. The parallel
IPv6 surface adds `IPV6_RECVTCLASS` /
`IPV6_TCLASS` cmsg per RFC 3542 §6.5 — Traffic Class
delivered as a 4-byte big-endian integer matching
Linux's `ipv6(7)` wire shape.

- TOS byte plumbing:
  `packages/pytcp/pytcp/runtime/socket/udp__metadata.py::UdpMetadata.ip__tos`,
  populated in the UDP RX handler from
  `packet_rx.ip.dscp` and `packet_rx.ip.ecn`.
- Socket flags: `_ip_recvtos` (IPv4),
  `_ipv6_recvtclass` (IPv6) on
  `packages/pytcp/pytcp/runtime/socket/__init__.py::socket`.
- Cmsg emission: `packages/pytcp/pytcp/runtime/socket/udp__socket.py::UdpSocket.recvmsg`
  alongside the existing IP_OPTIONS branch.

Linux socket-option numeric values are mirrored:
`IP_RECVTOS = 13`, `IPV6_RECVTCLASS = 66`.

---

## Test coverage audit

### §4.1.3.1 ICMP Port Unreachable on no matching socket

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py`
  — exercises the no-socket-match path and asserts
  outbound ICMP Port Unreachable on both IPv4 and IPv6,
  including the rate-limiter suppression counters.

**Status:** locked in.

### §4.1.3.3 ICMP error pass-up

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py`
  — pins the `notify_unreachable` / `notify_time_exceeded`
  / `notify_parameter_problem` / `notify_pmtu` callback
  surfaces; eight tests pin `IP_RECVERR` /
  `IPV6_RECVERR` setsockopt round-trip, error-queue
  population, `EMSGSIZE` + `ee_info` packing on PMTU
  errors, `recvmsg(MSG_ERRQUEUE)` 4-tuple shape, empty-
  queue raises, and the 32-entry FIFO bound.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiIpRecverr`
  — drives end-to-end ICMPv4 Port Unreachable through
  the RX demux → error queue → `recvmsg(MSG_ERRQUEUE)`
  returns embedded datagram + Linux-shape cmsg
  (ee_errno=ECONNREFUSED, ee_origin=ICMP, ee_type=3,
  ee_code=3) + offender address. Companion test pins
  that `IP_RECVERR=0` leaves the queue empty (legacy
  `ConnectionRefusedError` path still wired separately).

**Status:** locked in.

### §4.1.3.4 Checksum generate + validate + silent drop

- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py`
  (compute) + `test__udp__parser__integrity_checks.py`
  (verify, silent-drop, cksum=0 RX bypass).

**Status:** locked in.

### §4.1.3.4 Computed-zero → all-ones substitution

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py::TestUdpAssemblerMisc`
  — four tests across both serialization paths
  (`assemble()` multi-buffer and `__buffer__` single-
  buffer) × both branches (zero compute → 0xFFFF on
  wire, non-zero compute → pass-through). Each patches
  `inet_cksum` to drive the predicate deterministically.

**Status:** locked in.

### §4.1.3.5 Multihoming — specific-destination + getsockname

- **Unit:** `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py`
  — pins `bind()` with wildcard + `getsockname()` return
  of the picked local address.

**Status:** locked in.

### §4.1.3.6 Invalid source address dropping

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py::TestPacketHandlerUdpRxInvalidSourceAddress`
  — parametric class with three cases (IPv4 limited
  broadcast, IPv4 multicast, IPv6 multicast) asserting
  the UDP parser never runs and the IP-layer
  failed-parse counter bumps once.
- **Integration:** the existing IPv4 `src=0.0.0.0`
  parametric case exercises the UDP-layer
  `udp__ip_source_unspecified` drop.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__martian_source.py::TestIp4MartianSourceDirectedBroadcast`
  — three tests pin (a) directed broadcast of a locally
  configured subnet is dropped and bumps
  `ip4__src_directed_broadcast__drop`, (b) directed
  broadcast of a remote (non-configured) subnet is
  accepted as a unicast source, (c) a regular unicast
  source is unaffected.

**Status:** locked in for limited-broadcast, multicast
(both IP versions), unspecified, and directed-broadcast.

### §4.1.4 TTL + TOS per-socket override

- **Unit:** `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py`
  (or the base socket tests) pin `setsockopt(IP_TTL)` /
  `setsockopt(IPV6_UNICAST_HOPS)` plumbing.
- **Integration:** `test__packet_handler__udp__tx.py`
  pins the per-socket TTL value appearing on the
  outbound wire.

**Status:** locked in.

### §3.4 GET_MAXSIZES via IP_MTU / IPV6_MTU getsockopt

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketSolSocketOptions`
  — six tests pin `getsockopt(IP_MTU)` cache hit,
  `interface_mtu` fallback, `ENOTCONN` on unconnected
  socket, setsockopt rejection with `ENOPROTOOPT`, and
  the IPv6 mirror cases.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiIpMtuGetsockopt`
  — two tests drive end-to-end: bind+connect → empty cache
  returns `interface_mtu`; bind+connect + outbound UDP +
  inbound ICMPv4 Frag-Needed → cache populated →
  `getsockopt(IP_MTU)` returns the advertised next-hop
  MTU.

**Status:** locked in.

### §4.1.4 received TOS pass-through (IP_RECVTOS / IPV6_RECVTCLASS)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketSolSocketOptions`
  — two tests pin `IP_RECVTOS` and `IPV6_RECVTCLASS`
  round-trip via setsockopt / getsockopt.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketReceive`
  — six tests pin recvmsg IP_TOS cmsg emission gated by
  `IP_RECVTOS` (one-byte value, both non-zero and zero
  TOS), IPV6_TCLASS cmsg emission gated by
  `IPV6_RECVTCLASS` (4-byte big-endian int), and the
  `ancbufsize=0` suppression invariant.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__ip_options.py::TestUdpIpRecvTos`
  — two tests drive end-to-end IPv4 RX with DSCP=48 /
  ECN=2: cmsg returned when `IP_RECVTOS=1`, suppressed
  when `IP_RECVTOS=0`.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__ip_options.py::TestUdpIpV6RecvTClass`
  — two tests drive end-to-end IPv6 RX with the parallel
  IPV6_TCLASS cmsg shape.

**Status:** locked in.

### §4.1.3.2 IP options pass-through (RX + TX)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketSolSocketOptions`
  — six tests pin
  `setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)` round-trip
  (empty + Router Alert), EINVAL on unaligned / oversize /
  malformed blocks, and `IP_RECVOPTS` round-trip.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketReceive`
  — ten tests pin `recvmsg()` 4-tuple shape, AF_INET
  2-tuple address, AF_INET6 4-tuple address, ancdata
  emission gated by `IP_RECVOPTS`, `ancbufsize=0`
  suppresses cmsg, and the data is returned as bytes.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__ip_options.py::TestUdpIpOptionsRecvmsgPassThrough`
  — three tests drive end-to-end RX with Router Alert IPv4
  options: cmsg returned when `IP_RECVOPTS=1`, suppressed
  when `IP_RECVOPTS=0`, empty when the datagram has no
  options.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__ip_options.py::TestUdpIpOptionsSendto`
  — two tests pin end-to-end TX: outbound wire frame
  carries the per-socket IP_OPTIONS block with the
  correct `hlen` bump; absence of `setsockopt(IP_OPTIONS)`
  keeps the default 20-byte header.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| ICMP Port Unreachable on no socket                  | locked in |
| Silent discard on bad checksum                      | locked in |
| Checksum cksum=0 RX bypass                          | locked in |
| Computed-zero TX → all-ones (MUST)                  | locked in |
| `notify_*` ICMP error pass-up                       | locked in |
| `IP_RECVERR` / `MSG_ERRQUEUE` API parity            | locked in |
| `getsockname()` reveals picked source               | locked in |
| `is_unspecified` source RX drop                     | locked in |
| Broadcast / multicast / directed-broadcast source RX drop | locked in |
| TTL + TOS per-socket override                       | locked in |
| IP options pass-through (RX + TX)                   | locked in |
| Received TOS / TClass pass-through (IP_RECVTOS / IPV6_RECVTCLASS) | locked in |
| GET_MAXSIZES via IP_MTU / IPV6_MTU getsockopt        | locked in |

---

## Overall assessment (RFC 1122 §4.1.5 Requirements Summary)

Mapping the RFC's own row-by-row Requirements Summary
table to PyTCP status. "x" in the original table marks
the column the RFC assigns; PyTCP status follows.

| Feature                                                | §       | RFC level | PyTCP status |
|--------------------------------------------------------|---------|-----------|--------------|
| UDP send Port Unreachable                              | 4.1.3.1 | SHOULD    | met (rate-limited) |
| Pass rcv'd IP options to applic layer                  | 4.1.3.2 | MUST      | met (recvmsg cmsg gated by IP_RECVOPTS) |
| Applic layer can specify IP options in Send            | 4.1.3.2 | MUST      | met (setsockopt IP_OPTIONS) |
| UDP passes IP options down to IP layer                 | 4.1.3.2 | MUST      | met (_phtx_udp threads ip4__options to _phtx_ip4) |
| Pass ICMP msgs up to applic layer                      | 4.1.3.3 | MUST      | met (notify_* callbacks; IP_RECVERR API parity deferred) |
| UDP able to generate/check checksum                    | 4.1.3.4 | MUST      | met |
| Silently discard bad checksum                          | 4.1.3.4 | MUST      | met |
| Sender option to not generate checksum                 | 4.1.3.4 | MAY       | not implemented (no consumer) |
| Default is to checksum                                 | 4.1.3.4 | MUST      | met |
| Receiver option to require checksum                    | 4.1.3.4 | MAY       | not implemented (no consumer) |
| Pass spec-dest addr to application                     | 4.1.3.5 | MUST      | met |
| Applic layer can specify Local IP addr                 | 4.1.3.5 | MUST      | met (`bind()`) |
| Applic layer specify wild Local IP addr                | 4.1.3.5 | MUST      | met |
| Applic layer notified of Local IP addr used            | 4.1.3.5 | SHOULD    | met (`getsockname()`) |
| Bad IP src addr silently discarded by UDP/IP           | 4.1.3.6 | MUST      | met (limited-broadcast / multicast / reserved filtered at IP-layer parser; directed-broadcast filtered at IPv4 RX packet handler; unspecified at UDP layer) |
| Only send valid IP source address                      | 4.1.3.6 | MUST      | met |
| Full IP interface of 3.4 for application               | 4.1.4   | MUST      | met (GET_SRCADDR / GET_MAXSIZES / RECV_ICMP); ADVISE_DELIVPROB not implemented |
| Able to spec TTL, TOS, IP opts when send dg            | 4.1.4   | MUST      | met (TTL via IP_TTL; TOS via IP_TOS; IP options via IP_OPTIONS) |
| Pass received TOS up to applic layer                   | 4.1.4   | MAY       | met (recvmsg IP_TOS cmsg gated by IP_RECVTOS; IPv6: IPV6_TCLASS + IPV6_RECVTCLASS per RFC 3542 §6.5) |

**Principal gap:** none. Every "MUST" row in the §4.1.5
requirements-summary table is now met, the
`Pass received TOS up to applic layer` MAY row is also
met, and the previously-partial `GET_MAXSIZES`
(`IP_MTU` / `IPV6_MTU` getsockopt) is now fully met.
The remaining deltas are the cksum-skip MAY items
(`Sender option to not generate checksum`, `Receiver
option to require checksum`) — declined absent a PyTCP
consumer — and the unimplemented `ADVISE_DELIVPROB`
(`§3.4` advisory delivery-probability surface; PyTCP
has no routing-failure-rate feedback mechanism).

Six previously-flagged gaps in this audit are now closed:

- **§4.1.3.2 IP options pass-through (RX + TX)** — three
  MUST rows in the requirements summary; closed by adding
  `IP_OPTIONS` / `IP_RECVOPTS` setsockopt support, the
  `recvmsg` ancillary-data API, `UdpMetadata.ip4__options`,
  and TX plumbing through `_phtx_udp` →
  `_phtx_ip4(ip4__options=...)`.
- **§4.1.3.4 computed-zero → all-ones substitution** —
  both UDP serialization paths apply the substitution
  per RFC 768.
- **§4.1.3.6 broadcast/multicast source filtering** —
  the IPv4/IPv6 parser sanity checks reject
  limited-broadcast, multicast, and reserved sources
  before the UDP layer runs.
- **§4.1.3.6 directed-broadcast source filtering** —
  the IPv4 RX packet handler drops sources matching any
  locally configured subnet's broadcast address
  (`_ip4_broadcast` membership check). Closes the
  Phase-1 follow-up flagged in earlier revisions of
  this audit.
- **§4.1.4 received TOS pass-through (MAY)** — closed by
  adding `IP_RECVTOS` / `IPV6_RECVTCLASS` setsockopt
  support and `IP_TOS` / `IPV6_TCLASS` recvmsg cmsg
  emission. `UdpMetadata.ip__tos` carries the combined
  DSCP+ECN byte populated from the parsed IP header.
- **§3.4 GET_MAXSIZES via socket API** — closed by adding
  `IP_MTU` / `IPV6_MTU` getsockopt: returns the cached
  `stack.pmtu_cache[remote]` when present, falling back
  to `stack.interface_mtu`; raises `OSError(ENOTCONN)`
  on unconnected sockets to match Linux 'ip(7)'.

---

## Cross-references

- Base UDP specification: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md)
- IPv4 host requirements (umbrella for §3.x): [`../../ip4/rfc1122__host_requirements_ip4/adherence.md`](../../ip4/rfc1122__host_requirements_ip4/adherence.md)
- ICMPv4 host requirements (§3.2.2 generation gate): [`../../icmp4/rfc1122__host_requirements_icmp/adherence.md`](../../icmp4/rfc1122__host_requirements_icmp/adherence.md)
- IPv4 datagram framing (RFC 791 + 1122 §3): [`../../ip4/rfc791__ip4/adherence.md`](../../ip4/rfc791__ip4/adherence.md)
- DSCP / TOS plumbing: [`../../ip4/rfc2474__dscp/adherence.md`](../../ip4/rfc2474__dscp/adherence.md)
- Socket-API parity gaps (incl. `IP_RECVERR`, `IP_OPTIONS`, `IP_RECVTOS`): `docs/refactor/socket_linux_parity_audit.md`
