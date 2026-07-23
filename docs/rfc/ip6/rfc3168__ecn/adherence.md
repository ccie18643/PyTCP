# RFC 3168 — Explicit Congestion Notification (IPv6) — adherence

RFC 3168 defines the ECN field (the low 2 bits of the IPv4 TOS
octet / the IPv6 Traffic Class octet) and the rules for marking,
echoing, and reacting to congestion. This record audits the **IPv6**
half of PyTCP's ECN support — the IPv4 half is audited separately at
`docs/rfc/ip4/rfc3168__ecn/adherence.md`, and the RFC text lives
alongside that IPv4 record (RFC 3168 is one document covering both IP
versions). Most of the ECN machinery is **shared** between the
families; this record pins the IPv6-specific wire path and the
IPv6 reassembly aggregation.

The TCP-side ECN negotiation / CWR / ECE state machine is audited
under `docs/rfc/tcp/` (RFC 3168 §6, RFC 8311, RFC 9768 AccECN); this
record covers only the IPv6 **network-layer** ECN field handling.

## Top-line adherence

PyTCP **meets** the IPv6 network-layer ECN requirements: the 2-bit
ECN field is a typed slot on the IPv6 header, defaults to Not-ECT on
send, is settable per-socket (ECT marking) via `IPV6_TCLASS`, is
preserved across parse / assemble, and is aggregated per RFC 3168
§5.3 on fragment reassembly (including the Not-ECT-mixed drop). PyTCP
is a host, not a router, so the router-side §5 marking ("set CE when
the queue is congested") is n/a — there is a single best-effort TX
FIFO and no AQM.

| Section | Topic | Status |
|---------|-------|--------|
| §5      | ECN field in IP header (2 bits) | met (IPv6 Traffic Class low 2 bits) |
| §5      | Codepoints Not-ECT(00) / ECT(1)(01) / ECT(0)(10) / CE(11) | met (wire codec) |
| §5      | Default Not-ECT on transmit | met |
| §5      | Router sets CE on congestion (AQM) | n/a (host, single FIFO, no AQM) |
| §5.3    | ECN aggregation on fragment reassembly | met (shared aggregator; IPv6 wired) |
| §5.3    | Not-ECT mixed with ECT → drop | met (`ip6_frag__ecn_mixed__drop`) |
| §7 / app | Application ECT marking via socket | met (`IPV6_TCLASS` → `_effective_ip_ecn`) |
| §6      | TCP ECN negotiation / CE echo | audited under `docs/rfc/tcp/` (not here) |

---

## §5 ECN field structure and codepoints

> "This document specifies that the Internet provide a congestion
> indication for incipient congestion ... where the notification can
> sometimes be through marking packets rather than dropping them. ...
> bits 6 and 7 of the [...] IPv6 Traffic Class octet are designated
> as the ECN field."

**Adherence:** met. `Ip6Header.ecn: int` is the 2-bit field occupying
the low 2 bits of the Traffic Class octet
(`packages/net_proto/net_proto/protocols/ip6/ip6__header.py:100`,
asserted `is_uint2` at `:116`). The Traffic Class is packed as
`ver << 28 | dscp << 22 | ecn << 20 | flow` at `:149` and unpacked at
`:169-170` (`dscp = (tc >> 22) & 0x3f`, `ecn = (tc >> 20) & 0x03`).
The four codepoints (Not-ECT 00, ECT(1) 01, ECT(0) 10, CE 11) are
carried verbatim — PyTCP does not dispatch on the ECN value at the
IPv6 layer (no AQM), so any of the four is parsed and delivered
unchanged.

> "Senders are free to use either ECT(0) or ECT(1) ... Routers treat
> the ECT(0) and ECT(1) codepoints as equivalent."

**Adherence:** met (host scope). PyTCP-originated IPv6 packets default
to Not-ECT (`ip6__ecn` defaults to 0 through the assembler and TX
chain); a TCP connection that has negotiated ECN sets ECT(0) on data
segments (`session/tcp__session__tx.py`), and an application may set
any codepoint via `IPV6_TCLASS` (below). PyTCP is not a router, so the
ECT(0)/ECT(1) equivalence in forwarding is n/a.

## §5 default Not-ECT on transmit

**Adherence:** met. `Ip6Assembler` accepts `ip6__ecn` with a `0`
default (`ip6__assembler.py:64,78`); the IPv6 TX handler defaults the
kwarg to 0 (`packet_handler__ip6__tx.py:82`). Stack-generated traffic
(ND, MLD, ICMPv6) leaves the default in place → Not-ECT.

## §5 router CE marking (AQM)

**Adherence:** n/a (host). RFC 3168 §5's "an ECN-capable router MAY
set the CE codepoint" targets routers running active queue management.
PyTCP has a single best-effort TX FIFO (`runtime/tx_ring.py`) and no
AQM, so it never sets CE on transit. Phase-2 forwarding may grow this;
until then the requirement is vacuously satisfied (no forwarding
plane).

## §5.3 ECN and fragmentation / reassembly

> "If the ECN field of the fragments differ, the reassembled packet's
> ECN field is set per the table: ... if any fragment is CE the
> result is CE; Not-ECT combined with ECT is an error."

**Adherence:** met. IPv6 reassembly uses the **shared** IPv4/IPv6
aggregator `aggregate_ecn`
(`packages/pytcp/pytcp/protocols/ip/ip_frag.py:113-148`), which
implements the Linux `ip_frag_ecn_table` semantics: all-same
preserved; CE + any ECT → CE; ECT(0) + ECT(1) → ECT(0); Not-ECT mixed
with any ECT → error/drop. The IPv6 RX reassembly handler wires it at
`packet_handler__ip6_frag__rx.py`:

- per-fragment ECN fed into the fragment store: `ecn=packet_rx.ip6.ecn`
  at `:110`,
- Not-ECT-mixed drop: bumps `ip6_frag__ecn_mixed__drop` and discards
  at `:115-122`,
- the aggregated ECN is patched back into the reassembled IPv6
  Traffic Class (byte 1, bits 5-4) at `:135`:
  `header[1] = (header[1] & 0xCF) | ((result.ecn & 0x03) << 4)`.

This is the IPv6 analogue of the IPv4 patch
(`packet_handler__ip4__rx.py`, byte-1 low 2 bits).

## §7 / application ECT marking via the socket

**Adherence:** met. An application sets the IPv6 Traffic Class —
including the ECN bits — via `setsockopt(IPPROTO_IPV6, IPV6_TCLASS,
…)`. `_effective_ip_ecn()` returns the low 2 bits for an IPv6 socket
(`runtime/socket/__init__.py:1564-1572`, `self._ipv6_tclass & 0x03`), threaded
through `ip__ecn` → `ip6__ecn` into the outbound IPv6 header for UDP,
TCP, and raw sockets. (DSCP — the high 6 bits — is marked in parallel;
see `docs/rfc/ip6/rfc2474__dscp/adherence.md`.) This supersedes the
former "IP-layer ECN mark setting not yet exposed via the socket API"
note in `rfc8504__ipv6_node_reqs` §5.12, which has been corrected to
met.

---

## Test coverage audit

### §5 ECN wire codec (2-bit field in Traffic Class)
- **Unit:** the `Ip6Header` / `Ip6Assembler` parse/assemble round-trip
  matrices exercise the `ecn` field across its 0-3 range alongside
  `dscp` (`packages/net_proto/net_proto/tests/unit/protocols/ip6/`).

**Status:** locked in.

### §5.3 reassembly ECN aggregation
- **Unit:** `packages/pytcp/pytcp/tests/unit/...test__ip__ip_frag.py`
  `TestAggregateEcn` — family-agnostic, exercises the full
  `ip_frag_ecn_table` matrix including the Not-ECT-mixed error.
- **Integration:** the IPv6 reassembly suite
  (`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__reassembly.py`)
  drives fragmented IPv6 datagrams; the aggregated Traffic Class lands
  on the reassembled packet.

**Status:** locked in.

### §7 application ECT marking (socket → wire)
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiIpDscpOnWire`
  (the IPv6 case asserts both the DSCP and the ECN bits land on the
  outbound Traffic Class) and
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__fragmentation.py::TestUdpFragmentationDscp`
  (ECN preserved on every IPv6 fragment).

**Status:** locked in.

### Test coverage summary

| Aspect | Coverage |
|--------|----------|
| §5 ECN 2-bit wire codec (IPv6 Traffic Class) | locked in |
| §5 default Not-ECT on send | locked in |
| §5.3 reassembly CE aggregation + Not-ECT-mixed drop | locked in |
| §7 application ECT marking via `IPV6_TCLASS` | locked in |
| §5 router CE marking (AQM) | n/a (host, no AQM) |
| §6 TCP ECN negotiation | audited under `docs/rfc/tcp/` |

---

## Overall assessment

IPv6 ECN is at full parity with the audited IPv4 ECN behaviour,
largely via shared code (`aggregate_ecn`, `_effective_ip_ecn`) and the
structurally-parallel `ip6__ecn` field / kwarg / socket path. The only
host-out-of-scope item is router-side CE marking (no AQM, no
forwarding plane). The §6 transport-layer ECN behaviour lives in the
TCP records.
