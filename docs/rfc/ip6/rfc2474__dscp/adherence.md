# RFC 2474 — Differentiated Services (DSCP) (IPv6) — adherence

RFC 2474 defines the Differentiated Services field — the 6-bit DSCP
(plus a 2-bit currently-unused field, since redefined as ECN by
RFC 3168) occupying the IPv4 TOS octet / the IPv6 Traffic Class octet.
This record audits the **IPv6** half of PyTCP's DSCP support; the IPv4
half is audited at `docs/rfc/ip4/rfc2474__dscp/adherence.md`, where
the RFC text also lives (RFC 2474 is one document covering both IP
versions). The DSCP marking path is structurally parallel to IPv4.

## Top-line adherence

PyTCP **meets** the IPv6 wire-format and host-side posture: the DSCP
is a typed 6-bit slot on the IPv6 header (the high 6 bits of the
Traffic Class octet), defaults to 0 (Default PHB / CS0), is preserved
across parse / assemble and across fragmentation, and is settable
per-socket via `IPV6_TCLASS`. PyTCP has no PHB-mapping queueing layer;
as a Phase-1 host stack it delivers every received frame normally
regardless of DSCP. RFC 2474's PHB / re-marking / boundary-node
requirements target routers and DS-domain boundaries — n/a for host
scope.

| Section | Topic | Status |
|---------|-------|--------|
| §3 | DS field structure (6-bit DSCP + 2-bit CU) | met (wire codec) |
| §3 | Application DSCP marking (socket `IPV6_TCLASS` → wire, preserved across fragmentation) | met (2026-05-29) |
| §3 | Match PHB on entire 6-bit DSCP | n/a (no PHB tier) |
| §3 | CU bits MUST be ignored by PHB selection | n/a (no PHB tier; CU bits are ECN per RFC 3168) |
| §3 | Unrecognised codepoint → treat as Default; MUST NOT malfunction | met (delivered normally) |
| §4.1 | Default PHB MUST be available | met trivially (single FIFO) |
| §4.2.2 | Class Selector codepoints | n/a (no PHB tier) |
| §5 | PHB standardization guidelines | n/a (router) |

---

## §3 DS Field Structure

> "Six bits of the DS field are used as a codepoint (DSCP) ... A
> two-bit currently unused (CU) field is reserved."

**Adherence:** met (with CU bits redefined). `Ip6Header.dscp: int` is
a 6-bit field (`packages/net_proto/net_proto/protocols/ip6/ip6__header.py:99`,
asserted `is_uint6` at `:114`), and `Ip6Header.ecn: int` is the 2-bit
field occupying the former CU slot (`:100,116`). They pack into the
Traffic Class octet inside `ver << 28 | dscp << 22 | ecn << 20 | flow`
at `:149` and unpack at `:169-170`
(`dscp = (tc >> 22) & 0x3f`, `ecn = (tc >> 20) & 0x03`). The post-RFC
3168 CU-as-ECN split is audited at
`docs/rfc/ip6/rfc3168__ecn/adherence.md`.

**Application marking (socket → wire), shipped 2026-05-29.** The DSCP
is settable per-socket and marked on every outbound packet, not just
stored in the header struct. `setsockopt(IPPROTO_IPV6, IPV6_TCLASS,
dscp<<2 | ecn)` threads the high 6 bits through
`socket._effective_ip_dscp()` (`runtime/socket/__init__.py:1575-1584`,
`(self._ipv6_tclass >> 2) & 0x3f`) → `ip__dscp` / `ip6__dscp` → the
`Ip6Assembler.dscp` field, across UDP, TCP, and raw sockets. Each IPv6
fragment inherits the original datagram's DSCP + ECN: the IPv6
fragmenter copies the source packet's Traffic Class onto every
fragment's outer header
(`packet_handler__ip6_frag__tx.py`, `ip6__dscp=ip6_packet_tx.dscp,
ip6__ecn=ip6_packet_tx.ecn`) rather than zeroing it.

> "DS-compliant nodes MUST select PHBs by matching against the entire
> 6-bit DSCP field." / "The value of the CU field MUST be ignored by
> PHB selection."

**Adherence:** n/a (no PHB selection). PyTCP has no PHB-mapping layer —
a single FIFO output (`runtime/tx_ring.py`), no priority queueing.
DSCP is preserved across the stack but drives no local
forwarding-class decision because there is no forwarding plane. The
structural separation of DSCP and ECN at the type-system level (two
distinct fields, not a single 8-bit octet) means a hypothetical future
PHB layer cannot accidentally fold ECN into PHB matching.

> "Packets received with an unrecognized codepoint SHOULD be forwarded
> as if they were marked for the Default behavior." / "Such packets
> MUST NOT cause the network node to malfunction."

**Adherence:** met. `Ip6Header.dscp` accepts any 6-bit value
(`is_uint6` check); no code path dispatches on DSCP, so unrecognised
codepoints behave identically to recognised ones — delivered to the
upper layer. The "MUST NOT malfunction" hardening is trivially met:
the field is a stored integer.

## §4.1 Default PHB

**Adherence:** met (trivially). PyTCP has a single TX FIFO; every
datagram is forwarded best-effort. The default PHB is not just
available, it is the only PHB.

## §4.2.2 / §5 Class Selector + PHB standardization

**Adherence:** n/a (no PHB tier; router/DS-domain scope).

---

## Test coverage audit

### §3 DSCP wire codec (6-bit field in Traffic Class)
- **Unit:** the `Ip6Header` / `Ip6Assembler` parse/assemble round-trip
  matrices exercise the `dscp` field
  (`packages/net_proto/net_proto/tests/unit/protocols/ip6/`).

**Status:** locked in.

### §3 application DSCP marking (socket → wire)
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiIpDscpOnWire`
  (IPv6 case) and
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_dscp.py`
  (TCP SYN + data, IPv6 case) — `setsockopt(IPV6_TCLASS)` marks the
  outbound `dscp` field.
- **Integration (fragmentation):**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__fragmentation.py::TestUdpFragmentationDscp`
  (IPv6 case) — every fragment carries the DSCP + ECN.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__raw__socket.py::TestRawSocketDscp`
  — `_effective_ip_dscp()` IPv6 high-6-bit extraction.

**Status:** locked in.

### Test coverage summary

| Aspect | Coverage |
|--------|----------|
| §3 DSCP wire codec (IPv6 Traffic Class) | locked in |
| §3 CU bits split (now ECN per RFC 3168) | locked in (cross-ref RFC 3168 IPv6 audit) |
| §3 application DSCP marking (`IPV6_TCLASS` → wire, frag-preserved) | locked in |
| §3 unrecognised codepoint accepted | locked in by construction |
| §4.1 Default PHB available | met trivially (single FIFO) |
| §4.2.2 / §5 PHB tier | n/a (no PHB tier) |

---

## Overall assessment

IPv6 DSCP is at full parity with the audited IPv4 DSCP behaviour, via
the structurally-parallel `ip6__dscp` field / kwarg / socket path and
the same fragmentation-preservation fix. PHB / re-marking requirements
are router/DS-domain scope — n/a for a Phase-1 host with a single
best-effort FIFO.
