# RFC 2474 — Definition of the Differentiated Services Field (DS Field)

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 2474                                                 |
| Title       | Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers |
| Category    | Standards Track                                      |
| Date        | December 1998                                        |
| Updated by  | RFC 3168, RFC 3260, RFC 8436                         |
| Source text | [`rfc2474.txt`](rfc2474.txt)                         |

This document records the PyTCP codebase's adherence to RFC 2474
clause by clause. The audit was performed by reading the RFC
text fresh and inspecting `packages/net_proto/net_proto/protocols/ip4/ip4__header.py`
and the IPv4 RX/TX handlers directly; no prior memory or
rule-file content was reused. Non-normative content
(§1 Introduction, §2 Terminology, §6 IANA, §7 Security, §8/§9)
is omitted.

RFC 2474 redefines the TOS octet (RFC 791 §3.1) as the
DS field: 6 bits of **DSCP** (codepoint) + 2 bits **CU**
(currently unused; subsequently redefined as ECN by RFC 3168
— audited separately).

---

## Top-line adherence

PyTCP **meets** the wire-format and host-side posture: the
DSCP field is a typed 6-bit slot on the IPv4 header, defaults
to 0 (Default PHB), is preserved across parse / assemble, and
the CU bits (now ECN) are managed independently. PyTCP has no
PHB-mapping queueing layer; as a Phase-1 host stack it
delivers every received frame normally regardless of DSCP.
RFC 2474's PHB / re-marking / boundary-node requirements
target routers and DS-domain boundaries — n/a for host scope.

| Section | Topic                                                  | Status |
|---------|--------------------------------------------------------|--------|
| §3      | DS field structure (6-bit DSCP + 2-bit CU)             | met (wire codec) |
| §3      | Application DSCP marking (socket IP_TOS / IPV6_TCLASS → wire, preserved across fragmentation) | met (2026-05-29) |
| §3      | Match PHB on entire 6-bit DSCP                         | n/a (no PHB tier) |
| §3      | CU bits MUST be ignored by PHB selection               | n/a (no PHB tier; CU bits are ECN per RFC 3168) |
| §3      | Configurable codepoint-to-PHB mapping                  | n/a (no PHB tier) |
| §3      | Unrecognised codepoint → treat as Default; MUST NOT malfunction | met (delivered normally) |
| §4.1    | Default PHB MUST be available                          | met trivially (single FIFO) |
| §4.2.2  | Class Selector codepoints (legacy precedence mapping)  | n/a (no PHB tier) |
| §5      | PHB standardization guidelines                         | n/a (router) |

---

## §3 DS Field Structure

> "Six bits of the DS field are used as a codepoint (DSCP) ...
> A two-bit currently unused (CU) field is reserved."

**Adherence:** met (with CU bits redefined). `Ip4Header.dscp:
int` is a 6-bit field
(`packages/net_proto/net_proto/protocols/ip4/ip4__header.py:98,127`) and
`Ip4Header.ecn: int` is the 2-bit field that occupies the
former CU slot
(`ip4__header.py:99,129`). The TOS-byte pack at
`ip4__header.py:182` combines them as
`self.dscp << 2 | self.ecn`; unpack at `ip4__header.py:217-218`
splits them via `dscp__ecn >> 2` and `dscp__ecn & 0b11`.

The original RFC 2474 said the CU bits are "currently unused";
RFC 3168 subsequently allocated them as the ECN field
(audited separately under
`docs/rfc/ip4/rfc3168__ecn/adherence.md`). PyTCP follows the
post-3168 split.

**Application marking (socket → wire), shipped 2026-05-29.**
The DSCP is now settable per-socket and marked on every
outbound packet, not just stored in the header struct. A
`setsockopt(IPPROTO_IP, IP_TOS, dscp<<2 | ecn)` /
`setsockopt(IPPROTO_IPV6, IPV6_TCLASS, …)` threads the high
6 bits through `socket._effective_ip_dscp()` →
`ip__dscp` / `ip4__dscp` / `ip6__dscp` → the IPv4 / IPv6
assembler's `dscp` field, across UDP, TCP, and raw sockets
(M4 of `docs/refactor/socket_linux_parity_audit.md`). Linux
parity: the socket DSCP marks all of that socket's traffic;
ECN on TCP stays RFC-3168 stack-driven while DSCP is
orthogonal. Each IP fragment inherits the original
datagram's DSCP + ECN (RFC 791 §2.3 / RFC 8200 §4.5) — the
fragmenter copies the source packet's DS field onto every
fragment rather than zeroing it.

> "DS-compliant nodes MUST select PHBs by matching against the
> entire 6-bit DSCP field."

**Adherence:** n/a. PyTCP has no PHB-mapping layer — there is
a single FIFO output (`packages/pytcp/pytcp/lib/tx_ring.py`) and no
priority queueing. DSCP is preserved across the stack but does
not drive any local forwarding-class decision because there is
no forwarding plane. Phase 2 forwarding may grow PHB-aware
queueing; until then the requirement is vacuously satisfied.

> "The value of the CU field MUST be ignored by PHB selection."

**Adherence:** n/a (no PHB selection). The fact that PyTCP
separates DSCP and ECN at the type-system level (two distinct
6-bit + 2-bit fields, not a single 8-bit TOS byte) means a
hypothetical future PHB layer cannot accidentally fold ECN
into PHB matching — the structural separation prevents the
mistake.

> "Packets received with an unrecognized codepoint SHOULD be
> forwarded as if they were marked for the Default behavior."
> "Such packets MUST NOT cause the network node to
> malfunction."

**Adherence:** met. `Ip4Header.dscp` accepts any 6-bit value
(`is_uint6` check at `ip4__header.py:127`). No code path in
PyTCP dispatches on DSCP, so unrecognised codepoints behave
identically to recognised ones: delivered to the upper layer.
The "MUST NOT malfunction" hardening is trivially met because
the field is just a stored integer.

## §4.1 A Default PHB

> "A 'default' PHB MUST be available in a DS-compliant node."

**Adherence:** met (trivially). PyTCP has a single TX FIFO
(`TxRing`) — every datagram is forwarded with best-effort
treatment. The default PHB ("FIFO, no special handling") is
not just available, it is the only PHB.

## §4.2.2 Class Selector codepoints

> "Codepoints of the form 'xxx000' (where x = 0 or 1) are
> reserved as a set of Class Selector codepoints. PHBs which
> are mapped to from these codepoints MUST satisfy the Class
> Selector PHB Requirements ..."

**Adherence:** n/a (no PHB tier). DSCP values 0, 8, 16, 24,
32, 40, 48, 56 (the Class Selector subset) are stored on the
header like any other value; no per-codepoint queueing
behaviour is implemented.

## §5 PHB Standardization Guidelines

**Adherence:** n/a. Router-side guidance; no PyTCP consumer.

---

## Test coverage audit

### §3 Wire codec — DSCP/ECN split, 6+2 bit width

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  Boundary asserts: `dscp` must be uint6 (under_min, over_max),
  `ecn` must be uint2.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__operation.py`
  Round-trip matrix includes non-zero DSCP and ECN values
  across the full 6+2 bit range.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__assembler__operation.py`
  Assembler round-trip parametric over DSCP / ECN settings.

**Status:** locked in.

### §3 Default DSCP=0 on TX absent caller override

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Default TX cases ship with `dscp=0`. A dedicated case
  pinning "no caller override → dscp == 0" is trivial.

**Status:** locked in indirectly.

### §3 Application DSCP marking (socket → wire)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiIpDscpOnWire`
  (UDP v4 + v6) and
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_dscp.py`
  (TCP SYN + data, v4 + v6) — `setsockopt(IP_TOS /
  IPV6_TCLASS)` marks the outbound `dscp` field while the
  ECN bits behave per family.
- **Integration (fragmentation):**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__fragmentation.py::TestUdpFragmentationDscp`
  — every IPv4 / IPv6 fragment of an over-MTU datagram
  carries the DSCP + ECN, not just the first.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__raw__socket.py::TestRawSocketDscp`
  — `_effective_ip_dscp()` high-6-bit extraction (v4 + v6)
  and the raw-send `ip4__dscp` threading.

**Status:** locked in.

### §3 Unrecognised codepoint accepted without malfunction

- **Unit:** the parser round-trip matrix exercises DSCP values
  across the entire 0-63 range; none cause `Ip4SanityError` or
  any other rejection. Combined with the absence of any DSCP-
  dispatch site in the RX path, the "MUST NOT malfunction"
  property is satisfied by construction.

**Status:** locked in.

### §3 / §4.2.2 PHB mapping (n/a)

**No test surface — n/a (no PHB tier).** PyTCP has no PHB-mapping
layer; the audit explicitly classifies this as n/a.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| §3 DSCP wire codec (6-bit field, packed in TOS byte)  | locked in |
| §3 CU bits split (now ECN per RFC 3168)               | locked in (cross-ref RFC 3168 audit) |
| §3 Default DSCP=0 on send                             | locked in indirectly |
| §3 Application DSCP marking (socket IP_TOS / IPV6_TCLASS → wire) | locked in (UDP/TCP v4+v6 + fragmentation) |
| §3 Unrecognised codepoint accepted                    | locked in by construction |
| §4.1 Default PHB available                            | met trivially (single FIFO) |
| §4.2.2 Class Selector PHB compliance                  | n/a (no PHB tier) |
| Configurable codepoint-to-PHB mapping                 | n/a (no PHB tier) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3 DS field wire format (DSCP+CU)                   | met    |
| §3 Match PHB on full 6-bit DSCP                     | n/a (no PHB tier) |
| §3 Default PHB for unrecognised codepoints          | met    |
| §3 MUST NOT malfunction on unrecognised codepoint   | met    |
| §4.1 Default PHB available                          | met (trivially) |
| §4.2.2 Class Selector PHB requirements              | n/a    |
| §5 PHB standardization (router-side)                | n/a    |

RFC 2474's wire-format and "do no harm" requirements are met.
The PHB / queueing / re-marking requirements all target the
forwarding plane that PyTCP doesn't yet have. **`# Phase 2:`**
when PyTCP grows multi-queue output (e.g. for router-grade
QoS), the audit's "no PHB tier" entries flip to "implemented"
with the natural fix being a `ip4.dscp_phb_map` sysctl or
per-interface configuration.
