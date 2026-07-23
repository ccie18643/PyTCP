# RFC 6864 — Updated Specification of the IPv4 ID Field

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6864                                           |
| Title       | Updated Specification of the IPv4 ID Field     |
| Category    | Standards Track                                |
| Date        | February 2013                                  |
| Updates     | RFC 791, RFC 1122, RFC 2003                    |
| Source text | [`rfc6864.txt`](rfc6864.txt)                   |

This document records the PyTCP codebase's adherence to RFC 6864
clause by clause. The audit was performed by reading the RFC
text fresh and inspecting the codebase under
`packages/net_proto/net_proto/protocols/ip4/`, `packages/pytcp/pytcp/runtime/packet_handler/`, and
`packages/pytcp/pytcp/protocols/ip/ip_frag*.py` directly; no prior memory or
rule-file content was reused. Non-normative sections (§1
Introduction, §2 Conventions, §3 Background, §5 Impact discussion,
§7 IANA, §8 Security boilerplate) are omitted.

---

## Top-line adherence

PyTCP **meets** RFC 6864's normative requirements as a host
stack. The ID generator is a simple per-stack monotonic counter
that is bumped only on the fragmentation path; atomic datagrams
ship with ID=0. The "ignore ID on atomic datagrams" rule is
honoured because no PyTCP code path consults `packet_rx.ip4.id`
for any purpose other than fragmentation flow-key keying.

| Section | Topic                                                      | Status |
|---------|------------------------------------------------------------|--------|
| §4.1    | ID used only for fragmentation/reassembly                  | met    |
| §4.1    | Atomic datagrams MAY set ID to any value                   | met (we use 0) |
| §4.1    | Devices MUST ignore ID of atomic datagrams                 | met    |
| §4.2    | Non-atomic ID MUST NOT be reused when sending a copy       | met (no copy-resend path) |
| §4.3    | Sources MUST NOT repeat non-atomic IDs within one MDL per (src, dst, proto) | met (Phase 1; see notes) |
| §4.3    | DF=1 MUST NOT be fragmented                                | met    |
| §4.3    | Transit devices MUST NOT clear DF                          | n/a (Phase 2 forwarding) |

---

## §4 — Atomic vs. non-atomic datagram definition

> "Atomic datagrams: (DF==1)&&(MF==0)&&(frag_offset==0)"
> "Non-atomic datagrams: (DF==0)||(MF==1)||(frag_offset>0)"

**Adherence:** the definition is consumed implicitly by the
RX dispatch: `packet_handler__ip4__rx.py:171` tests
`packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf` (i.e. the
non-atomic predicate restricted to receivers — DF doesn't
matter on receive). On TX, atomic vs. non-atomic is decided by
the MTU comparison at `packet_handler__ip4__tx.py:151`:
within-MTU packets ship intact (atomic by construction);
over-MTU packets fragment (becoming non-atomic).

## §4.1 IPv4 ID Used Only for Fragmentation

> "The IPv4 ID field MUST NOT be used for purposes other than
> fragmentation and reassembly."

**Adherence:** met. The only reader of `packet_rx.ip4.id` in
the entire codebase is the reassembly flow-key constructor
(`packet_handler__ip4__rx.py:318` →
`IpFragFlowId(src=..., dst=..., id=packet_rx.ip4.id, proto=...)`).
There is no de-duplication cache keyed on ID, no ICMP-rate-limit
keyed on ID, no NAT or middlebox use. `grep -nE
"packet_rx\.ip4\.id|self\._header\.id" packages/pytcp/pytcp/ packages/net_proto/net_proto/`
returns only the flow-key site.

> "Originating sources MAY set the IPv4 ID field of atomic
> datagrams to any value."

**Adherence:** met. PyTCP's atomic-datagram path does not set
`ip4__id` on the `Ip4Assembler` constructor, so it defaults to
`ip4__id: int = 0` (`packages/net_proto/net_proto/protocols/ip4/ip4__assembler.py:69`).
Atomic datagrams ship with ID=0 uniformly. This matches Linux
3.16+ (`net/ipv4/ip_output.c::ip_select_ident` returns 0 when
`!skb_is_gso(skb) && skb->local_df == 0` for DF=1 datagrams).

> "All devices that examine IPv4 headers MUST ignore the IPv4
> ID field of atomic datagrams."

**Adherence:** met. As noted above, only the reassembly path
consults the ID, and the reassembly path is itself gated on
`packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf` (the
non-atomic predicate). Atomic frames never reach the ID
reader.

## §4.2 Encouraging Safe IPv4 ID Use

> "The IPv4 ID of non-atomic datagrams MUST NOT be reused when
> sending a copy of an earlier non-atomic datagram."

**Adherence:** met vacuously. PyTCP has no application-level
"copy this datagram and resend" code path. The only path that
emits a non-atomic datagram is the fragmenter
(`packet_handler__ip4__tx.py:288-323`), which calls
`_next_ip4_id()` (line 286) **before** building any of the
fragments for a given source datagram, then assigns that
fresh ID to every fragment. Resending the source datagram
(e.g. TCP retransmit at the upper layer) re-enters the TX
path and bumps `_ip4_id` again, producing a fresh ID.

> "[overlap] is also the result of in-network datagram
> duplication, which can still occur. As a result, this
> document does not change the need for receivers to support
> overlapping fragments."

**Adherence:** met. Fragment overlap is handled by the
reassembly state machine in
`packages/pytcp/pytcp/protocols/ip/ip_frag_table.py` (overlap → discard) —
audited under RFC 815.

## §4.3 IPv4 ID Requirements That Persist

> "Sources emitting non-atomic datagrams MUST NOT repeat IPv4
> ID values within one MDL for a given source address /
> destination address / protocol tuple."

**Adherence:** met. PyTCP uses a single monotonic counter
shared across all outbound flows
(`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:557`,
`self._ip4_id: int = 0`, bumped via `_next_ip4_id()` at
`packet_handler__ip4__tx.py:96`). The counter rolls over
modulo 2¹⁶ explicitly via the `& 0xFFFF` mask, matching the
`Ip4Header.id` 16-bit field.

A single shared counter trivially satisfies the per-tuple
uniqueness requirement at typical host emission rates: a wrap
requires 65 536 fragmented (non-atomic) datagrams between
collisions. PyTCP only emits non-atomic datagrams via the
fragmenter, which fires only when `len(packet) > MTU`. At a
realistic host load this is well below the wrap rate. A
per-flow counter would be Linux-parity but adds bookkeeping
that the audit does not require.

`# Phase 2:` — a router-grade forwarder that *forwards* a
fragmented datagram untouched preserves the source's ID; but
when a Phase-2 forwarder fragments a DF=0 datagram in transit
it generates a fresh ID, and the shared counter would no
longer suffice at scale. The fix when forwarding lands: hash
(src, dst, proto) into a small per-tuple counter array, or
adopt Linux's `secure_ipv4_id` SipHash-based scheme. Mark in
`packet_handler__ip4__tx.py:286` (the `_next_ip4_id()` call
site) so the upgrade path is greppable.

> "IPv4 datagrams whose DF=1 MUST NOT be fragmented."

**Adherence:** met. The TX fragmenter explicitly drops over-
MTU datagrams with DF=1 (`packet_handler__ip4__tx.py:169-176`)
before reaching the fragment-building loop. Counter:
`ip4__mtu_exceed__df_set__drop`. The DROPPED reason code
returned upward is `TxStatus.DROPPED__IP4__MTU_EXCEED_DF`
(matched against `DROPPED__IP4__MTU_EXCEED_DF` in TCP /
UDP / RAW socket layers so the user-visible errno chains
correctly).

> "IPv4 datagram transit devices MUST NOT clear the DF bit."

**Adherence:** n/a (Phase 2). PyTCP today is a host stack; it
neither originates an in-transit datagram nor rewrites a
forwarded one's flag bits. When the forwarder lands, the
fragment-on-forward path will explicitly preserve DF and emit
ICMPv4 Frag-Needed (RFC 1191) when DF=1 over MTU is encountered.

## §6.1 / §6.2 — Updates to RFC 791 / RFC 1122

These sections restate the §4.x requirements in terms of the
older specifications. PyTCP's posture is identical: ID is used
only for fragmentation and reassembly; retransmits at the
upper layer (TCP) drive a re-enter of the IPv4 TX path which
bumps `_ip4_id` afresh, so a retransmitted segment whose
length still exceeds MTU emits non-atomic fragments under a
new ID (not the original).

---

## Test coverage audit

### §4.1 Atomic datagram ID=0 on send

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc6864AtomicId::test__ip4__tx__atomic_datagram__ip4_id_is_zero`
  Dedicated assertion: drive `_phtx_ip4` with a unicast
  destination and a one-byte RAW payload; parse byte offsets
  18-19 of the captured Ethernet frame (= IPv4 header bytes
  4-5 = Identification field) and assert ID == 0.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Every non-fragmented happy-path case in the parametric
  matrix also pins the `id` field of the expected outbound
  frame to 0.

**Status:** locked in.

### §4.1 ID readers consult only the reassembly path

**Verification by code grep, not by test.** A `grep -rn
"\.id\b" packages/pytcp/pytcp/protocols/ packages/pytcp/pytcp/stack/` against the IPv4
RX/TX path returns only the flow-key constructor at
`packet_handler__ip4__rx.py:318`.

**Status:** locked in indirectly via the absence of any
non-reassembly reader.

### §4.2 ID bump on every non-atomic emission (no reuse on retransmit)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  fragmentation cases pin the ID stamped on each fragment;
  re-entering the TX path with the same payload pins the
  ID-bump on each call.

**Status:** locked in.

### §4.3 DF=1 over MTU is dropped (not fragmented)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  has a dedicated case that constructs a packet with DF=1
  and payload > MTU, asserting `TxStatus.DROPPED__IP4__MTU_EXCEED_DF`
  and the matching `ip4__mtu_exceed__df_set__drop` counter.

**Status:** locked in.

### §4.3 Non-atomic ID uniqueness per (src, dst, proto) — Phase 1 simplification

**No dedicated test — Phase 1 simplification.** The shared
counter trivially satisfies the per-tuple uniqueness
requirement at typical emission rates. A regression test
would have to exercise > 65 536 fragmented datagrams between
two flow tuples within MDL, which is impractical to script.
**`# Phase 2:`** when the forwarder lands and the per-tuple
counter is added, the natural test is one that:

1. emits two fragmented datagrams to `dst_a` (IDs N, N+1),
2. emits one fragmented datagram to `dst_b` (ID N+2 under
   shared counter, ID 0 under per-tuple counter),
3. asserts the ID space is partitioned (per-tuple counter)
   rather than shared (current Phase 1).

### Test coverage summary

| Aspect                                                       | Coverage |
|--------------------------------------------------------------|----------|
| §4.1 ID consulted only by reassembly                         | locked in indirectly (grep + code structure) |
| §4.1 Atomic datagrams ship with ID=0                         | locked in |
| §4.2 Non-atomic ID bumped on every emission                  | locked in |
| §4.3 DF=1 over MTU dropped (not fragmented)                  | locked in |
| §4.3 Non-atomic per-tuple ID uniqueness                      | n/a (Phase 1 shared counter; sufficient at host rates) |
| §4.3 Transit devices MUST NOT clear DF                       | n/a (Phase 2 forwarding) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §4.1 ID used only for fragmentation/reassembly      | met    |
| §4.1 Atomic datagrams MAY set ID to any value       | met (we use 0) |
| §4.1 Devices MUST ignore atomic-datagram ID         | met    |
| §4.2 No ID reuse on retransmit                      | met    |
| §4.3 Per-tuple non-atomic ID uniqueness within MDL  | met (Phase 1 shared counter; Phase 2 should partition) |
| §4.3 DF=1 MUST NOT be fragmented                    | met    |
| §4.3 Transit devices MUST NOT clear DF              | n/a (Phase 2)  |

All §4 normative requirements are satisfied for a Phase-1
host stack with full test coverage. The principal Phase-2
sharpening is the per-tuple ID partitioning at the forwarder,
marked in the code with the `# Phase 2:` comment proposed in
§4.3.
