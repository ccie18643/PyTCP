# RFC 6633 — Deprecation of ICMP Source Quench Messages

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 6633                                                   |
| Title       | Deprecation of ICMP Source Quench Messages             |
| Category    | Standards Track (Updates: 792, 1122, 1812)             |
| Date        | May 2012                                               |
| Source text | [`rfc6633.txt`](rfc6633.txt)                           |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 6633 by structural
absence: the codebase does not define ICMPv4 Source Quench
(Type 4) at any layer, so the four MUSTs imposed by §3 / §4
/ §5 / §6 are satisfied without any active gating logic.

- TX: no `Icmp4Type.SOURCE_QUENCH` member, no
  `Icmp4MessageSourceQuench` class, no call site that
  could synthesise a Type 4 frame. Generation is
  structurally impossible.
- RX: `Icmp4Parser._parse()`'s `match Icmp4Type.from_int(...)`
  has no arm for Type 4, so the message is constructed as
  `Icmp4MessageUnknown`, whose `validate_sanity` raises
  `Icmp4SanityError`; `_phrx_icmp4` catches the resulting
  `PacketValidationError` and silently discards (logs +
  bumps `icmp4__failed_parse__drop`).
- Transport-layer reaction (TCP / UDP / etc.) cannot
  occur because the ICMPv4 RX handler never reaches the
  transport demux for unknown-type frames.

This compliance is regression-pinned by the test class
`TestIcmp4Rx__SourceQuench__Rfc6633` in
`packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__rx.py`,
which verifies an inbound Type 4 frame produces no TX,
bumps only the `icmp4__failed_parse__drop` counter, and
never reaches a transport handler.

---

## §3 Updating RFC 1122

> "A host MUST NOT send ICMP Source Quench messages."

**Adherence:** **shipped (structural).** The codebase
defines no Source Quench message class, no enum member,
and no generation path. There is no call site that could
synthesise a Type 4 ICMPv4 frame. A regression that
re-introduced Source Quench would require adding a new
enum value, message class, and TX call site — none of
which exist today.

> "If a Source Quench message is received, the IP layer
> MAY silently discard it."

**Adherence:** **shipped.** The IP layer hands the
message to `Icmp4Parser`, which builds an
`Icmp4MessageUnknown` because Type 4 is absent from the
`Icmp4Type` enum; that message's `validate_sanity` raises
`Icmp4SanityError`, so `_phrx_icmp4` silently discards
(logs + bumps `icmp4__failed_parse__drop`). PyTCP
exercises the MAY clause: it discards rather than passing
to a transport-layer handler.

> "TCP MUST silently discard any received ICMP Source
> Quench messages."

**Adherence:** **shipped.** TCP never sees Source Quench
because the ICMPv4 RX path rejects the frame at parser
sanity and returns before any transport demux. The
behaviour is verified by
`test__icmp4__rx__source_quench__no_tx` (no TX response)
and the absence of any `tcp__icmp4__source_quench`
packet-stats counter.

## §4 Updating RFC 1812

> "A router MUST ignore any ICMP Source Quench messages
> it receives."

**Adherence:** **shipped (Phase 1 host-stack scope).**
PyTCP is currently a host stack and does not forward
packets, so router-side reaction does not arise. The
stack's ICMPv4 RX path silently discards Source Quench
in all cases. When Phase 2 router-grade work lands
(`CLAUDE.md` Project North Star), the same silent-
discard path will continue to satisfy the router MUST.

## §5 Clarification for UDP, SCTP, and DCCP

> "UDP endpoints MUST silently discard received ICMP
> Source Quench messages."

**Adherence:** **shipped.** UDP never sees Source Quench
for the same reason as TCP: unknown-type ICMPv4 frames
are absorbed at the ICMPv4 RX layer before reaching any
transport demux. PyTCP does not implement SCTP or DCCP,
so those clauses are not applicable.

## §6 General Advice to Transport Protocols

> "If a Source Quench message is received by any other
> transport-protocol instance, it MUST be silently
> ignored."

**Adherence:** **shipped (vacuous).** PyTCP implements
TCP and UDP at the transport layer; the §3 / §5 paths
already cover both. Any future transport added to PyTCP
inherits the unknown-type silent-discard behaviour for
free as long as the ICMPv4 parser does not gain a Type 4
arm.

## §7 Recommendation Regarding RFC 1016

> "the approach described in [RFC1016] MUST NOT be
> implemented."

**Adherence:** **shipped (vacuous).** RFC 1016's
experimental Quench-Pacing scheme requires Source Quench
processing as a precondition; since PyTCP discards
Source Quench at the IP layer, the RFC 1016 algorithm
has no input and cannot be invoked.

## §8 Security Considerations

> "Hosts, security gateways, and firewalls MUST silently
> discard received ICMP Source Quench packets and SHOULD
> log such drops as a security fault with at least
> minimal details (IP Source Address, IP Destination
> Address, ICMP message type, and date/time the packet
> was seen)."

**Adherence:** **shipped (MUST), partial (SHOULD).** The
silent-discard MUST is met. The SHOULD-log clause is met
in coarse form: when parser sanity rejects the frame,
`_phrx_icmp4` emits a debug log carrying the packet
tracker and the sanity-error text via the standard
`__debug__` channel, plus increments the
`icmp4__failed_parse__drop` counter. The log does not
include the source / destination IP addresses, and PyTCP
does not currently emit a structured "security fault" log
channel; the existing debug log is informational rather
than security-tagged. Promoting the unknown-type log to a
security-tier channel is a Phase-2 polish item rather
than a Phase-1 gap.

---

## Test coverage audit

| Aspect                                                       | Coverage |
|--------------------------------------------------------------|----------|
| §3 Type 4 RX silently discarded — no TX response             | shipped — `test__icmp4__rx__source_quench__no_tx` |
| §3 Type 4 RX increments `icmp4__failed_parse__drop` counter  | shipped — `test__icmp4__rx__source_quench__packet_stats_rx` |
| §3 Type 4 RX does not reach transport demux (no TX counters) | shipped — `test__icmp4__rx__source_quench__packet_stats_tx` |
| §3 host MUST NOT send Source Quench (TX-side structural)     | shipped — verified by codebase grep (`grep -r SOURCE_QUENCH packages/net_proto/net_proto/ packages/pytcp/pytcp/` returns no hits) |
| §4 router MUST ignore Source Quench                          | n/a (Phase 1 host-stack scope) |
| §5 UDP MUST silently discard                                 | shipped — covered by RX-side path; UDP demux unreachable |
| §6 other transports MUST silently ignore                     | n/a (no other transports implemented) |
| §7 RFC 1016 algorithm MUST NOT be implemented                | shipped — codebase contains no RFC 1016 references |
| §8 SHOULD log discard as security fault                      | partial — debug log present, not security-tier (Phase-2 polish) |

The regression-pinning tests live at
`packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__rx.py`,
class `TestIcmp4Rx__SourceQuench__Rfc6633`. They exercise
the full ICMPv4 RX path (Ethernet → IPv4 → ICMPv4) so a
future change that re-introduces Source Quench at any
layer is caught by at least one assertion.

---

## Overall assessment

| Aspect                                       | Status              |
|----------------------------------------------|---------------------|
| §3 host MUST NOT send Source Quench          | **shipped (structural)** |
| §3 host MAY silently discard at IP layer     | **shipped**         |
| §3 TCP MUST silently discard                 | **shipped**         |
| §4 router MUST ignore                        | n/a (Phase 1 scope) |
| §5 UDP MUST silently discard                 | **shipped**         |
| §6 other transports MUST silently ignore     | **shipped (vacuous)** |
| §7 RFC 1016 MUST NOT be implemented          | **shipped (vacuous)** |
| §8 MUST silently discard                     | **shipped**         |
| §8 SHOULD log as security fault              | partial (Phase-2)   |

PyTCP's compliance with RFC 6633 is structural rather than
gated: the codebase pre-dates the deprecation but never
implemented Source Quench in the first place, so no
active deprecation logic is required. The single Phase-2
follow-up is promoting the unknown-type log channel to a
security-tagged tier so §8's SHOULD-log clause is met
fully rather than partially.
