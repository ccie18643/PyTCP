# RFC 6918 — Formally Deprecating Some ICMPv4 Message Types

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 6918                                                   |
| Title       | Formally Deprecating Some ICMPv4 Message Types         |
| Category    | Standards Track (Updates: 792, 950; Obsoletes: 1788)   |
| Date        | April 2013                                             |
| Source text | [`rfc6918.txt`](rfc6918.txt)                           |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 6918 by structural absence:
none of the 15 deprecated ICMPv4 message types is defined at any
layer of the codebase. RFC 6918's normative content is mostly
IANA-registry cleanup with implicit "host SHOULD NOT generate /
SHOULD ignore" semantics — there are no per-type MUSTs comparable
to the Source Quench treatment in RFC 6633.

The deprecated set:

| Type | Name | Originating RFC |
|------|------|-----------------|
| 6 | Alternate Host Address | RFC 792 (no public spec) |
| 15 | Information Request | RFC 792 |
| 16 | Information Reply | RFC 792 |
| 17 | Address Mask Request | RFC 950 |
| 18 | Address Mask Reply | RFC 950 |
| 30 | Traceroute | RFC 1393 (Historic via RFC 6814) |
| 31 | Datagram Conversion Error | RFC 1475 (Historic) |
| 32 | Mobile Host Redirect | CMU-MOBILE (never standardised) |
| 33 | IPv6 Where-Are-You | SIMPSON-DISCOV (Internet Draft) |
| 34 | IPv6 I-Am-Here | SIMPSON-DISCOV |
| 35 | Mobile Registration Request | SIMPSON-MOBILITY |
| 36 | Mobile Registration Reply | SIMPSON-MOBILITY |
| 37 | Domain Name Request | RFC 1788 (Historic via RFC 6918) |
| 38 | Domain Name Reply | RFC 1788 |
| 39 | SKIP | SKIP-ADP (Internet Draft) |

For all 15:

- **TX**: no `Icmp4Type` enum member, no `Icmp4Message<Name>` class,
  no call site that could synthesise such a frame. Generation is
  structurally impossible.
- **RX**: `Icmp4Parser._parse()` has no arm for any of these
  type values, so the message is constructed as
  `Icmp4MessageUnknown`, whose `validate_sanity` raises
  `Icmp4SanityError`; `_phrx_icmp4` catches the resulting
  `PacketValidationError` and silently discards (logs +
  bumps the `icmp4__failed_parse__drop` counter).

The behaviour is regression-pinned by:

- `TestIcmp4Rx__UnknownType` — exercises Type 99 (a non-IANA-
  assigned arbitrary unknown), proving the unknown-type
  silent-discard path itself works.
- `TestIcmp4Rx__DeprecatedTypes__Rfc6918` — exercises Type 17
  (Address Mask Request) as the most well-known deprecated type
  in the set, proving a deprecated-but-once-real type also
  flows through the same path.
- `TestIcmp4Rx__SourceQuench__Rfc6633` — exercises Type 4 for
  the related RFC 6633 deprecation.

Together these three test classes pin the silent-discard
mechanism for every deprecated type without bloating the test
file with 15 near-identical methods.

---

## §2 Discussion of Deprecated ICMPv4 Message Types

§2 is informational — it documents the rationale for each type's
deprecation but does not impose normative wire-protocol
behaviour. Selected highlights relevant to PyTCP's compliance
posture:

- **§2.2/§2.3 Information Req/Reply (Types 15/16)**: superseded
  by DHCP (RFC 2131). PyTCP uses DHCP for host configuration;
  Information Request never arose as a need.
- **§2.4/§2.5 Address Mask Req/Reply (Types 17/18)**: superseded
  by DHCP. PyTCP receives subnet masks via the `Ip4IfAddr`
  configuration mechanism and DHCP option 1, never via ICMPv4.
- **§2.6 Traceroute (Type 30)**: relies on the Traceroute IPv4
  option (Type 82), which was itself obsoleted by RFC 6814.
  PyTCP does not implement IPv4 option Type 82.
- **§2.7 Datagram Conversion Error (Type 31)**: tied to TP/IX
  (RFC 1475 Historic). PyTCP has no TP/IX support.
- **§2.8 Mobile Host Redirect (Type 32)**: experimental mobility
  protocol. Mobility extensions (MIPv6, NEMO, etc.) are listed
  as out-of-scope non-goals in `CLAUDE.md` Project North Star.
- **§2.9–§2.12 IPv6/Mobile types (Types 33–36)**: never widely
  deployed; mobility scope per North Star.
- **§2.13/§2.14 Domain Name Req/Reply (Types 37/38)**: RFC 1788
  was changed to Historic by §4 of this RFC. PyTCP uses standard
  DNS for FQDN resolution.
- **§2.15 SKIP (Type 39)**: never standardised; superseded by
  IKE/IPsec, which are out-of-scope crypto extensions.

## §3 IANA Considerations

> "This document formally deprecates the following ICMP message
> Types and requests IANA to mark them as such in the
> corresponding registry."

**Adherence:** **shipped (structural).** PyTCP's `Icmp4Type`
enum (`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message.py`)
contains exactly five members: `ECHO_REPLY` (0),
`DESTINATION_UNREACHABLE` (3), `ECHO_REQUEST` (8),
`TIME_EXCEEDED` (11), `PARAMETER_PROBLEM` (12). None of the 15
deprecated types appears. A grep-level audit confirms no
references to any deprecated type name (`grep -r "INFORMATION_R"
"ADDRESS_MASK" "DOMAIN_NAME" "MOBILE_HOST" "ALTERNATE_HOST"
"DATAGRAM_CONVERSION" "TRACEROUTE" "SKIP" packages/net_proto/net_proto/ packages/pytcp/pytcp/`
returns no implementation hits).

The note at the end of §3 ("The ICMPv4 Source Quench Message
(Type 4) has already been deprecated by RFC 6633") is covered
by the parallel adherence record at
[`docs/rfc/icmp4/rfc6633__deprecate_source_quench/adherence.md`](../rfc6633__deprecate_source_quench/adherence.md).

## §4 Changing the Status of RFC 1788 to Historic

**Adherence:** n/a (no implementation impact — informational).

## §5 Security Considerations

> "This document does not modify the security properties of the
> ICMPv4 message types being deprecated. However, formally
> deprecating these message types serves as a basis for, e.g.,
> filtering these packets."

**Adherence:** **shipped (vacuous).** PyTCP's silent-discard
path filters all deprecated-type packets at the ICMPv4 RX layer.
The §8 SHOULD-log clause inherited from RFC 6633 (security-fault
logging of unknown ICMPv4) applies equivalently here; the
unknown-type debug log is informational rather than
security-tier, recorded as a Phase-2 polish item in the RFC 6633
adherence record.

---

## Test coverage audit

| Aspect                                                          | Coverage |
|-----------------------------------------------------------------|----------|
| §3 host generation MUST NOT happen (TX-side structural)         | shipped — codebase grep returns no hits for any deprecated-type name |
| §3 host RX silently discards deprecated types                   | shipped — see test classes below |
| §3 Type 17 (Address Mask Request) RX no TX                      | shipped — `test__icmp4__rx__addr_mask_request__no_tx` |
| §3 Type 17 RX bumps `icmp4__failed_parse__drop`                 | shipped — `test__icmp4__rx__addr_mask_request__packet_stats_rx` |
| §3 Type 4 (Source Quench, related RFC 6633) RX no TX            | shipped — `TestIcmp4Rx__SourceQuench__Rfc6633` |
| §3 generic unknown type (Type 99) silent discard                | shipped — `TestIcmp4Rx__UnknownType` |
| §3 14 other deprecated types (6, 15, 16, 18, 30–36, 37, 38, 39) | covered transitively — they share the unknown-type code path with Types 17 and 99 |
| §4 RFC 1788 Historic                                            | n/a (no implementation impact) |
| §5 security-tier logging of deprecated-type discard             | partial — debug log present, security tier is Phase-2 polish (see RFC 6633 §8 audit) |

The 14 untested-individually deprecated types share a single
code path with Types 17 and 99: the `Icmp4Parser._parse()`
match statement falls through to `Icmp4MessageUnknown` for
every type value not in the enum. Adding 14 more
near-identical test methods would not increase coverage of
distinct branches; the existing tests pin the path.

---

## Overall assessment

| Aspect                                                | Status              |
|-------------------------------------------------------|---------------------|
| §3 IANA cleanup — host structural deprecation         | **shipped (structural)** |
| §3 RX silently discards 15 deprecated types           | **shipped**         |
| §4 RFC 1788 Historic                                  | n/a                 |
| §5 host filter / security log                         | partial (Phase-2)   |

PyTCP's compliance with RFC 6918 is structural rather than
gated, identical in mechanism to RFC 6633: the codebase
predates the IANA cleanup but never implemented any of the
deprecated types. No active deprecation logic is required.
The single Phase-2 polish item is the unknown-type log
channel's security-tier promotion, recorded in the RFC 6633
adherence record and shared with this one.
