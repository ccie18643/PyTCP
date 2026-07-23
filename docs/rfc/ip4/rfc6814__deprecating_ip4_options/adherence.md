# RFC 6814 — Formally Deprecating Some IPv4 Options

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6814                                           |
| Title       | Formally Deprecating Some IPv4 Options         |
| Category    | Standards Track                                |
| Date        | November 2012                                  |
| Source text | [`rfc6814.txt`](rfc6814.txt)                   |

This document records the PyTCP codebase's adherence to RFC 6814
clause by clause. The audit was performed by reading the RFC
text fresh and inspecting `packages/net_proto/net_proto/protocols/ip4/options/`
directly; no prior memory or rule-file content was reused.
Non-normative content (§1 Introduction, §3 IANA, §5/§6/§7) is
omitted.

RFC 6814 is a short status update: it formally deprecates nine
IPv4 option numbers and moves three referenced RFCs to
Historic. There is no protocol-behaviour normative content
besides "do not generate these options; ignoring them on
receive remains the host posture inherited from RFC 1122
§3.2.1.8".

---

## Top-line adherence

PyTCP **meets** RFC 6814 trivially: none of the deprecated
options have a typed dataclass under
`packages/net_proto/net_proto/protocols/ip4/options/`, so the stack cannot
originate any of them. On receive, unknown option kinds fall
through to `Ip4OptionUnknown` which preserves the wire bytes
but takes no action — satisfying the inherited RFC 1122
§3.2.1.8 "silently ignore options you don't understand" rule.

| Option            | Value | PyTCP origination | RX handling |
|-------------------|-------|-------------------|-------------|
| SID (Stream ID)   | 136   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| VISA              | 142   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| ENCODE            | 15    | not implemented   | preserved as Ip4OptionUnknown, ignored |
| EIP               | 145   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| TR (Traceroute)   | 82    | not implemented   | preserved as Ip4OptionUnknown, ignored |
| ADDEXT            | 147   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| SDB               | 149   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| DPS               | 151   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| UMP               | 152   | not implemented   | preserved as Ip4OptionUnknown, ignored |
| MTUP (RFC 1063)   | 11    | not implemented   | preserved as Ip4OptionUnknown, ignored |
| MTUR (RFC 1063)   | 12    | not implemented   | preserved as Ip4OptionUnknown, ignored |

---

## §2.1 Stream ID (SID, 136)

> "The Stream ID option is obsolete."

**Adherence:** met. No `Ip4OptionStreamId` file exists. RFC 1122
§3.2.1.8 already specifies "this option SHOULD NOT be sent, and
MUST be silently ignored if received" — see the RFC 1122
audit's §3.2.1.8(b) entry for the same conclusion.

## §2.2 Extended Internet Protocol (EIP, 145)

**Adherence:** met. No typed file. EIP was an experimental IPv7
proposal superseded by IPv6 — PyTCP implements IPv6 separately
under `packages/net_proto/net_proto/protocols/ip6/`, not via this option.

## §2.3 Traceroute (TR, 82)

**Adherence:** met. No typed file. Traceroute in PyTCP would
be implemented via the standard ICMP / TTL-expiry approach, not
this experimental option.

## §2.4 ENCODE (15)

**Adherence:** met. No typed file. IP-layer encryption in PyTCP
is out of scope per CLAUDE.md's "Explicit non-goals" (no AH /
ESP / IPsec).

## §2.5 VISA (142)

**Adherence:** met. No typed file. Experimental access-control
option from 1987-89; no consumer in PyTCP.

## §2.6 Address Extension (ADDEXT, 147)

**Adherence:** met. No typed file. IPv7 experimental option.

## §2.7 Selective Directed Broadcast (SDB, 149)

**Adherence:** met. No typed file. Broadcast handling in PyTCP
follows the RFC 919 / 922 path documented in those audits.

## §2.8 Dynamic Packet State (DPS, 151)

**Adherence:** met. No typed file. DiffServ in PyTCP follows
the RFC 2474 audit; DPS was an experimental extension that
never landed.

## §2.9 Upstream Multicast Pkt. (UMP, 152)

**Adherence:** met. No typed file. Multicast routing (PIM /
BIDIR-PIM) is Phase 2 router-grade work that's not on the
PyTCP roadmap (CLAUDE.md non-goals).

## §3 (RFC 1063 MTU Probe / MTU Reply)

**Adherence:** met. RFC 1063 was already obsoleted by RFC 1191
PMTUD before RFC 6814; PyTCP implements PMTUD per RFC 1191
audit (`docs/rfc/ip4/rfc1191__pmtud_ip4/adherence.md`). The
MTUP / MTUR options have no typed file and would land in
`Ip4OptionUnknown` on receive.

## §4 — Status Changes to Historic

> "The RFC Editor has changed the status of [RFC1385], [RFC1393],
> [RFC1475], and [RFC1770] to Historic."

**Adherence:** n/a (documentation-only change). No PyTCP code
or audit references these as governing specifications.

---

## Test coverage audit

### Deprecated options fall through to Ip4OptionUnknown on receive

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__option__unknown.py`
  Verifies that any option type not matched by the typed
  dispatch chain in `Ip4Options.from_buffer` is parsed into an
  `Ip4OptionUnknown` with the original type byte preserved.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__options.py`
  Container composition tests include an `Ip4OptionUnknown` in
  the option stream and verify round-trip identity.

**Status:** locked in.

### Test coverage summary

| Aspect                                                    | Coverage |
|-----------------------------------------------------------|----------|
| Deprecated options not generated (no typed file exists)   | locked in (verifiable by repo grep — no `Ip4OptionStreamId` etc.) |
| Deprecated options preserved as Unknown on receive        | locked in via the Ip4OptionUnknown test surface |
| RFC 1063 MTUP/MTUR pre-obsoleted by RFC 1191              | locked in (PMTUD audited under RFC 1191) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §2.1-§2.9 Deprecated options: PyTCP does not originate | met |
| Inherited RFC 1122 §3.2.1.8 silent-ignore on receive | met (`Ip4OptionUnknown` pass-through) |
| §3 IANA registry markings                            | n/a (documentation) |
| §4 Historic status of referenced RFCs                | n/a (documentation) |

RFC 6814 is fully satisfied. The audit is genuinely short
because the RFC itself is just a status-change document; the
operational requirements were already covered by RFC 1122
§3.2.1.8 (audited in the RFC 1122 record) which PyTCP meets via
the typed-option-or-Unknown dispatch in `Ip4Options.from_buffer`.
