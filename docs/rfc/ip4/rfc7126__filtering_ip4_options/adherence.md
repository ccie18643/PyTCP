# RFC 7126 — Recommendations on Filtering of IPv4 Packets Containing IPv4 Options

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 7126                                                 |
| Title       | Recommendations on Filtering of IPv4 Packets Containing IPv4 Options |
| Category    | Best Current Practice (BCP 186)                      |
| Date        | February 2014                                        |
| Source text | [`rfc7126.txt`](rfc7126.txt)                         |

This document records the PyTCP codebase's adherence to RFC 7126
clause by clause. RFC 7126 is a **BCP that targets routers,
security gateways, and firewalls** with per-option filtering
advice. PyTCP today is a host stack; the advice translates as
"what does PyTCP do with each option on receive" — which is the
RFC 1122 §3.2.1.8 silent-ignore baseline for most options plus
the LSRR/SSRR drop-by-default gate already in place.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_proto/net_proto/protocols/ip4/options/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py`
directly. Non-normative content (§1 Introduction, §2 IP Options
background, §3 General Security Implications, §6 IANA, §7
Security boilerplate, §8 References) is omitted.

---

## Top-line adherence

PyTCP **meets** the host-side filtering posture for the
sensitive options (LSRR / SSRR drop-by-default gated by the
per-interface `ip4.accept_source_route` sysctl). For the operationally-benign
options (EOL, NOP, Record Route, Timestamp, Router Alert,
Stream ID, deprecated MTU Probe / Reply), PyTCP accepts the
frame and delivers it normally — matching the RFC 7126 §4.5.5
/ §4.7.5 / §4.8.5 "accept and pass" advice for hosts. The
parsing-level integrity checks (option length sanity,
alignment) are enforced uniformly across all option kinds.

| Section | Option (Type)             | RFC 7126 advice          | PyTCP posture |
|---------|---------------------------|--------------------------|---------------|
| §4.1    | End of Option List (0)    | accept                   | accepted (typed `Ip4OptionEol`) |
| §4.2    | No Operation (1)          | accept                   | accepted (typed `Ip4OptionNop`) |
| §4.3    | LSRR (131)                | **drop by default**      | dropped by default (gate `ip4.accept_source_route=False`) |
| §4.4    | SSRR (137)                | **drop by default**      | dropped by default (same gate) |
| §4.5    | Record Route (7)          | drop by default (routers); host-side accept | accepted, no action |
| §4.6    | Stream Identifier (136)   | drop (obsolete)          | accepted but no typed dispatch (Unknown), no action |
| §4.7    | Timestamp (68)            | drop by default (routers); host-side accept | accepted, no action |
| §4.8    | Router Alert (148)        | accept                   | accepted, no action (see RFC 6398 audit) |
| §4.9    | Probe MTU (11) obsolete   | drop                     | not implemented (Unknown), no action |
| §4.10   | Reply MTU (12) obsolete   | drop                     | not implemented (Unknown), no action |
| §4.11   | Traceroute (82)           | drop by default          | not implemented (Unknown), no action |
| §4.12+  | CIPSO / future            | implementation-defined   | typed (`Ip4OptionCipso`), no policy action |

---

## §4.1 End of Option List (Type = 0)

> "Advice: ... if this option is present in a packet, it MUST
> NOT be ignored by IP nodes (whether routers or hosts);
> ignoring this option ... could result in ambiguous packets."

**Adherence:** met. `Ip4OptionEol` is a typed dataclass; the
options-stream parser stops at the EOL marker
(`packages/net_proto/net_proto/protocols/ip4/options/ip4__options.py`). The
remaining bytes within the IHL-bounded option area are treated
as padding (no further options parsed).

## §4.2 No Operation (Type = 1)

> "Advice: ... accept ... process ... and forward ..."

**Adherence:** met. `Ip4OptionNop` is a typed dataclass;
parsed normally and ignored (used for alignment padding).

## §4.3 LSRR (Type = 131) / §4.4 SSRR (Type = 137)

> "Routers, security gateways, and firewalls SHOULD implement
> an option-specific configuration knob ... The default setting
> for this knob SHOULD be 'drop', and the default setting MUST
> be documented."

**Adherence:** met. PyTCP applies the drop-by-default policy
to **both** LSRR and SSRR jointly via the per-interface
`ip4.accept_source_route` sysctl (backing dict
`IP4__ACCEPT_SOURCE_ROUTE` in
`packages/pytcp/pytcp/stack/__init__.py:217`, default `{"default": False}`,
read via `sysctl_iface.get_for_iface`). The RX
handler (`packet_handler__ip4__rx.py:146-158`) drops any
LSRR/SSRR-bearing frame with the
`ip4__source_route__drop` counter and a `<WARN>` log message
when the gate is off. The default matches Linux
`net.ipv4.conf.*.accept_source_route = 0`.

This is a single boolean gate (not per-option) because RFC 7126
§4.4.3 explicitly notes "the SSRR option has the same security
implications as the LSRR option" — a unified gate is
appropriate. When the operator opts in, both options become
visible on the parser object (`packet_rx.ip4.lsrr`,
`packet_rx.ip4.ssrr`) for whatever consumer wants to act on
them.

## §4.5 Record Route (Type = 7)

> "[For routers/firewalls] Drop the packet by default ... [For
> hosts] this option does not represent a direct security risk
> ... most implementations process this option ..."

**Adherence:** met (host-side accept). PyTCP parses Record
Route into the typed `Ip4OptionRr` and delivers the frame
normally. As a host the implementation does not append the
local address into the next pointer slot — that's router-side
work (§4.5.1 use is for router path recording).

## §4.6 Stream Identifier (Type = 136, obsolete)

> "Routers, security gateways, and firewalls SHOULD drop these
> packets."

**Adherence:** not implemented. Stream ID has no typed
dataclass in PyTCP (see RFC 6814 audit); on receive it lands
in `Ip4OptionUnknown` and the frame is delivered without
modification. **Gap (Phase 2 router):** when forwarding lands,
add a generic "ignore unknown option type, but log and
optionally rate-limit" gate per the BCP.

## §4.7 Internet Timestamp (Type = 68)

> "[For routers/firewalls] drop by default."

**Adherence:** host-side accept. Typed as
`Ip4OptionTimestamp`; passed through unmodified. Like RR, the
host does not write its own timestamp into received Timestamp
options — that's router-side behaviour.

## §4.8 Router Alert (Type = 148)

> "Accept ... the IP Router Alert option is meant to be
> processed by routers as a signaling mechanism for various
> protocols."

**Adherence:** met. Typed `Ip4OptionRouterAlert`; accepted on
receive. Host posture per RFC 2113 / RFC 6398: ignore on the
host side. See `docs/rfc/ip4/rfc6398__router_alert/adherence.md`.

## §4.9 / §4.10 Probe MTU / Reply MTU (Types 11, 12, obsolete)

**Adherence:** met. Not implemented as typed options
(superseded by RFC 1191 PMTUD). Received frames are parsed as
`Ip4OptionUnknown` and delivered through; the RFC 1191 PMTUD
machinery operates independently via ICMPv4 Frag-Needed
messages, not via IP option carriage.

## §4.11 Traceroute (Type = 82, RFC 1393 / RFC 6814)

**Adherence:** met. Not implemented (deprecated by RFC 6814);
falls through to `Ip4OptionUnknown`.

## §4.12 / §4.13 Security options (CIPSO / IPSO / DoD Basic / Extended)

**Adherence:** wire codec for CIPSO is shipped
(`ip4__option__cipso.py`); the option is accepted but no
labelling policy is enforced. CIPSO is an internet-draft, not
a normative RFC; PyTCP preserves the option for environments
that need it but does not act on it. RFC 7126 §4.12.5 advises
"the default behavior should be to drop these packets, except
for those administrative domains where these options are
known to be necessary" — PyTCP's posture (accept and ignore)
is consistent with the second branch (the assumption being
that an operator deploying CIPSO knows the option's role).

## §4.14 Internal use options (Experimental Flow Control, etc.)

**Adherence:** not implemented (no consumer). Such options
would land in `Ip4OptionUnknown` on receive.

---

## Option-length sanity (cross-cutting, §3.1)

> "An option-length field that is outside the possible range
> ... has been observed to put some IP implementations into
> infinite loops." (RFC 1122 §3.2.1.8, reiterated by RFC 7126)

**Adherence:** met. `Ip4Options.validate_integrity`
(`packages/net_proto/net_proto/protocols/ip4/options/ip4__options.py`) walks the
option stream during the integrity phase and rejects any
frame whose option-length declarations would extend past the
IHL-bounded options area. This is invoked from
`Ip4Parser._validate_integrity` (`ip4__parser.py:113`) before
any per-option parsing runs, so a hostile `length=0xff` on a
short option area cannot trigger any iteration into the
options stream.

---

## Test coverage audit

### §4.3 / §4.4 LSRR / SSRR drop-by-default

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__source_route.py`
  Matrix: LSRR with gate off → drop, LSRR with gate on → accept,
  SSRR with gate off → drop, SSRR with gate on → accept. Counter
  `ip4__source_route__drop` verified.

**Status:** locked in.

### Per-option wire codec (every option kind)

- **Unit:** one file per option in
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/`
  (`test__ip4__option__eol.py`, `..__nop.py`, `..__rr.py`,
  `..__lsrr.py`, `..__ssrr.py`, `..__timestamp.py`,
  `..__router_alert.py`, `..__cipso.py`, `..__unknown.py`).

**Status:** locked in.

### Option-length sanity (anti-infinite-loop)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__integrity_checks.py`
  Cases that set deliberately wrong option lengths and verify
  `Ip4IntegrityError` is raised before any per-option
  iteration runs.

**Status:** locked in.

### Phase-2 gaps

**No test surface — Phase 2 (router/firewall):**

1. Per-option drop knobs for RR / Timestamp / Stream ID /
   Traceroute / obsolete MTU Probe / Reply (the RFC 7126
   §4.5.5 / §4.6.5 / §4.7.5 / §4.9.5 / §4.10.5 / §4.11.5
   advice). When PyTCP gains a firewall plane the natural
   pattern is one sysctl per option family, with defaults
   tracking the BCP recommendation.
2. Unknown-option-kind dropping (RFC 7126 §3.2 "ignore unknown
   options is the conservative default"). PyTCP currently
   accepts and preserves; the BCP's drop-default would be a
   single sysctl `ip4.drop_unknown_options`.

### Test coverage summary

| Aspect                                                    | Coverage |
|-----------------------------------------------------------|----------|
| LSRR / SSRR drop-by-default with operator override        | locked in |
| Per-option wire-format round-trip                         | locked in |
| Option-length sanity / anti-loop                          | locked in |
| Per-option drop knobs for RR / Timestamp / etc.           | n/a (Phase 2) |
| Drop-by-default for unknown option kinds                  | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §4.1 EOL / §4.2 NOP — accept and process            | met    |
| §4.3 LSRR — drop by default with operator override  | met    |
| §4.4 SSRR — drop by default with operator override  | met (shared gate with LSRR) |
| §4.5 RR — host-side accept                          | met    |
| §4.6 Stream ID (obsolete) — drop / ignore           | met (no typed dispatch; passes through harmlessly) |
| §4.7 Timestamp — host-side accept                   | met    |
| §4.8 Router Alert — accept                          | met (cross-reference RFC 6398) |
| §4.9 / §4.10 MTU Probe / Reply (obsolete)           | met (not implemented; PMTUD via ICMP per RFC 1191) |
| §4.11 Traceroute (obsolete)                         | met (not implemented) |
| §4.12 CIPSO / security options                      | accepted (codec preserved; no labelling policy enforced) |
| Option-length sanity (anti-infinite-loop)           | met    |
| Per-option drop knobs (firewall plane)              | n/a (Phase 2) |

PyTCP meets RFC 7126's host-side filtering posture. The
Phase-2 sharpenings (per-option drop knobs for benign-but-
rarely-useful options like RR and Timestamp) become relevant
when PyTCP gains a forwarding / firewall plane.
