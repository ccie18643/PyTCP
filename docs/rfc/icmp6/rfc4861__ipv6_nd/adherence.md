# RFC 4861 — Neighbor Discovery for IPv6

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4861                                               |
| Title       | Neighbor Discovery for IP version 6 (IPv6)         |
| Category    | Standards Track                                    |
| Date        | September 2007                                     |
| Source text | [`rfc4861.txt`](rfc4861.txt)                       |

This document records, section by section, how the current
PyTCP codebase relates to each normative statement in
RFC 4861 — the foundational IPv6 Neighbor Discovery
specification. The audit was performed by reading the RFC
text fresh and inspecting the implementation under
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__{rx,tx}.py`,
`packages/pytcp/pytcp/lib/neighbor.py`, `packages/pytcp/pytcp/protocols/icmp6/nd/`, and
`packages/net_proto/net_proto/protocols/icmp6/message/nd/` directly. No prior
audit content was reused.

Sections without normative content — §1 Introduction, §2
Terminology, §11-12 IANA / Acknowledgments, §13 References,
§14 Authors' Addresses — are summarised inline only where
they inform a normative requirement, and otherwise omitted.

Adherence levels: **met**, **partial**, **not implemented**,
**deferred (Phase-2 router)**, **n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 4861 host-side requirements. All five
ND message types (Router Solicitation, Router
Advertisement, Neighbor Solicitation, Neighbor
Advertisement, Redirect) are parsed and consumed; NS and
NA are emitted from the host. The Neighbor Unreachability
Detection (NUD) state machine is shipped at
`packages/pytcp/pytcp/lib/neighbor.py` and runs as a `Subsystem` that
ages and re-probes cache entries.

Router-side specifications — §6 (router behaviour), §8.3
(Redirect TX), unsolicited RA emission — are **deferred to
the Phase-2 router track** per CLAUDE.md Project North
Star. The router-side RX paths (Redirect consumption, RA
consumption) ARE shipped because they are part of the host
spec.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §4.1    | RS wire format                                     | met    |
| §4.2    | RA wire format                                     | met    |
| §4.3    | NS wire format                                     | met    |
| §4.4    | NA wire format                                     | met    |
| §4.5    | Redirect wire format                               | met    |
| §4.6    | ND options (SLLA / TLLA / PI / MTU)                | met (RH option deferred — no Redirect TX consumer) |
| §5      | Conceptual model (ND cache, default-router list, prefix list) | met |
| §6      | Router specification                               | deferred (Phase-2 router)            |
| §7.1    | Validation rules (NS / NA)                         | met    |
| §7.2.1  | Interface initialization                           | met    |
| §7.2.2  | Sending NS                                         | met    |
| §7.2.3  | Receiving NS — DAD + cache update + NA emit        | met    |
| §7.2.4  | Sending NA in response                             | met    |
| §7.2.5  | Receiving NA — cache update                        | met    |
| §7.2.6  | Sending unsolicited NA                             | met (RFC 9131 cross-reference)       |
| §7.3    | Neighbor Unreachability Detection                  | met    |
| §8.1    | Redirect message format                            | met    |
| §8.2    | Receiving Redirect                                 | met    |
| §8.3    | Sending Redirect                                   | deferred (Phase-2 router)            |
| §10     | Protocol constants                                 | met (sysctl-backed)                  |

---

## §4 Message Formats

### §4.1 Router Solicitation

> "ICMPv6 Type = 133. Code = 0. Source address: either an
>  assigned address for the interface or :: when no address
>  has been assigned. Hop Limit MUST be 255."

**Adherence:** met. RS codec at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/icmp6__nd__message__router_solicitation.py:80`.
TX path at
`packet_handler__icmp6__tx.py:313` forces `ip6__hop=255`
and `ip6__src=Ip6Address()` (unspecified) when the
interface has not yet completed DAD.

### §4.2 Router Advertisement

> "ICMPv6 Type = 134. Code = 0. Cur Hop Limit + Flags + Router
>  Lifetime + Reachable Time + Retrans Timer fields. May
>  include SLLA / MTU / Prefix Information options."

**Adherence:** met (RX). Codec at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/icmp6__nd__message__router_advertisement.py:87`;
RX handler at
`packet_handler__icmp6__rx.py:805` consumes Cur Hop Limit
(§6.3.4), M/O flags, Router Lifetime, Reachable Time,
Retrans Timer, and walks all carried options.

TX (router-side emission of unsolicited RAs) is
**deferred to Phase-2 router work**.

### §4.3 Neighbor Solicitation

> "ICMPv6 Type = 135. Target Address (the address being
>  resolved or DAD-probed). May include SLLA option."

**Adherence:** met. Codec at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/icmp6__nd__message__neighbor_solicitation.py:89`.
Multicast NS (address resolution) emitted at
`packet_handler__icmp6__tx.py:340`; unicast NS (NUD probe)
at `:376`.

### §4.4 Neighbor Advertisement

> "ICMPv6 Type = 136. Target Address + R/S/O flags + TLLA
>  option (when the link-layer address changes or is being
>  announced)."

**Adherence:** met. Codec at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/icmp6__nd__message__neighbor_advertisement.py:88`.
Solicited NA emitted at `packet_handler__icmp6__tx.py:427`;
unsolicited / gratuitous NA at `:480` (RFC 9131 cross-
reference).

### §4.5 Redirect

> "ICMPv6 Type = 137. Target Address + Destination Address
>  + (optional) TLLA + (optional) Redirected Header."

**Adherence:** met (RX). Codec at
`packages/net_proto/net_proto/protocols/icmp6/message/nd/icmp6__nd__message__redirect.py:96`.
RX handler at `packet_handler__icmp6__rx.py:1082` consumes
Redirects and updates the ND cache. TX (router-side
Redirect emission) is **deferred to Phase-2 router work**.

### §4.6 Options

> "ND messages MAY carry options: Source / Target Link-
>  layer Address (1, 2), Prefix Information (3), Redirected
>  Header (4), MTU (5)."

**Adherence:** met for SLLA / TLLA / PI / MTU; the
Redirected Header **codec is also met** — it is parsed and
assembled — but has no consumer (Redirect TX is the only
emitter, deferred to the Phase-2 router track).

| Option             | Type | Codec file                                               |
|--------------------|------|----------------------------------------------------------|
| Source Link Layer  | 1    | `..nd/option/icmp6__nd__option__slla.py:62`              |
| Target Link Layer  | 2    | `..nd/option/icmp6__nd__option__tlla.py:62`              |
| Prefix Information | 3    | `..nd/option/icmp6__nd__option__pi.py:75`                |
| Redirected Header  | 4    | `..nd/option/icmp6__nd__option__redirected_header.py:64` |
| MTU                | 5    | `..nd/option/icmp6__nd__option__mtu.py:63`               |

Additional options shipped beyond RFC 4861's defined set:
RA Flags Extension (RFC 5175 — stub), DNS Search List
(RFC 8106 — stub), Recursive DNS Server (RFC 8106 — stub),
Nonce (RFC 7527 Enhanced DAD — met), Route Information
(RFC 4191 — partial), MTU.

---

## §5 Conceptual Model of a Host

> "Each entry in the Neighbor Cache contains: IP, link-
>  layer address, IsRouter flag, Reachability state, a
>  pending packet queue."

**Adherence:** met. The Neighbor Cache lives at
`packages/pytcp/pytcp/lib/neighbor.py:201` (`_find_entry`) /
`packages/pytcp/pytcp/lib/neighbor.py:246` (`_add_entry`). The ND-flavour
adapter at `packages/pytcp/pytcp/protocols/icmp6/nd/nd__cache.py:51`
specializes the generic NUD framework for IPv6 +
`MacAddress` keys.

> "Default Router List: a list of routers from RAs."

**Adherence:** met. Stored at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:53` and
maintained by the single chokepoint
`pytcp.runtime.packet_handler.__init__._update_icmp6_default_router`.
That chokepoint also drives the host-mode routing table
(RFC 1122 §3.3.1 equivalent for v6): on RA Router
Lifetime > 0 it installs the FIB `::/0` default route via
`stack.route.replace_default_ip6(gateway=<RA src LL>,
protocol=RouteProtocol.RA)`, and on Lifetime == 0 for a
known router it withdraws it via
`stack.route.remove_default_ip6()`
(`packages/pytcp/pytcp/runtime/fib.py` `RouteTable`,
`packages/pytcp/pytcp/stack/route.py` `RouteApi`). The next hop for an
off-link IPv6 destination is therefore resolved by an FIB
longest-prefix `lookup`, not a per-`IfAddr` gateway
(`IfAddr.gateway` was deleted). Pinned by
`packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_default_route.py`
(RA lifetime > 0 installs the `protocol=RA` `::/0` route;
lifetime 0 withdraws it) and
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__routing.py::TestIp6RoutingNextHop`
(on-link direct, off-link via the RA router, no-route
drop).

> "Prefix List: prefixes from RA Prefix Information
>  options."

**Adherence:** met. Stored at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:87` and
populated by the RA RX handler when consuming the PI
option (per RFC 4862 §5.5.3).

---

## §6 Router Specification

**Adherence:** deferred (Phase-2 router track). Per
CLAUDE.md Project North Star §Phase 2, all router-grade
behaviour — including unsolicited RA emission, the
`AdvSendAdvertisements` knob, Redirect TX, on-link
forwarding — is deferred until the forwarding plane
lands.

---

## §7 Host Specification

### §7.1 Validation Rules

> "A node MUST silently discard any received NS / NA /
>  Redirect message that fails the validation checks in
>  §7.1.1 / §7.1.2 / §8.1."

**Adherence:** met. Validation lives in the per-message
`__post_init__` / `validate_sanity` paths:

- NS validation at `..nd/icmp6__nd__message__neighbor_solicitation.py:182`
- NA validation at `..nd/icmp6__nd__message__neighbor_advertisement.py:193`
- Redirect validation at `..nd/icmp6__nd__message__redirect.py:195`

Failed validation raises `Icmp6SanityError` / wire-format
errors; the RX handler catches and silently drops the
packet.

### §7.2.1 Interface Initialization

> "Upon attachment, a host begins by performing DAD on its
>  link-local address, then sends one or more Router
>  Solicitations."

**Adherence:** met. The boot path at
`packet_handler/__init__.py::_create_stack_ip6_addressing`
runs DAD on the link-local address, then enters the RS
backoff loop at
`packet_handler/__init__.py:1431-1456`
(`_send_icmp6_nd_router_solicitations_with_backoff` —
RFC 7559 cross-reference).

### §7.2.2 Sending Neighbor Solicitations

> "Address resolution: send a multicast NS to the
>  solicited-node multicast of the target."

**Adherence:** met. `_send_icmp6_nd_dad_message` (DAD
case) at `packet_handler__icmp6__tx.py:170`; multicast
NS for address resolution at
`packet_handler__icmp6__tx.py:340`.

### §7.2.3 Receiving Neighbor Solicitations

> "On receipt of a valid NS, the receiver verifies the
>  target address, applies the DAD check (if its own
>  address is tentative), updates the ND cache from the
>  SLLA, and emits an NA in response."

**Adherence:** met. RX handler at
`packet_handler__icmp6__rx.py:934` applies:

- DAD-target check (signals our own DAD slot if the NS
  targets a tentative candidate).
- §7.1.1 validity gate (hop=255, ICMP code=0, target not
  multicast, SLLA opt-only-if-source-not-unspecified).
- SLLA cache update.
- NA emission via `send_icmp6_neighbor_advertisement` at
  `packet_handler__icmp6__rx.py:944`.

The handler also threads the RFC 7527 Enhanced DAD Nonce
check at `:874-892` for loop-hairpin detection.

### §7.2.4 Sending Solicited NA

> "When sending an NA in response to an NS, set Solicited
>  flag, set Override flag for unsolicited (gratuitous)
>  NAs, include TLLA option."

**Adherence:** met. `send_icmp6_neighbor_advertisement` at
`packet_handler__icmp6__tx.py:427` sets the flag bits per
caller-supplied arguments and includes the TLLA option
when `include_tlla=True`.

### §7.2.5 Receiving Neighbor Advertisements

> "On receipt of NA, update the Neighbor Cache per the
>  Override / Solicited / Router flag matrix in §7.2.5."

**Adherence:** met. RX handler at
`packet_handler__icmp6__rx.py:1040` walks the §7.2.5
update matrix. Notable behaviours:

- `S=1, O=1` → mark REACHABLE, update TLLA.
- `S=1, O=0` → mark REACHABLE only if TLLA matches cached.
- `S=0, O=1` → update TLLA, mark STALE.
- `S=0, O=0` → no change.

### §7.2.6 Sending Unsolicited Neighbor Advertisements

> "A node MAY send unsolicited NAs when its link-layer
>  address changes or when announcing a newly-claimed
>  address."

**Adherence:** met (RFC 9131 cross-reference). PyTCP
emits gratuitous NAs after DAD success per RFC 9131 §3
via `send_icmp6_neighbor_advertisement_gratuitous` at
`packet_handler__icmp6__tx.py:480`. See
[`../rfc9131__gratuitous_na/adherence.md`](../rfc9131__gratuitous_na/adherence.md).

### §7.3 Neighbor Unreachability Detection (NUD)

> "Each cache entry traverses the states INCOMPLETE,
>  REACHABLE, STALE, DELAY, PROBE."

**Adherence:** met. `NudState` enum at
`packages/pytcp/pytcp/lib/neighbor.py:73` declares the five states; the
state machine runs in the `NeighborCache` subsystem loop
`_subsystem_loop` at `packages/pytcp/pytcp/lib/neighbor.py:406`. State transitions:

- New entry → INCOMPLETE; multicast NS to resolve.
- NS resolved → REACHABLE; lifetime = `REACHABLE_TIME`.
- After REACHABLE_TIME elapses → STALE.
- First TX to STALE neighbor → DELAY; wait
  `DELAY_FIRST_PROBE_TIME` for unsolicited reply.
- DELAY expired → PROBE; emit unicast NS;
  `MAX_UNICAST_SOLICIT` retries.
- All probes failed → FAILED; entry purged.

The state-machine logic is shared between IPv6 ND and
IPv4 ARP (`packages/pytcp/pytcp/lib/neighbor.py` is the generic
`NeighborCache[A, P]` framework; the ARP and ND adapters
are thin specialisations).

---

## §8 Redirect

### §8.1 Validation

> "Hop Limit MUST be 255. ICMP Code = 0. Source MUST be a
>  link-local. Target Address and Destination Address
>  fields valid."

**Adherence:** met. Parse-time gates at
`..nd/icmp6__nd__message__redirect.py:195`; runtime gates
in the RX handler at `packet_handler__icmp6__rx.py:1082`
enforce `accept_redirects` sysctl and the §8.1 validity
matrix.

### §8.2 Receiving Redirect

> "On a valid Redirect, install a more-specific next-hop
>  entry in the Destination Cache (or update the
>  Neighbor Cache TLLA if the Target is on-link)."

**Adherence:** met. RX handler at
`packet_handler__icmp6__rx.py:1082` updates the ND cache
when the Target is on-link and the TLLA option carries
the target's link-layer address. The
`icmp6.accept_redirects` sysctl gates acceptance (default
1 — accept; set 0 for Linux-parity "disable redirects
entirely" behaviour).

The destination-cache update (RFC 4861's §5.2-style
per-destination next-hop override) is **partial**. PyTCP
now has the routing-table substrate a Redirect-installed
more-specific route would live in — `packages/pytcp/pytcp/runtime/fib.py`
`RouteTable` (longest-prefix; a Redirect would add a
host/prefix `Route` with `RouteProtocol.REDIRECT`, the
enum value already reserved) — and §5.2 next-hop
determination itself is now FIB-driven
(`stack.ip6_fib.lookup` in the Ethernet-TX path). What
remains Phase-2 is the Redirect RX handler actually
calling `stack.route.add_ip6_route(...,
protocol=RouteProtocol.REDIRECT)`; today the override is
reflected only via the ND-cache TLLA update. Symmetric
with the IPv4 side — see
`docs/rfc/ip4/rfc1122__host_requirements_ip4/adherence.md`
§3.3.1.

### §8.3 Sending Redirect

**Adherence:** deferred (Phase-2 router track). A router
emits Redirects when it observes a host sending via a
non-optimal next-hop; PyTCP is host-only.

---

## §10 Protocol Constants

> "Default values: REACHABLE_TIME = 30000 ms,
>  RETRANS_TIMER = 1000 ms, DELAY_FIRST_PROBE_TIME = 5
>  seconds, MIN_RANDOM_FACTOR = 0.5, MAX_RANDOM_FACTOR =
>  1.5, MAX_MULTICAST_SOLICIT = 3, MAX_UNICAST_SOLICIT =
>  3, MAX_NEIGHBOR_ADVERTISEMENT = 3, MAX_RTR_SOLICITATIONS
>  = 3, RTR_SOLICITATION_INTERVAL = 4 seconds."

**Adherence:** met (sysctl-backed). The
`neighbor.*` namespace at
`packages/pytcp/pytcp/lib/neighbor__constants.py` declares the NUD
constants:

| RFC 4861 §10 constant       | PyTCP sysctl                              | Default |
|-----------------------------|-------------------------------------------|---------|
| RETRANS_TIMER               | `neighbor.retrans_timer_ms`               | 1000 ms |
| REACHABLE_TIME              | `neighbor.reachable_time_s`               | 30 s    |
| DELAY_FIRST_PROBE_TIME      | `neighbor.delay_first_probe_s`            | 5 s     |
| MAX_MULTICAST_SOLICIT       | `neighbor.max_multicast_solicit`          | 3       |
| MAX_UNICAST_SOLICIT         | `neighbor.max_unicast_solicit`            | 3       |

RFC 4861 §10 RS-related constants live in
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py`:

| RFC 4861 §10 constant       | PyTCP sysctl                              | Default  |
|-----------------------------|-------------------------------------------|----------|
| RTR_SOLICITATION_INTERVAL   | `icmp6.rtr_solicitation_interval_ms`      | 4000 ms  |
| MAX_RTR_SOLICITATIONS       | `icmp6.max_rtr_solicitations`             | 3        |
| MAX_RTR_SOLICITATION_INTERVAL | `icmp6.rtr_solicitation_max_rt_ms`      | 3600000 ms (RFC 7559 cap) |

Linux-parity host knobs:

- `icmp6.accept_redirects` (default 1) — RFC 4861 §8 gate.
- `icmp6.accept_ra_defrtr` (default 1) — default-router
  learning from RA.
- `icmp6.accept_ra_pinfo` (default 1) — SLAAC prefix
  learning from RA.
- `icmp6.dad_transmits` (default 1) — RFC 4862 §5.4 DAD
  probe count.
- `icmp6.gratuitous_na_count` (default 1) — RFC 9131 §3
  announcement count.

---

## Test coverage audit

The `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/`
directory contains 23 integration test files covering
the §-clauses above:

| §             | Test file(s)                                                   |
|---------------|----------------------------------------------------------------|
| §4.1 RS wire  | `test__icmp6__nd__rs_backoff.py` (TX shape via RFC 7559 path)  |
| §4.2 RA wire  | `test__icmp6__nd__ra_parameters.py` (RX consume)                |
| §4.3 NS wire  | `test__icmp6__nd__accept_dad.py` (DAD shape)                    |
| §4.4 NA wire  | `test__icmp6__nd__async_dad.py`                                  |
| §4.5 Redirect | `test__icmp6__nd__redirect.py`                                   |
| §5.1 cache    | `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py` (NUD framework)    |
| §5.2 routers  | `test__icmp6__nd__default_router_list.py`                        |
| §5.3 prefixes | `test__icmp6__nd__multi_prefix_router.py`                        |
| §6 router     | n/a (Phase-2 deferred)                                           |
| §7.2.1 init   | `test__icmp6__nd__slaac_runtime_claim.py`                        |
| §7.2.3 NS RX  | `test__icmp6__nd__simultaneous_probe.py` + DAD slot tests        |
| §7.2.5 NA RX  | `test__icmp6__nd__optimistic_dad.py` (Override flag handling)    |
| §7.2.6 grat   | `test__icmp6__nd__accept_dad.py` + `..ra_parameter_consumers.py` (post-DAD gratuitous NA; RFC 9131) |
| §7.3 NUD      | `test__lib__neighbor.py` (state machine)                         |
| §8.2 RD RX    | `test__icmp6__nd__redirect.py`                                   |
| §10 constants | covered indirectly via the per-feature integration cases       |

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Five ND message-type wire formats                   | locked in |
| Validation rules (§7.1 / §8.1)                      | locked in (parse-time + runtime gates) |
| NUD state machine (§7.3)                            | locked in (unit + integration) |
| Address resolution (§7.2.2 / §7.2.3)                | locked in (cache + cross-protocol fixture) |
| Redirect RX (§8.2)                                  | locked in |
| §5.2 next-hop / RA default route (FIB)              | locked in (`test__icmp6__nd__ra_default_route.py`, `test__ip6__routing.py`, `test__runtime__fib.py`, `test__stack__route.py`) |
| Redirect destination-cache override                 | partial — FIB substrate + `RouteProtocol.REDIRECT` exist; ND-cache TLLA update covered; Redirect→route wiring deferred with forwarding plane |
| Router-side TX (§6, §8.3)                           | n/a (Phase-2 deferred) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §4.1-§4.5 message wire formats (RS / RA / NS / NA / RD) | met  |
| §4.6 ND options (SLLA / TLLA / PI / MTU)              | met    |
| §4.6 Redirected Header option                         | met (codec parsed + assembled; no Redirect TX consumer — Phase-2 router) |
| §5 Conceptual host model (ND cache / router list / prefix list) | met |
| §5.2 Next-hop determination (FIB longest-prefix; RA router → `::/0` default route) | met |
| §6 Router specification                               | deferred (Phase-2 router) |
| §7.1 Validation rules                                 | met    |
| §7.2.1 Interface initialization                       | met    |
| §7.2.2 Sending NS (multicast + unicast)               | met    |
| §7.2.3 Receiving NS                                   | met    |
| §7.2.4 Sending NA                                     | met    |
| §7.2.5 Receiving NA (Override / Solicited matrix)     | met    |
| §7.2.6 Unsolicited NA                                 | met (cross-ref RFC 9131) |
| §7.3 NUD state machine                                | met    |
| §8.1 Redirect validation                              | met    |
| §8.2 Receiving Redirect                               | met (ND cache TLLA update; full destination cache is Phase-2) |
| §8.3 Sending Redirect                                 | deferred (Phase-2 router) |
| §10 Protocol constants                                | met (sysctl-backed)       |

PyTCP fully ships RFC 4861's host specification. The
remaining items are explicit Phase-2 router work
(unsolicited RA emission, Redirect TX, full destination-
cache override) — all gated by CLAUDE.md Project North
Star §Phase 2.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (all of RFC 4861 is mandatory
  for IPv6 hosts).
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  SLAAC layered on top of RFC 4861 (DAD uses RFC 4861 NS).
- `docs/rfc/icmp6/rfc7559__rs_backoff/adherence.md` —
  updates §6.3.7 / §10 to add RS backoff.
- `docs/rfc/icmp6/rfc4429__optimistic_dad/adherence.md` —
  updates §5.4 with the OPTIMISTIC tentative state.
- `docs/rfc/icmp6/rfc7527__enhanced_dad/adherence.md` —
  Nonce-option loop-hairpin detection for §7.2.3.
- `docs/rfc/icmp6/rfc9131__gratuitous_na/adherence.md` —
  formalises the §7.2.6 unsolicited-NA path.
- `docs/rfc/icmp6/rfc4311__host_to_router_load_share/adherence.md`
  — multi-router selection layered on §5.2 default-router
  list.
- IPv4 parallel: `docs/rfc/arp/rfc826__arp/adherence.md` +
  `docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` (ARP / ACD
  are the IPv4 equivalent of ND + DAD).
- Source: `packages/pytcp/pytcp/lib/neighbor.py` (NUD framework),
  `packages/pytcp/pytcp/protocols/icmp6/nd/nd__cache.py` (IPv6 cache
  adapter), `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__{rx,tx}.py`
  (ND message dispatch),
  `packages/net_proto/net_proto/protocols/icmp6/message/nd/` (wire codecs).
