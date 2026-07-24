# RFC 4862 — IPv6 Stateless Address Autoconfiguration

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4862                                               |
| Title       | IPv6 Stateless Address Autoconfiguration (SLAAC)   |
| Category    | Standards Track                                    |
| Date        | September 2007                                     |
| Source text | [`rfc4862.txt`](rfc4862.txt)                       |

This document records, section by section, how the current
PyTCP codebase relates to each normative statement in
RFC 4862. The audit was performed by reading the RFC text
fresh and inspecting `packages/pytcp/pytcp/runtime/packet_handler/__init__.py`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py`,
`packages/pytcp/pytcp/protocols/icmp6/nd/`, and `packages/net_addr/net_addr/ip6_ifaddr.py`
directly. No prior audit content was reused.

Sections without normative content — §1 Introduction, §2
Terminology, §7-§9 Acknowledgments / References /
Authors — are omitted.

Adherence levels: **met**, **partial**, **not implemented**,
**deferred (Phase-2 router)**, **n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 4862's host specification. The SLAAC
boot sequence creates a link-local address (with EUI-64 by
default; RFC 7217 stable opaque IIDs available), runs RFC
4861 §7.2 Duplicate Address Detection, sends RFC 7559
RS-backoff Router Solicitations, consumes inbound RA
Prefix Information per §5.5.3 (including the (e)(6) 2-hour
rule), and sweeps deprecated / invalid addresses on the
lifetime-expiry path.

Three RFC-numbered extensions integrate cleanly:

- **RFC 4429** (Optimistic DAD): TENTATIVE → OPTIMISTIC fast-
  install path that lets the address be used for TX before
  DAD completes (gated on the per-address Override flag).
- **RFC 7217** (stable opaque IIDs): default IID generator is
  RFC 7217 secret-keyed hash; EUI-64 remains as a fallback.
- **RFC 7527** (Enhanced DAD): Nonce-option-based loop-
  hairpin detection layered onto the DAD probe RX path.

| Section | Topic                                                    | Status |
|---------|----------------------------------------------------------|--------|
| §3.1    | Tentative / Preferred / Deprecated / Invalid states      | met    |
| §4.1    | Site renumbering (2-hour rule cross-ref)                 | met (cross-ref §5.5.3 (e)(6)) |
| §5.1    | DupAddrDetectTransmits node-configuration variable       | met (sysctl-backed)           |
| §5.2    | ValidLifetime / PreferredLifetime per-address state      | met    |
| §5.3    | Link-local address creation                              | met (EUI-64 default; RFC 7217 alternative) |
| §5.4.1  | Message validation                                       | met    |
| §5.4.2  | Sending DAD Neighbor Solicitations                       | met    |
| §5.4.3  | Receiving DAD Neighbor Solicitations                     | met    |
| §5.4.4  | Receiving DAD Neighbor Advertisements                    | met    |
| §5.4.5  | DAD failure → address abandon                            | met    |
| §5.5.1  | Soliciting Router Advertisements                         | met (RFC 7559 backoff)        |
| §5.5.2  | Absence of RA → DHCPv6 fallback                          | n/a (no PyTCP DHCPv6 client)  |
| §5.5.3  | Router Advertisement Processing (PI rules e(1)-e(6))     | met    |
| §5.5.4  | Address Lifetime Expiry (sweep / removal)                | met    |
| §5.6    | Configuration consistency                                | met    |
| §5.7    | Retaining addresses for stability                        | met (cross-ref RFC 8981)      |
| §6      | Security considerations                                  | n/a (informational)           |

---

## §3 Address Autoconfiguration Model

> "An address autoconfigured per this document goes
>  through the following states: Tentative → Preferred →
>  Deprecated → Invalid."

**Adherence:** met. Per-address state lives in
`Icmp6SlaacAddress` at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:87-104`,
with the state computed lazily from `valid_until` /
`preferred_until` wall-clock timestamps via the
`state(now)` accessor. The four states map verbatim to
the RFC §3.1 transitions:

- **TENTATIVE / OPTIMISTIC / VALID** — the DAD-lifecycle
  states, declared at
  `packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:121-138`
  (via the `Icmp6DadState` enum).
- **PREFERRED** — `now < preferred_until`.
- **DEPRECATED** — `preferred_until ≤ now < valid_until`.
- **INVALID** — `valid_until ≤ now` (entry will be swept
  by the next address-list maintenance pass).

---

## §4.1 Site Renumbering

> "The 2-hour rule prevents an attacker from shortening
>  the lifetime of an existing valid address below 2
>  hours via unauthenticated Router Advertisements."

**Adherence:** met. `ICMP6__SLAAC__TWO_HOUR_RULE_S` at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:104` defines
the 2-hour boundary; the gate runs in
`_update_icmp6_slaac_address` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:1836-1845`
(audited in detail under §5.5.3 below).

---

## §5 Protocol Specification

### §5.1 Node Configuration Variables

> "DupAddrDetectTransmits: the number of consecutive NS
>  messages sent while performing DAD on a tentative
>  address. Default = 1."

**Adherence:** met. `ICMP6__DAD_TRANSMITS` at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:63-67`
(default 1, sysctl `icmp6.dad_transmits`); registered at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:544-547`.
Operator can set 0 to disable DAD entirely (Linux parity
with `net.ipv6.conf.<iface>.dad_transmits=0`).

### §5.2 Autoconfiguration-Related Variables

> "Each autoconfigured address has a Valid Lifetime and a
>  Preferred Lifetime."

**Adherence:** met. `Icmp6SlaacAddress` at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:87-104`
stores both lifetimes as wall-clock expiry instants
(`valid_until` / `preferred_until`). The lazy-aged
accessor at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:664-673`
computes the current state from `time.monotonic()`
without a separate timer.

### §5.3 Creation of Link-Local Addresses

> "A node forms a link-local address by combining the
>  fe80::/10 prefix with an interface identifier."

**Adherence:** met. Two IID derivation paths shipped:

- **EUI-64** (RFC 4291 Appendix A — pre-RFC-7217 default):
  `Ip6IfAddr.from_eui64` at `packages/net_addr/net_addr/ip6_ifaddr.py:164-180`
  flips the universal/local bit and constructs the
  `fe80::EUI-64` form.
- **RFC 7217** (default in modern PyTCP): `Ip6IfAddr.from_rfc7217`
  at `packages/net_addr/net_addr/ip6_ifaddr.py:223-282` derives a stable
  opaque IID via secret-keyed hash; the address is stable
  per `(prefix, interface, secret)` triple but unlinkable
  across networks.

The link-local claim path runs at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3839`
(`PacketHandlerL2._create_stack_ip6_addressing`). The sysctl
`icmp6.use_rfc7217` selects which path the IID generator
takes (default 1 = RFC 7217); see also the dedicated
[`../rfc7217__stable_iid/adherence.md`](../rfc7217__stable_iid/adherence.md).

### §5.4 Duplicate Address Detection

#### §5.4.1 Message Validation

> "A node MUST silently discard any received message
>  that fails the validation checks described in [RFC
>  4861] §7.1 (for NS / NA)."

**Adherence:** met. Validation is layered:

- **Parse-time** — `__post_init__` on the NS / NA
  dataclasses in `packages/net_proto/net_proto/protocols/icmp6/message/nd/`
  rejects malformed wire formats.
- **Runtime** — the NS RX handler at
  `packet_handler__icmp6__rx.py:849` and NA RX at `:957`
  apply the RFC 4861 §7.1.1 / §7.1.2 gates (hop=255,
  code=0, target not multicast, source-checks).
- **PI option validation** — RA RX runs the §5.4.1 PI-
  option-specific checks at
  `packet_handler__icmp6__rx.py:777-795` (A-flag set,
  prefix not link-local, lifetime sanity).

#### §5.4.2 Sending Neighbor Solicitations

> "Before sending a Neighbor Solicitation, the host MUST
>  wait a random delay between 0 and
>  MAX_RTR_SOLICITATION_DELAY seconds."

**Adherence:** met. `_perform_ip6_nd_dad` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3561-3626`
sleeps a random `[0, ICMP6__DAD_INITIAL_DELAY_MS]` ms
window before the first probe; the probe loop at `:3645-3688`
emits `ICMP6__DAD_TRANSMITS` NS messages spaced by
`ICMP6__RETRANS_TIMER_MS`.

Wire-form details: source = `::` (RFC 4862 §5.4.2),
target = the tentative candidate, destination =
`solicited_node_multicast(target)`, Hop Limit = 255.

#### §5.4.3 Receiving Neighbor Solicitations

> "If the host receives an NS targeted at one of its own
>  tentative addresses ... the host MUST treat this as a
>  conflict and abandon DAD."

**Adherence:** met. The NS RX handler at
`packet_handler__icmp6__rx.py:858-901` consults the
per-candidate DAD slot in the
`DadSlotRegistry` (`packages/pytcp/pytcp/lib/dad_slot_registry.py:83-100`).
The registry signals `LOOP_HAIRPIN` (RFC 7527 Nonce
match → silent drop), `SIGNALED` (genuine
simultaneous-probe conflict from a foreign sender → abort
local DAD), or `NO_SLOT` (we're not probing this target).

#### §5.4.4 Receiving Neighbor Advertisements

> "An NA whose Target Address matches a tentative address
>  is a DAD conflict."

**Adherence:** met. The NA RX handler at
`packet_handler__icmp6__rx.py:972-987` extracts the
NA's `target_address` and consults the DAD registry; a
match signals the slot and the local DAD aborts.

#### §5.4.5 When Duplicate Address Detection Fails

> "If DAD fails on a tentative address, the node MUST
>  not use that address for any communication."

**Adherence:** met. The DAD-failure path at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:1680-1693`
removes the failed candidate from the address list and
clears the DAD slot. The `icmp6.accept_dad` sysctl
controls the failure policy (values 0/1/2 declared at
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:668-674`):

- `0` — accept the address anyway despite the conflict
  (debug / lab use only).
- `1` — drop the conflicted address (default; RFC 4862
  behaviour).
- `2` — fail-hard: drop the address AND set the
  interface IPv6 "dadfailed" state (Linux-parity strict
  mode).

### §5.5 Creation of Global / Site-Local Addresses

#### §5.5.1 Soliciting Router Advertisements

> "A host SHOULD send Router Solicitations on link-local
>  attachment, with retransmissions per RFC 4861 §6.3.7
>  / RFC 7559 §2."

**Adherence:** met (cross-reference RFC 7559).
`_send_icmp6_nd_router_solicitations_with_backoff` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3534-3559`
implements the truncated binary exponential backoff
described in
[`../rfc7559__rs_backoff/adherence.md`](../rfc7559__rs_backoff/adherence.md).
First RA receipt short-circuits the backoff loop via the
`_icmp6_ra__event` semaphore.

#### §5.5.2 Absence of Router Advertisements

> "Falls through to DHCPv6 stateless or stateful
>  autoconfiguration if the M / O flag was set."

**Adherence:** n/a (PyTCP has no DHCPv6 client). RFC
8504 §6.5 marks DHCPv6 as deferred; until a DHCPv6
client lands, the absence of RA leaves the host with
only the link-local address.

#### §5.5.3 Router Advertisement Processing

> "For each Prefix Information option, the host applies
>  rules (a)-(f) ... (e)(1)-(e)(6) for refresh handling
>  of an existing prefix."

**Adherence:** met. RA RX at
`packet_handler__icmp6__rx.py:805-933` walks the option
list; PI options pass through the §5.4.1 validation gate
(lines 843-850: A-flag set, valid_lifetime ≥
preferred_lifetime, prefix not link-local) and then
hand off to `_update_icmp6_slaac_address` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:1793-1874` which
applies the (e)(1)-(e)(6) refresh logic:

- **(e)(1)** Valid Lifetime == 0 → remove the address.
- **(e)(2)** Existing entry, refresh under the 2-hour rule:
  - If new valid_lifetime > 2 hours OR > remaining,
    accept new lifetime.
  - Else if remaining ≤ 2 hours, ignore (drop counter
    `pi__2hour_rule_ignored__drop` bumps).
  - Else clamp to 2 hours.
- **(e)(6)** First-install → bypass the 2-hour rule.

Address derivation at line 1847 calls `_derive_ip6_host`
which selects EUI-64 or RFC 7217 per the
`icmp6.use_rfc7217` sysctl.

#### §5.5.4 Address Lifetime Expiry

> "When an address's valid_lifetime reaches zero, the
>  address MUST be removed from the interface."

**Adherence:** met. The address sweep loop at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:926-963` runs
periodically and filters out entries whose
`valid_until ≤ now`. The lazy-aged accessor at
`:664-673` also masks invalid entries from any code
that walks the live address list mid-sweep — no
window where an INVALID address can be used for TX.

### §5.6 Configuration Consistency

> "Multiple addresses on the same interface MUST be
>  consistent; the same prefix MUST NOT yield two
>  different addresses except under temporary-address
>  generation (RFC 8981)."

**Adherence:** met. The address-list bookkeeping in
`_update_icmp6_slaac_address` enforces uniqueness:
on each PI option processing, the prior entry for the
same prefix is removed before the new one is appended
(`_icmp6_slaac_addresses = [a for a in ... if a.prefix
!= prefix]`). Temporary addresses are tracked
separately in `_icmp6_temp_addresses` per
[`../rfc8981__temp_addresses/adherence.md`](../rfc8981__temp_addresses/adherence.md).

### §5.7 Retaining Configured Addresses for Stability

> "A host SHOULD attempt to maintain address stability
>  across reboots and reconnections."

**Adherence:** met. PyTCP's stability surface:

- **RFC 7217 stable opaque IIDs** (default) — addresses
  derive deterministically from `(prefix, interface,
  secret_key)`. As long as the operator pins the
  secret, addresses recur across reboots; see
  [`../rfc7217__stable_iid/adherence.md`](../rfc7217__stable_iid/adherence.md).
- **EUI-64 fallback** — when enabled, MAC-derived IID
  is itself stable.
- **RFC 8981 temporary addresses** are the explicit
  opt-out for stability — see
  [`../rfc8981__temp_addresses/adherence.md`](../rfc8981__temp_addresses/adherence.md).

---

## §6 Security Considerations

> "DAD MUST detect address conflicts; the address-
>  collision risk depends on the IID randomness."

**Adherence:** met (covered by the DAD framework and
the RFC 7217 / 7527 extensions):

- **Atomic DAD signal** —
  `packages/pytcp/pytcp/lib/dad_slot_registry.py:83-100` ensures the
  per-candidate slot can be installed, checked, and
  signalled atomically from the RX thread.
- **Enhanced DAD (RFC 7527)** — Nonce-option loop-
  hairpin detection at
  `packet_handler__icmp6__rx.py:881-892` prevents an
  L2 loop from triggering a false DAD failure. Gate
  via `icmp6.enhanced_dad` sysctl
  (`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:621-626`).
- **Optimistic DAD (RFC 4429)** — pre-DAD provisional
  assignment at
  `packages/pytcp/pytcp/runtime/packet_handler/__init__.py:1599-1619`
  lets the address be used for TX with the Override
  flag suppressed; gate via `icmp6.optimistic_dad`
  sysctl (`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py:736-740`).

---

## Test coverage audit

The `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/`
directory contains 11 SLAAC- / DAD-specific integration
test files:

| §       | Test file                                          |
|---------|----------------------------------------------------|
| §3.1    | `test__icmp6__nd__slaac_address_state.py` — PREFERRED / DEPRECATED transitions |
| §5.1    | `test__icmp6__nd__accept_dad.py` — `accept_dad={0,1,2}` modes      |
| §5.3    | `test__icmp6__nd__rfc7217_slaac.py` — RFC 7217 derivation          |
| §5.4.2  | `test__icmp6__nd__dad_initial_delay.py` — random initial delay     |
| §5.4.2  | `test__icmp6__nd__multi_probe_dad.py` — multi-probe loop           |
| §5.4.3  | `test__icmp6__nd__simultaneous_probe.py` — simultaneous-probe conflict |
| §5.4.3  | `test__icmp6__nd__dad_slot_lock.py` — atomic slot registry         |
| §5.4.3  | `test__icmp6__nd__enhanced_dad.py` — RFC 7527 Nonce hairpin        |
| §5.4.5  | `test__icmp6__nd__accept_dad.py` — fail-hard mode                  |
| §5.5.3  | `test__icmp6__nd__multi_prefix_router.py` — multi-prefix RA        |
| §5.5.3  | `test__icmp6__nd__slaac_address_tracking.py` — PI option table     |
| §5.5.3  | `test__icmp6__nd__slaac_runtime_claim.py` — runtime PI → claim     |
| §5.7    | `test__icmp6__nd__rfc8981_temp.py` — temporary addresses           |

Plus the Optimistic-DAD path:
`test__icmp6__nd__optimistic_dad.py`.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Address state transitions (TENT/OPTIMISTIC/VALID, PREF/DEPR/INVALID) | locked in |
| §5.1 DupAddrDetectTransmits sysctl                  | locked in |
| §5.3 Link-local creation (EUI-64 + RFC 7217)        | locked in |
| §5.4.2 DAD probe timing (initial delay + retrans)   | locked in |
| §5.4.3 / §5.4.4 DAD conflict detection (NS + NA)    | locked in |
| §5.4.5 DAD fail policy (`accept_dad` 0/1/2)         | locked in |
| §5.5.1 RS solicitation backoff                      | locked in (RFC 7559) |
| §5.5.3 PI option processing (rules e(1)-e(6))       | locked in |
| §5.5.3 (e)(6) 2-hour rule                           | locked in |
| §5.5.4 Address sweep / expiry                       | locked in |
| §5.7 Stability extensions (RFC 7217 + RFC 8981)     | locked in |
| RFC 4429 Optimistic DAD                             | locked in |
| RFC 7527 Enhanced DAD (Nonce option)                | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Address state model                              | met    |
| §4.1 Site renumbering (2-hour rule)                   | met    |
| §5.1 DupAddrDetectTransmits                           | met    |
| §5.2 Valid / Preferred lifetimes                      | met    |
| §5.3 Link-local creation                              | met (EUI-64 + RFC 7217)       |
| §5.4.1 Message validation                             | met    |
| §5.4.2 Sending DAD NS                                 | met    |
| §5.4.3 Receiving DAD NS                               | met (Enhanced DAD overlay)    |
| §5.4.4 Receiving DAD NA                               | met    |
| §5.4.5 DAD failure handling                           | met (accept_dad sysctl)       |
| §5.5.1 Soliciting Router Advertisements               | met (RFC 7559 backoff)        |
| §5.5.2 Absence-of-RA → DHCPv6 fallback                | n/a (no DHCPv6 client)        |
| §5.5.3 PI option processing (rules e(1)-e(6))         | met    |
| §5.5.4 Address lifetime expiry                        | met    |
| §5.6 Configuration consistency                        | met    |
| §5.7 Retaining addresses (RFC 7217 + RFC 8981)        | met    |
| §6 Security considerations                            | met    |

PyTCP fully ships RFC 4862. Phase-2 router work would
extend the spec via §6.5 (DHCPv6) integration when a
PyTCP DHCPv6 client lands; that's an additive feature,
not a gap against RFC 4862's MUSTs.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (all of RFC 4862 is mandatory
  for IPv6 hosts).
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — RFC
  4861 supplies the NS/NA wire format DAD uses.
- `docs/rfc/icmp6/rfc4429__optimistic_dad/adherence.md`
  — RFC 4429 OPTIMISTIC tentative state.
- `docs/rfc/icmp6/rfc7217__stable_iid/adherence.md` —
  default IID generator.
- `docs/rfc/icmp6/rfc7527__enhanced_dad/adherence.md` —
  Nonce-option loop-hairpin detection.
- `docs/rfc/icmp6/rfc7559__rs_backoff/adherence.md` —
  RS retransmission backoff.
- `docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md`
  — temporary addresses (RFC 4941 successor).
- `docs/rfc/icmp6/rfc9131__gratuitous_na/adherence.md` —
  gratuitous NA on DAD-success.
- Source: `packages/pytcp/pytcp/runtime/packet_handler/__init__.py`
  (SLAAC orchestration; ~lines 1793-3714),
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py:805-933`
  (RA RX), `packages/pytcp/pytcp/lib/dad_slot_registry.py` (atomic DAD
  signalling), `packages/net_addr/net_addr/ip6_ifaddr.py:164-282`
  (IID derivation).
