# RFC 6724 — Default Source Address Selection — Implementation Plan

> **SHIPPED (reconciled 2026-05-25).** All four phases in the status
> table below are shipped (IPv4 + IPv6 source selection, code at
> `packages/pytcp/pytcp/protocols/ip6/ip6__source_selection.py` and
> `packages/pytcp/pytcp/protocols/ip4/ip4__source_selection.py` —
> the planned `lib/` paths below are historical; the code shipped
> under `protocols/ip{4,6}/`. Integration tests under
> `tests/integration/protocols/ip{4,6}/test__ip{4,6}__rfc6724_*`).
> The "single remaining piece is source-address selection" prose
> further down is the original plan framing and is now historical —
> that piece landed.

This document tracks the multi-commit implementation arc for
RFC 6724 (Default Address Selection for IPv6) in PyTCP.
Originally tracked as `nd_linux_parity §12c / §18d`; lifted
to its own document because RFC 6724 is fundamentally a
source-address-selection concern rather than a
Neighbor-Discovery concern.

## Phase status

| Phase   | Scope                                          | Status      |
|---------|------------------------------------------------|-------------|
| §12c.1  | Rules 1, 2, 3, 8 + adherence record            | **shipped** |
| §12c.2  | Rule 7 (temp-address preference)               | **shipped** |
| §12c.3  | Rule 6 (RFC 6724 §10.3 policy table)           | **shipped** |
| §12c.4  | IPv4 source-selection symmetry                 | **shipped** |

## What's already in place (state at HEAD `4229c1a7`)

ND parity is **substantially complete** in terms of address
lifecycle:

- `_ip6_ifaddr` is fully dynamic — stable SLAAC addresses are
  claimed at boot AND on post-boot PI admission (§12a.runtime);
  RFC 8981 temp addresses are minted per-PI (§18b), regenerated
  before preferred-lifetime expiry (§18c.2), and swept from both
  the tracking table and `_ip6_ifaddr` at valid-lifetime expiry
  (§18c.1, §12a.runtime).
- DAD is async and per-address (§20.1); failures retry with
  `dad_counter` increment up to `icmp6.idgen_retries` (§20.3);
  modes gated by `icmp6.accept_dad` 0/1/2 (§20.4); RFC 4429
  Optimistic DAD via `icmp6.optimistic_dad` (§20).
- `_icmp6_slaac_addresses` records per-prefix
  PREFERRED/DEPRECATED state per RFC 4862 §5.5.4 (§12b).
- `_icmp6_temp_addresses` records per-prefix temp addresses
  with `created_at`, `preferred_until`, `valid_until`
  (§18b/c).

**The single remaining piece is source-address selection.** The
addresses cycle correctly at the lifecycle level; the TX path
just needs to consult their state when picking a source. That's
what RFC 6724 closes.

## Why it matters

Without RFC 6724 source-address selection, several behaviours
that PyTCP's current ND machinery already supports are silently
broken or incomplete:

1. **§18 RFC 8981 privacy is theatre.** PyTCP mints, claims, and
   rotates temporary addresses (§18a/b/c.1/c.2 shipped) but TX
   still picks the stable RFC 7217 address as source. Until RFC
   6724 rule 7 is wired, peers see the stable IID anyway. The
   ~300 lines of §18 work are dead weight without the consumer.
2. **DEPRECATED-aware selection.** §12b shipped the SLAAC address
   state machine (`Icmp6SlaacAddressState.PREFERRED` /
   `DEPRECATED`) but the state isn't consulted at TX time. New
   connections still pick DEPRECATED sources, and die mid-flow
   when `valid_until` passes. RFC 6724 rule 3 fixes this.
3. **Scope-leak correctness bug.** PyTCP's "first host whose
   network contains the destination" can pick a link-local
   source for a global destination. RFC 6724 rule 2 (scope
   match) prevents this.
4. **Deterministic multi-prefix behaviour.** Multi-WAN /
   multi-prefix RAs today produce non-deterministic source
   choice ("first match" depends on RA arrival order). RFC
   6724 rule 8 (longest matching prefix) makes the choice
   deterministic.
5. **Operator-tunable preference.** RFC 6724 §10.3 policy table
   lets operators express deployment policies (prefer ULA for
   ULA destinations, prefer corporate VPN address for
   corporate-prefix destinations, etc.).

## Per-RFC adherence record

Create at `docs/rfc/ip6/rfc6724__default_address_selection/`
(does not yet exist) when §12c.1 lands. The directory hosts
the spec text plus the adherence audit per the
[`rfc_adherence_audit`](.claude/skills/rfc_adherence_audit/SKILL.md)
skill convention.

## Phase split

| Phase | Scope | Lines | RFC clauses |
|---|---|---|---|
| §12c.1 | Rules 1, 2, 3, 8 + adherence record | ~150 | RFC 6724 §5 rules 1/2/3/8; §3.1 scope rules |
| §12c.2 | Rule 7 (temp-address preference) | ~80 | RFC 6724 §5 rule 7; gated by `icmp6.use_tempaddr=2` |
| §12c.3 | Rule 6 (policy table from §10.3) | ~100 | RFC 6724 §5 rule 6; §2.1 / §10.3 policy table |
| §12c.4 | IPv4 source-selection symmetry | ~100 | RFC 6724 §6 (IPv4 mapped) |

Each phase is independent enough to ship as its own commit
with its own tests-first cycle.

## §12c.1 — Rules 1, 2, 3, 8 + adherence record

The first phase. Establishes the framework and replaces the
current monolithic `__validate_src_ip6_address` algorithm with
a rule-based candidate sort.

### Current state

`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`:
the source-validation logic lives in
`__validate_src_ip6_address` (around line 173, ~115 lines).
Today it does:

- Reject if `ip6__src` not owned.
- If `ip6__src` is multicast → swap with first unicast.
- If `ip6__src` unspecified AND destination is on-link →
  pick first host on that subnet.
- If `ip6__src` unspecified AND destination external →
  pick first host with gateway.
- Special cases for DAD probe (src=::) and MLDv2 report
  (src=::).

Verify the current line range with
`grep -n "def __validate_src_ip6_address" packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`
before editing — the file has been growing.

### Target shape

Extract a new `_select_ip6_source(*, ip6__dst) -> Ip6Address |
None` method on the TX mixin. It enumerates candidate sources
from `_ip6_ifaddr`, applies RFC 6724 §5 rules in order, and
returns the winner.

```python
def _select_ip6_source(self, *, ip6__dst: Ip6Address) -> Ip6Address | None:
    candidates: list[Ip6Address] = [h.address for h in self._ip6_ifaddr]

    # Rule 1 — prefer same address.
    if ip6__dst in candidates:
        return ip6__dst

    # Rule 2 — prefer appropriate scope.
    candidates = _rule2_scope(candidates, ip6__dst)

    # Rule 3 — avoid deprecated.
    candidates = _rule3_avoid_deprecated(self._icmp6_slaac_addresses, candidates)

    # Rule 8 — longest matching prefix.
    candidates.sort(key=lambda src: -_common_prefix_len(src, ip6__dst))

    return candidates[0] if candidates else None
```

The existing `__validate_src_ip6_address` becomes a thin
wrapper that calls `_select_ip6_source` when `ip6__src` is
unspecified.

### Tests

Cover each rule in isolation:

- **Rule 1:** TX with `dst == src.address` returns `src.address`.
- **Rule 2:** Global destination + link-local + global candidates →
  picks global; link-local destination → picks link-local.
- **Rule 3:** With `_icmp6_slaac_addresses` containing both PREFERRED
  and DEPRECATED entries, picks PREFERRED.
- **Rule 8:** Multiple candidates in the same scope, picks the one
  with the longest common prefix to `ip6__dst`.

Tests live at
`packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc6724_source_selection_rules_1_2_3_8.py`
(or split into multiple files per rule if cleaner).

## §12c.2 — Rule 7 (temp-address preference)

Add the §18b/c privacy-benefit consumer. With
`icmp6.use_tempaddr=2`, prefer entries from
`_icmp6_temp_addresses` over `_icmp6_slaac_addresses` when
both are in the candidate set. With `=1`, no preference (the
default). With `=0`, temp addresses don't exist anyway.

This is the headline §18 consumer. After §12c.2 ships, an
operator who set `icmp6.use_tempaddr=2` actually gets the
privacy benefit.

## §12c.3 — Rule 6 (policy table)

RFC 6724 §10.3 specifies a default policy table:

| Prefix | Precedence | Label |
|---|---|---|
| `::1/128` | 50 | 0 |
| `::/0` | 40 | 1 |
| `::ffff:0:0/96` | 35 | 4 |
| `2002::/16` | 30 | 2 |
| `2001::/32` | 5 | 5 |
| `fc00::/7` | 3 | 13 |
| `::/96` | 1 | 3 |
| `fec0::/10` | 1 | 11 |
| `3ffe::/16` | 1 | 12 |

Rule 6 — match label of source to label of destination.
Rule 8 also uses precedence as a secondary sort key.

Ships:
- New policy table exposing the default table plus a
  `lookup(address) → (precedence, label)` function. (Shipped as
  `packages/pytcp/pytcp/protocols/ip6/ip6__policy_table.py`, not the
  planned `lib/ip6_policy_table.py`.)
- Operator override — **shipped** as `set_policy_table` /
  `reset_policy_table` / `get_policy_table` on the policy-table
  module (the `ip addrlabel` analogue, a dedicated control API
  rather than a scalar sysctl since a whole table is not a
  scalar; copy-on-write reference swap, lock-free under
  free-threading). `lookup` reads the active table live so the
  rule-6 selector picks up an override without a restart.
- Rule 6 wired into `_select_ip6_source`.

## §12c.4 — IPv4 source-selection symmetry

RFC 6724 §6 covers IPv4-mapped IPv6 addresses; PyTCP's
IPv4 path is currently a separate "first host with
gateway" heuristic in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__tx.py`.
This phase aligns the IPv4 selection with the same rule
structure.

This phase is mostly cosmetic for typical deployments
since IPv4 multi-prefix is rare, but it closes the
parity gap.

## Sequencing

§12c.1 first — establishes the framework. §12c.2 next —
the headline §18 privacy consumer. §12c.3 and §12c.4 are
follow-ups that close the long-tail RFC compliance gaps.

Each phase is tests-first per
[`.claude/rules/feature_implementation.md`](../../.claude/rules/feature_implementation.md)
§2.

## Done

All four phases shipped. The kick-off arc is complete; the
adherence record at
[`docs/rfc/ip6/rfc6724__default_address_selection/adherence.md`](../rfc/ip6/rfc6724__default_address_selection/adherence.md)
is the canonical state-of-affairs.

Remaining sub-tasks that *could* extend the arc but are not
blocking:

- **Sysctl-driven policy-table override.** The §10.3 default
  table is hard-coded; a future change could add a sysctl key
  (e.g. `ip.policy_table`) accepting a list of `(prefix,
  precedence, label)` triples to override the default. Not
  needed for default-Linux-host parity since the default
  table matches `/etc/gai.conf`.
- **Destination address selection (RFC 6724 §6 DAS rules
  D1–D8).** This is a DNS-resolution-time concern (picking
  among multiple AAAA / A answers) rather than a stack-TX
  concern; PyTCP does not perform DNS resolution at the
  stack layer, so there is no consumer to wire it into.
  Out of scope unless a future PyTCP socket-API change adds
  resolver behavior.

## Cross-references

- `docs/refactor/nd_linux_parity.md` §0 — points here for
  RFC 6724 work.
- `docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md`
  §18d entry — explicitly defers source-selection
  consumer to this track.
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` §12c
  entry (when audited) — same.
