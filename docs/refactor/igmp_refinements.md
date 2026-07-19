# IGMP — Refinements & Engineering-Debt Ledger

| Field        | Value                                                              |
|--------------|--------------------------------------------------------------------|
| Status       | SHIPPED — R1-R7 all landed; only §C feature follow-ons remain       |
| Author       | IGMP design review (2026-05-26)                                    |
| Parent       | `docs/refactor/igmp_host_membership.md` (Phases 0-6 shipped)       |
| Sibling      | `docs/refactor/igmp_version_fallback.md` (the RFC 3376 §7 feature track) |
| Scope        | Corner-cuts, parity nits, and accepted-as-is decisions surfaced in the post-implementation review. NOT new features — those are the §7 fallback track. |

This ledger records the engineering decisions made while shipping the
IGMP host implementation (commits `2477b18e`..`b9dacf5c`) that a review
flagged: which were **accepted as-is** (with rationale, no action) and
which are **refinements worth doing**. Feature-level gaps (the §7
version-fallback block) live in `igmp_version_fallback.md` and are only
cross-referenced here.

---

## A. Accepted decisions — no action

These were reviewed and deliberately kept; recorded so they are not
re-litigated.

1. **Structural sibling = ICMPv4, not MLDv2.** IGMP is a top-level IP
   protocol (number 2) with a message-only checksum, exactly like
   ICMPv4; MLDv2 rides ICMPv6 and its checksum includes the IPv6
   pseudo-header. Copying MLDv2's framing would have produced a wrong
   checksum. The message-body *semantics* were borrowed from MLDv2
   (group records, EXCLUDE/INCLUDE), the *skeleton* from ICMPv4. Keep.

2. **No dedicated listener `Subsystem`.** Query-response and
   state-change reports drive off the shared event-driven `Timer` +
   the RX/TX handlers, exactly as the shipped MLDv2 listener does. A
   `Subsystem` (per-iteration loop) would be an idle thread polling
   nothing. The only thing that wants a periodic loop is the
   router/querier role (Phase-2). Keep. Confirmed against Linux: the
   kernel host path (`net/ipv4/igmp.c`, `net/ipv6/mcast.c`) drives off
   per-group `timer_list` entries fired from the timer softirq +
   reactive RX + the socket API — there is no listener thread; the
   periodic machinery is reserved for the querier/router role.

3. **One polymorphic `IgmpMessageQuery` with a `version` field** (vs the
   per-type split used for the legacy v1/v2/v3 reports). The Query is a
   single wire type byte (0x11) discriminated by *message length*
   (RFC 3376 §7.1), not by distinct type bytes — so a version field is
   correct, and it is *not* inconsistent with the legacy-report split
   (which keyed off genuinely distinct type bytes). Keep.

4. **`stack.membership` as a dedicated control API** (vs folding
   join/leave into `AddressApi`). Group membership is a distinct plane
   (Linux `ip maddr` vs `ip addr`); the dedicated `MembershipApi`
   mirrors the established `address`/`neighbor`/`route` shape. Keep.

5. **One class per legacy type** (`IgmpMessageV2Report` /
   `IgmpMessageV2Leave` / `IgmpMessageV1Report`). Already done in
   `b9dacf5c` — matches the ICMPv4 echo-request/echo-reply convention.

---

## B. Refinements worth doing

Ordered by priority.

### R1 — State-change retransmit: recompute at fire, supersede on a new change (CORRECTNESS) — SHIPPED

**Shipped** (with R2). `_send_igmp_v3_state_change` now records a
per-group pending-change entry and arms a single recompute-at-fire
retransmit ticket (`_arm_state_change_retransmit` /
`_fire_state_change_retransmit`); a new change overwrites the group's
pending record and re-seeds its count, so a join cancelled by a quick
leave retransmits the leave, never the stale join. Test:
`test__igmp__robustness_retransmit.py::test__igmp__retransmit__leave_supersedes_pending_join`.

**Today (before fix):** `_schedule_state_change_retransmits` captures the join/leave
record in a closure and re-emits it RV-1 times; it does **not** cancel
outstanding retransmits when a new state-change for the same group
occurs, nor recompute their contents.

**Problem:** a rapid **join→leave** of the same group emits
join-report, leave-report, then a stale join-*retransmit*, which can
make a router transiently re-add the membership until its next query /
timeout. RFC 3376 §5.1: "If more changes to the same interface state
entry occur before all the retransmissions ... have been completed,
each such additional change triggers the immediate transmission of a
new State-Change Report" — i.e. the train must reflect the latest
state.

**Fix — recompute-at-fire (Linux model), NOT cancel-and-replace.**
Linux never replays a captured record. Each group carries a
pending-change record plus a retransmit countdown (`crcount`, seeded to
the robustness variable); the interface-change timer
(`igmp_ifc_event` / `igmp_ifc_timer`, `mr_ifc_count`) fires, re-serializes
the *current* pending-change records, and decrements their counters. A
**new** change to a group overwrites that group's pending record and
re-seeds its counter — so a join superseded by a leave never
retransmits the join.

Mirror that here: keep a per-group pending-change map on the handler,
`_igmp_pending_change: dict[Ip4Address, _Pending]`, where `_Pending`
holds the record type (`CHANGE_TO_EXCLUDE_MODE` / `CHANGE_TO_INCLUDE_MODE`)
and a remaining-repeats count seeded to `igmp.robustness`. `join` /
`leave` **overwrites** the group's entry (this is the supersede) and
emits the immediate report; a single recurring retransmit ticket
recomputes the report from the map at each fire, decrements every
entry, and drops entries that reach zero. No captured record, no
per-handle cancellation — superseding is just a dict overwrite, and
the emitted record always reflects the latest change.

Test via `IcmpTestCase` (patch `random.randint` for a deterministic
delay): join then leave the same group before the retransmit fires,
advance the clock → the retransmit that fires must reflect the *leave*
(`CHANGE_TO_INCLUDE_MODE`), never the stale join. **This is the latent
correctness bug; do it first.**

Reference: RFC 3376 §5.1 (a new change supersedes the in-flight
retransmit train); Linux `net/ipv4/igmp.c` (`igmp_ifc_event`,
`mr_ifc_count` / `crcount`).

### R2 — Drop the `stack.timer` retransmit guard; give `NetworkTestCase` a Timer (TEST-INFRA) — SHIPPED

**Shipped** (with R1). `NetworkTestCase` now installs an inert
`FakeTimer` as `stack.timer` via `mock__init` (snapshot/restored in
setUp/tearDown), so the IGMP TX path calls `stack.timer.call_later`
unconditionally — matching the always-unguarded RX query-response
path — and the `getattr(stack, "timer", None)` guard is gone.

**Today (before fix):** `_schedule_state_change_retransmits` guards on
`getattr(stack, "timer", None)` because `NetworkTestCase` brings up no
Timer subsystem, so a join/leave there would otherwise crash.

**Problem:** a production-code branch whose only real trigger is the
test harness, and inconsistent with the query-response path
(`packet_handler__igmp__rx.py`), which calls `stack.timer.call_later`
**unconditionally** — it only survives because its tests use
`IcmpTestCase`. So a query driven from a `NetworkTestCase` test would
crash today (a latent footgun the guard does not cover).

**Fix sketch:** pass `mock__timer=Timer()` from `NetworkTestCase`
(unstarted = no thread; `call_later` just registers heap entries that
never fire — inert for the stateless tests), then delete the guard so
the TX path matches the unguarded RX path. Run the full suite — the
change touches the shared base, but an inert Timer is invisible to
existing tests. Pairs naturally with R1 (which needs a Timer in the
NetworkTestCase join tests anyway).

### R3 — Per-socket membership refcounting (SEMANTICS) — SHIPPED

**Shipped (Phases A/B/C).** Membership is reference-counted per socket
(unified interface refcount: operator flag + socket count, edge-gated
join/leave Reports); `close()` releases a socket's memberships
(`ip_mc_drop_socket`); double-join → `EADDRINUSE`, drop-non-member →
`EADDRNOTAVAIL`. Full record in
`docs/refactor/igmp_r3_socket_refcounting.md`.


**Today:** membership is presence-based per interface; the first
`IP_DROP_MEMBERSHIP` removes the group even if another socket still
holds it, and a socket `close()` leaks its memberships (no auto-leave).

**Fix sketch:** a per-(interface, group) join refcount keyed by the
joining socket; the actual leave + Leave Report fires only when the
count hits zero, and `close()` releases the socket's memberships.
Mirrors Linux `ip_mc_socklist` / `ip_mc_drop_socket`. Couples with R7
(shared leave path).

**Full sub-plan (tests-first):**
`docs/refactor/igmp_r3_socket_refcounting.md` — the design decision
(unified interface refcount, operator API contract preserved), touch
list, and the phased A/B/C test inventory.

### R4 — `max_memberships` overflow should raise ENOBUFS, not EINVAL (PARITY NIT) — SHIPPED

**Shipped.** `MembershipApi.join` now raises a dedicated
`MembershipLimitError(ValueError)` over the cap; the socket facade
catches it before the generic `ValueError` arm and maps it to
`OSError(ENOBUFS)` (Linux `IP_ADD_MEMBERSHIP` over
`igmp_max_memberships`), leaving other membership errors on `EINVAL`.
The `ValueError` subclassing keeps the operator-API cap tests green.
Test: `test__igmp__socket_membership_refcount.py::...join_over_limit_raises_enobufs`.

### R5 — RX hardening: enforce TTL=1 on inbound IGMP (HARDENING) — SHIPPED

**Shipped.** `_phrx_igmp` now drops inbound IGMP with IP TTL != 1
(bumping a dedicated `igmp__ttl_invalid__drop` counter) before
parsing, matching the Linux martian-IGMP guard (RFC 3376 §4: IGMP is
sent with TTL = 1). Unconditional (no sysctl) — Linux does not gate
this. Test: `test__igmp__query_response.py::...ttl_not_one_dropped`.

**Router Alert intentionally NOT required on receipt.** RFC 3376 §4
has senders set Router Alert, but IGMPv2 senders predate it and Linux
does not drop received IGMP for a missing RA — requiring it would
break interop. Send-side already sets RA (per the TX handler).

### R6 — `ip_mreqn` (12-byte) socket-option form (PARITY) — SHIPPED

**Shipped.** `_ipproto_ip_membership` now accepts the 12-byte
`ip_mreqn` (imr_multiaddr + imr_address + host-order C-int
imr_ifindex): a non-zero imr_ifindex selects the interface directly and
takes precedence over imr_address, while imr_ifindex 0 falls back to
the 8-byte address selection. Tests:
`test__igmp__socket_membership_opts.py::...ip_mreqn_explicit_ifindex_takes_precedence`
and `...ip_mreqn_zero_ifindex_falls_back_to_address`.

### R7 — Graceful Leave on shutdown / link-down (HOST-CONFORMANCE SHOULD) — SHIPPED (IPv4)

**Shipped (IPv4 / IGMP).** `stack.stop()` now calls each interface's
`_send_igmp_leave_all` before any subsystem teardown (while the TX path
is live): a single combined IGMPv3 Report transitions every joined
group (except permanent 224.0.0.1) to `CHANGE_TO_INCLUDE_MODE`, no
retransmits (Linux `ip_mc_down`). Tests:
`test__igmp__shutdown_leave.py` + a `stack.stop()` ordering test in
`test__stack__init.py`.

**MLD (IPv6) — SHIPPED symmetrically.** MLDv2 now has the analogous
leave path: `remove_ip6_multicast` calls `_send_icmp6_mld_leave`
(a `CHANGE_TO_INCLUDE` State Change Report, or an MLDv1 Done in v1
compat mode), and `send_mld_leave_all` is the graceful-leave-on-
shutdown hook wired into `stack.stop()` right next to
`send_igmp_leave_all`. Tests: `test__icmp6__mld2_leave.py`.

**Original (pre-fix):** `stack.stop()` silently abandoned every joined
group — no `CHANGE_TO_INCLUDE_MODE` / Leave was emitted, so a router
held each group until its membership query timed out.

**Linux:** `ip_mc_down()` (on `NETDEV_DOWN`) and `ip_mc_leave_group()`
(on `IP_DROP_MEMBERSHIP` / socket close) emit the leave for reported
groups; `igmp_group_dropped()` does the per-group work.

**Fix sketch:** a **stop-hook, NOT a `Subsystem`/loop**, wired into the
`stack.stop()` teardown ordering — for each joined group except the
all-systems group 224.0.0.1, emit the state-change leave *before* the
Timer / TX-ring teardown. The same hook fires on interface-down once
Phase-2 multi-interface lands. MLD has the identical gap (RFC 3810 /
RFC 2710 Done) — fix both symmetrically. Low risk; a host-conformance
SHOULD, and it shares the leave path with R3 (per-socket refcount), so
the two pair naturally.

Reference: RFC 2236 §3 / RFC 3376 §5.1 (a host announces leaving);
Linux `net/ipv4/igmp.c` (`ip_mc_down`, `igmp_group_dropped`).

---

## C. Out of scope here (tracked elsewhere)

These are feature-level gaps, not refinements — see
`igmp_version_fallback.md`:

- RFC 3376 §7 v1/v2 querier-version fallback (v2-form reports, Leave to
  224.0.0.2, report suppression, `igmp.version` knob).
- Per-group / source-specific Query response (the §5.2 per-group
  timers) and the IGMPv1 default Max Resp Time.
- Source-specific filtering (§9, `IP_ADD_SOURCE_MEMBERSHIP`).
- The IGMPv3 router/querier role (Phase-2).
- ~~**MLDv2 leave reporting (IPv6).**~~ **SHIPPED** — the IPv6 MLDv2
  listener now emits a per-group leave (`CHANGE_TO_INCLUDE` State
  Change Report, or an MLDv1 Done in v1 compat mode) on
  `remove_ip6_multicast`, and `send_mld_leave_all` does the
  graceful-leave-on-shutdown, wired into `stack.stop()` alongside the
  IGMP R7 hook. Tests: `test__icmp6__mld2_leave.py`. Only the IGMPv3
  router/querier role above remains Phase-2.

---

## D. Suggested sequencing

R1 + R2 together (R2 unblocks R1's NetworkTestCase tests and removes
the guard in the same breath) — this is the highest-value, ~half-day
unit and closes the only latent correctness issue. R1 uses the
**recompute-at-fire** (per-group pending-change map) model, not
cancel-and-replace. R3 (per-socket refcount) + R7 (graceful leave)
pair next since both touch the leave path — do them together if
multi-socket multicast matters; otherwise R7 can land on its own as a
host-conformance fix. R4 / R5 / R6 are cleanup-on-touch parity nits.
The §7 fallback (sibling doc) is the larger feature follow-on and would
naturally absorb R2's NetworkTestCase-Timer change as well.

## E. Cross-references

- `docs/refactor/igmp_host_membership.md` — the shipped Phases 0-6.
- `docs/refactor/igmp_version_fallback.md` — the §7 feature track.
- `docs/rfc/ip4/rfc3376__igmp_v3/adherence.md` — per-clause audit.
- `.claude/skills/sysctl_knob` (for R5's optional gate),
  `.claude/skills/rfc_adherence_audit` (refresh on R1/R3 landing).
