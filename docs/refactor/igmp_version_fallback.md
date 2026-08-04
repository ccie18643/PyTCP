# IGMP — Older-Version (IGMPv1/v2) Querier Interoperation — Implementation Plan

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Status       | SHIPPED — Phases A-D complete (RFC 3376 §7 host fallback closed) |
| Plan author  | IGMP track close-out (2026-05-26)                                     |
| Target RFC   | RFC 3376 §7 (Interoperation With Older Versions of IGMP), with RFC 2236 §3 / RFC 1112 §6 host behaviours |
| Parent track | `docs/refactor/igmp_host_membership.md` (Phases 0-6 shipped); this is the deferred §7 block lifted to its own doc, the way RFC 6724 was lifted out of the ND track |
| North Star   | Phase 1 (host-stack parity). Closes the last RFC 3376 host-side `MUST`. |

## 0. What this closes (and why it was deferred)

PyTCP runs **IGMPv3** (RFC 3376) as its host protocol. RFC 3376 §7
makes it a `MUST` for an IGMPv3 host to fall back to IGMPv1/v2
behaviour when it shares a link with an **older-version querier** (a
router that speaks only v1/v2): such a router cannot parse a V3
Membership Report, so a host that keeps sending V3 Reports has its
multicast memberships silently ignored by that router.

This was deferred from the main track (Phase 5) as a cohesive block
because it has no consumer until the version state machine exists, and
half-wiring it against throwaway constants would have added unconsumed
knobs. The **wire codec and parsing are already done**, so this track
is purely the state machine + report-form selection on top:

**Already shipped (no changes needed):**
- v1/v2 Query parsing — `IgmpMessageQuery.from_buffer` discriminates
  the version by message length (RFC 3376 §7.1) and exposes
  `IgmpMessageQuery.version` (`IgmpVersion.V1 | V2 | V3`) and
  `max_response_time`.
- The legacy report wire forms — `IgmpMessageV2Report` (`0x16`),
  `IgmpMessageV2Leave` (`0x17`), and `IgmpMessageV1Report` (`0x12`)
  assemble/parse the IGMPv2 Membership Report, IGMPv2 Leave Group, and
  IGMPv1 Membership Report (one class per type).
- The IGMP RX/TX handlers, the query-response scheduler, and the
  state-change report path (all v3 today).

**Missing (this track):** the per-interface Host Compatibility Mode
state machine that decides *which* report form to emit, the v2/v1
report destinations, the v2 Leave Group path, v1/v2 report
suppression, and the `igmp.version` force knob.

## 1. Grounding facts to verify before coding

The plan is a snapshot; re-confirm against the code and RFC text
(`docs/rfc/ip4/rfc3376__igmp_v3/rfc3376.txt` §7 / §8, RFC 2236 §3)
before relying on any detail.

- **§7.1 version discrimination** (already in `IgmpMessageQuery`):
  v1 Query = 8 octets **and** Max Resp Code == 0; v2 Query = 8 octets
  **and** Max Resp Code != 0; v3 Query = ≥12 octets. `query.version`
  already returns this.
- **§7.2.1 host compatibility mode is per-interface**, derived from two
  per-interface "Older Version Querier Present" timers (one v1, one
  v2). Mode = IGMPv1 if the v1 timer is running, else IGMPv2 if the v2
  timer is running, else IGMPv3. **Changing mode cancels all pending
  response/retransmission timers.**
- **§8.4 Older Version Querier Present Timeout** = [Robustness
  Variable] × [Query Interval] + [Query Response Interval]. The host
  has no Query Interval from a v1/v2 Query (no QQIC), so it uses the
  default Query Interval — this is the consumer that justifies an
  `igmp.query_interval` knob. The Query Response Interval for v2 comes
  from the Query's Max Resp Time.
- **Report destinations differ by version:** a v3 Report goes to
  224.0.0.22 carrying *all* groups; a **v2/v1 Report is per-group,
  sent to the group address itself**; a v2 Leave Group goes to
  224.0.0.2 (the all-routers group).
- **v1 has no Leave** — in IGMPv1 mode a leave emits nothing.
- **v1/v2 report suppression** (RFC 2236 §3): in v1/v2 mode, while a
  group's response timer runs, hearing another host's v1/v2 Report for
  that group cancels (suppresses) the host's own pending Report. IGMPv3
  does **not** suppress — today PyTCP counts and ignores received
  Reports (`igmp__membership_report`).

## 2. Phased plan

Each phase is one tests-first commit (or a tests+impl pair); lint +
full suite + §7.2 audit clean before each, per standing discipline.

### Phase A — Host Compatibility Mode state machine

- Add per-interface state to `PacketHandler`: the v1 and v2
  "Older Version Querier Present" deadlines
  (`_igmp__v1_querier_present_until_ms` / `_v2_...`), initialised in
  the base `__init__` (declare at class level; mirror the existing
  `_igmp_query__pending_response_at_ms` pattern).
- In `__phrx_igmp__membership_query` (`packet_handler__igmp__rx.py`):
  on a v1 Query arm the v1 deadline, on a v2 Query arm the v2 deadline,
  to `now_ms + older_version_querier_present_timeout`.
- A `_igmp_host_compatibility_mode() -> IgmpVersion` accessor: honour a
  forced `igmp.version` (1/2/3); else v1 if the v1 deadline is in the
  future, elif v2, else v3.
- On a mode change, cancel the pending query-response timer (§7.2.1).
- Register `igmp.version` (force_igmp_version: 0=auto, 1/2/3) and
  `igmp.query_interval` (125 s) sysctls via the `sysctl_knob` skill.
- Tests: a v2 Query flips the mode to v2; it reverts to v3 after the
  timeout; `igmp.version=2` pins v2; a v1 Query yields v1 mode.

### Phase B — Report-form selection (query response + state change)

- Query response: in `_igmp_query__send_now`, branch on the
  compatibility mode — v3 → the current `_send_igmp_v3_report`; v2 →
  emit one **IGMPv2 Membership Report** (`IgmpMessageV2Report`)
  **per joined group to the group address**; v1 → one **IGMPv1
  Report** (`IgmpMessageV1Report`) per group. Add the TX method(s) on
  `IgmpTxHandler` (e.g. `_send_igmp_group_report(group, type)`), built
  on a shared emit helper (Router Alert + TTL=1; dst = the group).
- State change on join: v3 → CHANGE_TO_EXCLUDE_MODE (today); v2 → v2
  Membership Report to the group; v1 → v1 Report to the group.
- State change on leave: v3 → CHANGE_TO_INCLUDE_MODE (today); v2 →
  **IGMPv2 Leave Group** (`0x17`) **to 224.0.0.2** (RFC 2236 §3); v1 →
  nothing.
- The robustness retransmit (§5.1) wraps the chosen form unchanged.
- Tests: in v2 mode, the query response and the join report use the v2
  per-group form to the group; a leave emits a v2 Leave Group to
  224.0.0.2; v1 mode uses the v1 form and emits nothing on leave.

### Phase C — v1/v2 report suppression

- In v1/v2 compatibility mode only, track the per-group pending
  response so an inbound v1/v2 Report for that group can cancel it. In
  `_phrx_igmp` (the Report/Leave arm), when the mode is v1/v2 and a
  response is pending for the reported group, cancel it (suppression)
  and bump a counter (`igmp__membership_query__suppressed`).
- IGMPv3 mode keeps the current count-and-ignore behaviour (no
  suppression).
- Tests: v2 mode, a response scheduled for a group, another host's v2
  Report for that group arrives → the pending Report is suppressed (no
  TX when the timer would have fired).

### Phase D — adherence records + integration sweep

- Flip RFC 3376 §7 and RFC 2236 §3 in the adherence records from
  *deferred* to *met*, with the test-coverage audit.
- Update `igmp_host_membership.md` Phase 5 "still deferred" note and
  `v3_0_6_remaining_work.md` §2.0 (remove the §7 gap).
- Final integration sweep across the new version-fallback tests.

## 3. New / touched files

- **Touched (pytcp):** `packet_handler__igmp__rx.py` (mode arming +
  suppression + response-form branch), `packet_handler__igmp__tx.py`
  (v2/v1 per-group report + v2 Leave methods), `packet_handler/
  __init__.py` (per-interface mode state + state-change form branch),
  `protocols/igmp/igmp__constants.py` (`igmp.version` /
  `igmp.query_interval` sysctls), `lib/packet_stats.py` (suppression /
  v2-report / v2-leave TX counters).
- **New (tests):** `tests/integration/protocols/igmp/
  test__igmp__version_fallback.py`,
  `test__igmp__v2_report_suppression.py`.
- **Docs:** the RFC 3376 / 2236 adherence records; the two refactor
  ledgers.

## 4. Sequencing / dependencies

A (mode machine) is the foundation; B (report-form selection) depends
on A; C (suppression) depends on A + the per-group response state; D
(records) lands in lockstep and a final sweep. The codec and parsing
need no changes.

## 5. Scope notes

- **Per-interface** compatibility mode (RFC 3376 §7.2.1), not
  per-group — simplest faithful model; a started stack has a Timer so
  the mode timers fire (unlike the stateless `NetworkTestCase`; use
  `IcmpTestCase` + FakeTimer for the timing tests).
- The IGMPv3 **router/querier** role and **source-specific filtering**
  (§9, `IP_ADD_SOURCE_MEMBERSHIP`) are outside *this* track — SSM
  shipped separately (`igmp_source_specific_multicast.md`), and the
  router/querier role shipped in the Phase-2 multicast router
  (`router_forwarding_plane.md`).

## 6. Cross-references

- `docs/refactor/igmp_host_membership.md` — the parent track (Phases
  0-6 shipped); §7 fallback was its one deferred item.
- `docs/rfc/ip4/rfc3376__igmp_v3/adherence.md` §7 — the deferred-clause
  record this track flips to met.
- `docs/rfc/ip4/rfc2236__igmp_v2/adherence.md` §3 — v2 host behaviours.
- `.claude/skills/sysctl_knob` — for `igmp.version` / `igmp.query_interval`.
- `.claude/skills/rfc_adherence_audit` — for the §7 record refresh.
