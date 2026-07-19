# MLDv1 Compatibility Fallback (RFC 3810 §8) — implementation plan

| Field | Value |
|-------|-------|
| Status | **SHIPPED** — Phase 1 (`e3bd1a2f`, net_proto MLDv1 wire codec) + Phase 2 (the RFC 3810 §8 compat-mode state machine). Adherence: `docs/rfc/icmp6/rfc2710__mld_v1/adherence.md`. MLDv1 Done-on-leave SHIPPED (`test__icmp6__mld2_leave.py`; a leave in v1 compat mode emits an MLDv1 Done to ff02::2). Deferred-with-rationale: Report suppression (optimization), the `mld.version` force knob (Linux extension, needs the sysctl_knob workflow). |
| Target RFC | RFC 3810 §8 (Interoperation With MLDv1), with RFC 2710 host behaviours |
| Mirror of | `docs/refactor/igmp_version_fallback.md` (the shipped IGMP RFC 3376 §7 fallback) — the IGMP↔MLD analogue |
| North Star | Phase 1 (host-stack parity). Closes the MLDv2-host MLDv1-interop `MUST`. |

## 0. What this closes

PyTCP runs **MLDv2** (RFC 3810) as its IPv6 multicast-listener protocol.
RFC 3810 §8 makes it a `MUST` for an MLDv2 host to fall back to MLDv1
(RFC 2710) behaviour when it shares a link with an **MLDv1-only
querier** (a router that can't parse MLDv2 Reports). This mirrors the
shipped IGMP RFC 3376 §7 fallback exactly; MLD is simpler — a 2-mode
(v1/v2) machine, vs IGMP's 3-mode (v1/v2/v3).

## 1. Phase 1 — net_proto MLDv1 wire codec — SHIPPED (`e3bd1a2f`)

The MLDv1 wire forms (which, unlike IGMP's legacy reports, did NOT
exist):
- `Icmp6Type.MULTICAST_LISTENER_REPORT = 131`, `MULTICAST_LISTENER_DONE = 132`.
- `net_proto/.../icmp6/message/mld1/` — `Icmp6Mld1MessageReport` (131,
  parse+assemble), `Icmp6Mld1MessageDone` (132, parse+assemble),
  `Icmp6Mld1MessageQuery` (130, 24-octet, RX-only). Shared fixed
  24-octet RFC 2710 §3 form (`! BBH HH 16s`).
- `Icmp6Parser._message_class`: type 130 length-discriminates MLDv1
  (24) vs MLDv2 (≥28) per RFC 3810 §8.1; 131/132 wired.
- 14 unit tests.

## 2. Phase 2 — the compat-mode state machine (SHIPPED)

The IGMP §7 mirror, on top of the codec. **Must land as one cohesive
commit** (state + RX + TX report-form selection + Done) — a
flip-the-mode-but-still-send-v2 partial is the "unconsumed knob"
anti-pattern the IGMP plan called out.

### 2.1 Version representation
Add `MldVersion(IntEnum) { V1 = 1, V2 = 2 }` (per `enums.md`).
`IgmpVersion` lives at
`packages/net_proto/net_proto/protocols/igmp/message/igmp__message.py:62`;
place `MldVersion` analogously (e.g. the MLDv2 query/report module or a
small icmp6 mld lib). The MLD force-knob (`mld.version`, the
`igmp.version` analogue) is OPTIONAL/deferred — it needs the
`sysctl_knob` skill workflow and is a Linux extension, not an RFC MUST.
The timer-driven mode below is the §8 MUST.

### 2.2 Per-interface state + mode function (`runtime/packet_handler/__init__.py`)
Mirror `_igmp__v1_querier_present_until_ms` (decl ~`:213`, init ~`:558`)
and `_igmp_host_compatibility_mode` (`:2164`):
- Declare `_mld__v1_querier_present_until_ms: int | None`; init `None`.
- `_mld_host_compatibility_mode() -> MldVersion`: `now_ms <
  _mld__v1_querier_present_until_ms` → `V1`, else `V2`. (Reads
  `stack.timer.now_ms`, like the IGMP fn.)
- **no-GIL:** the new scalar is written by the RX thread and read by
  the TX/timer paths — fold its read/write under the existing
  per-interface `_lock__multicast` (the standing invariant; same as the
  IGMP querier-present timers).

### 2.3 RX — MLDv1 Query handling (`packet_handler__icmp6__rx.py`)
The type-130 dispatch (`:188 __phrx_icmp6__mld2_query`) must branch on
the parsed message class:
- `isinstance(packet_rx.icmp6.message, Icmp6Mld1MessageQuery)` → new
  `__phrx_icmp6__mld1_query`: arm `_mld__v1_querier_present_until_ms`
  (deadline = now + [Robustness × Query Interval] + Max-Response-Delay;
  RFC 3810 §9.2/§8.2.1 "Older Version Querier Present Timeout"), then
  respond — General Query → schedule a per-group response; Multicast-
  Address-Specific Query → respond for that group. Both respond in the
  v1 Report form (see §2.4). Mirror `_igmp_update_compatibility_mode`
  (`packet_handler__igmp__rx.py:342`) including the
  cancel-pending-on-mode-change.
- else (MLDv2 query) → existing `__phrx_icmp6__mld2_query` (an MLDv2
  query does not lower the mode).

### 2.4 TX — report-form selection (`packet_handler__icmp6__tx.py`)
The single current-state emitter is `_send_icmp6_multicast_listener_report`
(`:196`), which always builds the MLDv2 aggregate Report (HBH+RA, dst
`ff02::16`, hop 1, pre-computed pshdr_sum). Add:
- `_send_icmp6_mld1_report(group)` — one `Icmp6Mld1MessageReport` per
  group, wrapped in the SAME HBH+Router-Alert(value=MLD)+PadN machinery,
  dst = **the group address** (RFC 2710 §3: an MLDv1 Report is sent to
  the multicast address being reported), hop 1. Factor the HBH/RA/
  pshdr_sum wrapping (`:226-282`) into a shared helper to avoid
  duplicating the checksum logic (this is the fiddliest part — the
  pshdr_sum is hand-computed because `Ip6Assembler` doesn't auto-inject
  it under an HBH header).
- `_send_icmp6_mld1_done(group)` — `Icmp6Mld1MessageDone`, dst =
  `ff02::2` (all-routers), hop 1.
- **Report-form selection:** at `_send_icmp6_multicast_listener_report`
  and at every group-membership-change emit site, branch on
  `_mld_host_compatibility_mode()`: `V1` → loop `_send_icmp6_mld1_report`
  per joined group (skip `ff02::1`); `V2` → the existing aggregate.
- **Leave → Done:** the leave path (`_remove_ip6_multicast`,
  `__init__.py:756/1405`; `stack/address.py:185`) must, in V1 mode,
  emit `_send_icmp6_mld1_done(group)`. (In V2 mode the existing
  state-change machinery handles leave.) Confirm which leave sites are
  app-driven vs sweep-driven and gate accordingly.

### 2.5 Mode revert
No explicit timer needed — `_mld_host_compatibility_mode()` reads the
deadline live and returns `V2` once it passes (same as IGMP).

## 3. Tests (tests-first)
- **Unit:** `_mld_host_compatibility_mode()` returns V1 while the timer
  runs, V2 after (patch `stack.timer.now_ms`).
- **Integration (`NdTestCase`/`IcmpTestCase`, the multicast harness):**
  1. Drive an MLDv1 Query (24-octet type 130) → assert the interface
     enters V1 mode and a **MLDv1 Report (type 131)** is emitted for a
     joined group (not an MLDv2 Report 143).
  2. In V1 mode, leave a group → assert an **MLDv1 Done (type 132)** to
     `ff02::2`.
  3. Advance the virtual clock past the Older-Version-Querier-Present
     timeout → assert the next report reverts to the MLDv2 aggregate
     (143).
  4. An MLDv2 Query does not lower the mode (regression guard).
- §7.2 docstring audit on every new test file.

## 4. Adherence record
New `docs/rfc/icmp6/rfc2710__mld_v1/adherence.md` (or fold a §8 section
into `rfc3810__mld2`) — the MLDv1 host behaviours + the §8 compat-mode
machine, citing the Phase-1 codec tests + the Phase-2 integration
tests. Mirror the IGMP `rfc3376__igmp_v3` §7 audit.

## 5. Effort / risk
~1–1.5 days for Phase 2. Risk concentrated in §2.4 (the per-group v1
Report TX + the hand-computed HBH/RA pseudo-header checksum, and
finding every report-emit call site). The state machine + RX are a
clean IGMP mirror. Land cohesively, tests-first.

## 6. Resume prompt (paste verbatim in a fresh session)

```
Read docs/refactor/mld_version_fallback.md — Phase 1 (net_proto MLDv1
wire codec) shipped as e3bd1a2f; implement Phase 2 (the RFC 3810 §8
compat-mode state machine), tests-first, mirroring the shipped IGMP
RFC 3376 §7 fallback (docs/refactor/igmp_version_fallback.md + the
_igmp_host_compatibility_mode / _igmp_update_compatibility_mode code).
Land Phase 2 as ONE cohesive commit (per-interface MLDv1
querier-present timer + _mld_host_compatibility_mode + RX MLDv1-Query
handling + TX per-group MLDv1 Report/Done emission + report-form
selection at the report/leave call sites). Fold the new scalar under
_lock__multicast (no-GIL invariant). Then the RFC 2710/§8 adherence
record. Standing discipline: make lint + full make test + §7.2 audit
clean per commit; commit trailer "Co-Authored-By: Claude Opus 4.8
(1M context) <noreply@anthropic.com>"; push only when asked.
```
