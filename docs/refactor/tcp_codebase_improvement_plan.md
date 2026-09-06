# TCP Codebase Improvement Plan

Authored 2026-05-05 after a full review of the TCP codebase
following completion of Tier 1, Tier 2, and partial Tier 3 RFC
work (RFC 9406 HyStart++ shipped; RFC 8257 DCTCP and RFC 9331 L4S
deferred by scope decision; RFC 1191 PMTUD + RFC 4821 PLPMTUD
remain pending and depend on the ICMP refactor below).

This document is the canonical plan for the structural and
maintainability improvements the codebase needs. It is
**separate from RFC-conformance work** — every recommendation
here is a refactor / decomposition / hygiene item, not a new
RFC clause.

The codebase as of commit `943698f2` (test framework TFO
state-isolation fix) is in **good correctness shape**: 8382 tests
passing, 0 skipped, lint clean, full SHOULD/MUST parity for the
modern TCP stack feature set. The issues below are organisational,
not functional.

---

## 1. Concerns identified

### Concern #1 — `tcp__session.py` is a 4000+-line god class

`packages/pytcp/pytcp/protocols/tcp/tcp__session.py` carries every aspect of a
TCP session: connection identity, send-side state, receive-side
state, timers, ~7 congestion-control snapshot/restore state
groups, ~30 socket-API knobs, plus the FSM dispatcher itself.
`__init__` is ~700 lines of state declarations. `_transmit_packet`
is ~400 lines. `_process_ack_packet` is ~500 lines.

**Severity:** High. **Effort:** Large (must be incremental).

### Concern #2 — `_transmit_packet` orchestrates 12+ concerns — RESOLVED

> **Resolved by Refactor #5** (see below). `transmit_packet` is now a
> ~100-line coordinator over named per-concern helpers.

A single function handles: RFC 6298 §5.7 idle-reset, RFC 5681
§4.1 RW reduction, RTT-sample tracker init, last-send timestamp
refresh, WSCALE shift, SWS gate, WSCALE / SACK-perm / Timestamps /
TFO / AccECN option emission, ECE/CWR flag composition, retransmit-
ECT-suppression, packet-handler dispatch, FIN bookkeeping,
SND.NXT / SND.MAX update, partial-segment Minshall tracking.
That's twelve concerns in one function.

**Severity:** Medium. **Effort:** Medium.

### Concern #3 — `_process_ack_packet` mixes 16 phases inline — RESOLVED

> **Resolved by Refactor #2** (see below), delivered as part of the
> TcpSession decomposition. `process_ack_packet` is a ~35-line
> coordinator over five named phase methods.

The cum-ACK path runs (in this order): SACK ingest → RACK process
→ unacceptable-segment ack → SND.UNA advance → recover_seq decay
→ bytes_acked compute → retransmit timer manage → CC state update
(CUBIC vs Reno + HyStart override) → snd_ewn recompute → keep-
alive arm → TLP arm → F-RTO step 2/3 spurious-detection → TSecr
RTTM → Karn RTT harvest → recovery_point exit → PRR window update.
Order matters in several spots; the comments document the
dependencies but a refactor into named phases would make them
explicit.

**Severity:** Medium. **Effort:** Medium.

### Concern #4 — Module-level stack state is creeping

`packages/pytcp/pytcp/stack/__init__.py` accumulates: `tcp__fastopen_cookies`,
`tcp__fastopen_negative`, `tcp__fastopen_pending_count`, plus
secrets, cache caps, etc. The TFO test-isolation bug (commit
`943698f2`) was the canary — adding module-level state without
updating the test framework's snapshot+clear pattern silently
leaks state between tests. This will recur as the codebase
grows.

**Severity:** Medium. **Effort:** Small (one-time refactor).

### Concern #5 — ICMP error demux is partial (TCP missing, PMTUD missing) — RESOLVED

> **RESOLVED (reconciled 2026-05-25).** This concern is stale: the
> "Missing" cells and the `# TODO` line references below no longer
> hold. The ICMP→TCP demux shipped (`icmp_into_tcp_fsm_plan.md` =
> "✅ COMPLETED — all four phases") and PMTUD shipped
> (`icmp_demux_pmtud_plan.md` + `plpmtud_unified_engine.md` SHIPPED;
> the `pmtu_cache` is live; ICMPv4 Frag-Needed / ICMPv6 Packet-Too-Big
> feed it). There are **zero `# TODO` markers** left in the cited
> files. The only remaining sliver is the RFC 4821/8899 *active*
> probe-segment emit (`v3_0_6_remaining_work.md` §2.1), a separate
> enhancement on top of the shipped passive PMTUD. The original
> snapshot table is kept below as archaeology.

The ICMP RX handlers
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py:147` and
`packet_handler__icmp6__rx.py:142`) **already** demux Destination-
Unreachable to UDP: they parse the embedded IP+UDP header out of
the ICMP error payload, build a `UdpMetadata`, look up the
matching socket, and call `socket.notify_unreachable()`. So the
infrastructure exists for one protocol/error combination.

What is missing:

| ICMP error path                                   | UDP                                | TCP                            |
|---------------------------------------------------|------------------------------------|--------------------------------|
| ICMPv4 Type 3 (Dest-Unreachable, all codes)       | Wired (`notify_unreachable`)       | **Missing**                    |
| ICMPv4 Type 3 Code 4 (Frag-Needed) — PMTUD        | **Missing** (`# TODO` line 152)    | **Missing**                    |
| ICMPv6 Type 1 (Dest-Unreachable)                  | Wired (`notify_unreachable`)       | **Missing** (TODO lines 185-187) |
| ICMPv6 Type 2 (Packet-Too-Big) — PMTUD            | **Missing**                        | **Missing**                    |
| ICMPv4 Type 11, ICMPv6 Type 3 (Time Exceeded)     | Not wired (log only)               | Not wired                      |

RFC 1122 §4.2.3.9 (TCP MUST react to ICMP) is currently treated
as "satisfied at the fault-tolerance minimum" via R2 abort
fallback. PMTUD (RFC 1191 / RFC 8201 / RFC 4821 / RFC 8899) is
blocked on the missing Frag-Needed / Packet-Too-Big handling for
both UDP and TCP. The embedded-header parsing is duplicated
inline in each Dest-Unreachable handler today; a refactor lifts
it into a shared helper used by both Dest-Unreachable and the
new Packet-Too-Big handlers.

**Severity:** High. **Effort:** Medium-Large.

### Concern #6 — Heavy `setUp` in some integration tests

A few integration test files rebuild the same handshake fixture
per test method. Class-level fixtures or a shared
`_make_established_session(...)` helper would shrink test files
substantially.

**Severity:** Low. **Effort:** Small.

### Concern #7 — `_advertise_*` flag explosion

`_advertise_ts`, `_advertise_wscale`, `_advertise_sack`,
`_advertise_ecn`, `_advertise_accecn`, `_advertise_fastopen`.
Each controls whether the active-open SYN offers the
corresponding option. Works, but a `class HandshakeAdvertise`
dataclass with one place to flip defaults would be cleaner.

**Severity:** Low. **Effort:** Small.

---

## 2. Recommended refactors (ordered for sequencing)

### Refactor #1 — Extract `CcState` dataclass

**Effort:** 3–4 commits. **Risk:** Low. **Closes:** Concern #1 (partial).

Extract a `CcState` dataclass under
`packages/pytcp/pytcp/protocols/tcp/tcp__state__cc.py` carrying:

- `cwnd, ssthresh, snd_ewn` — primary CC variables
- `recovery_point, recover_seq` — RFC 6582 step 4 + RFC 6675 §5.1
- `frto_active, frto_step, frto_pre_*, frto_pre_cubic_*` — RFC 5682
- `fr_pre_cubic_*, fr_pre_cwnd, fr_pre_ssthresh, fr_cubic_snapshot_valid` — RFC 9438 §4.9.2
- `cubic_w_max, cubic_K_ms, cubic_epoch_start_ms, cubic_w_est, cubic_in_ca` — RFC 9438 §4
- `prr_delivered, prr_out, recover_fs` — RFC 6937
- `hystart_state` — RFC 9406 (already a dataclass; reference it here)

Removes ~25 fields from `TcpSession.__init__`. The snapshot+restore
patterns (`_restore_frto_snapshot`, `_fr_cubic_snapshot_valid` clear)
become methods on the dataclass. Lowest risk because each field
moves with no semantic change; tests pass throughout.

**Validation:** existing 415 TCP integration tests + RFC
adherence records' test references all unchanged.

### Refactor #2 — Split `_process_ack_packet` into phase functions — SHIPPED

**Effort:** 2 commits. **Risk:** Low. **Closes:** Concern #3.

> **SHIPPED** as part of the TcpSession decomposition
> (`docs/refactor/tcp_session_decomposition.md`). The processor lives
> at `protocols/tcp/session/tcp__session__ack.py`:
> `process_ack_packet` is a coordinator calling
> `_phase1_cum_ack_side_effects`, `_phase3_harvest_rtt_samples`,
> `_phase4_loss_detection_and_recovery_exit` and
> `_phase5_consume_segment_and_postprocess`, with
> `_phase2_frto_spurious_detect` called from phase 1. The phase
> boundaries differ from the sketch below; the split is equivalent.

Split into named phase functions called in order:

1. `_phase1_ingest_sack_and_rack(packet_rx_md)` — SACK ingest +
   RACK time-based loss detection on dup-ACK path.
2. `_phase2_advance_snd_una_and_state(packet_rx_md, bytes_acked)` —
   SND.UNA advance, recover_seq decay, retransmit timer manage,
   keep-alive arm, TLP arm.
3. `_phase3_update_congestion_control(bytes_acked)` — CUBIC vs
   Reno cwnd + HyStart override + F-RTO step 2/3 spurious-detection
   + recovery exit (cwnd = ssthresh) + PRR window update.
4. `_phase4_harvest_rtt_samples(packet_rx_md)` — TSecr-driven RTTM
   + Karn sample-tracker harvest, with HyStart fold side-effects.

Each phase is one page. Mostly mechanical extraction; the order
constraints documented in the existing inline comments become
function-call ordering at the top level.

### Refactor #3 — `TcpStack` class around module-level state

**Effort:** 2 commits. **Risk:** Low. **Closes:** Concern #4.

Aggregate the module-level stack state into a `TcpStack` class:

```python
class TcpStack:
    fastopen_cookies: dict[Ip4Address | Ip6Address, bytes]
    fastopen_negative: set[Ip4Address | Ip6Address]
    fastopen_pending_count: int
    iss_secret: bytes
    fastopen_secret: bytes
    fastopen_cache_max_size: int
```

Instantiate once at stack import. Tests construct a fresh
instance per test instead of clearing module-level dicts/sets.
Eliminates the test-isolation pattern by construction. Also makes
it possible to run two PyTCP "instances" in one process
(currently impossible).

Migration is mechanical: `stack.tcp__fastopen_cookies[k]` becomes
`stack.tcp_stack.fastopen_cookies[k]` at every call site. Replace
the per-RFC-7413-§4.1.3.1 / §4.2 setUp/tearDown snapshot+clear
in `TcpTestCase` with a single `stack.tcp_stack =
TcpStack()` reset.

### Refactor #4 — Generalise ICMP error demux + per-destination MTU cache

**Effort:** 4–6 commits. **Risk:** Medium. **Closes:** Concern #5
+ unblocks PMTUD work (RFC 1191 / RFC 8201 / RFC 4821 / RFC 8899).

This is **not** an ICMP→TCP refactor. The codebase already has
working ICMP→UDP demux for Destination-Unreachable on both v4
and v6 (see Concern #5 table). What's missing is the TCP path
entirely + the Packet-Too-Big / Frag-Needed path for both UDP
and TCP. The work is to **extend** the existing demux, not
build it from scratch.

Steps:

1. **Lift the embedded-header parser into a shared helper.** The
   parsing logic currently inlined in
   `__phrx_icmp4__destination_unreachable` (lines 163-181) and
   its v6 counterpart moves to
   `packages/pytcp/pytcp/runtime/packet_handler/_icmp_error_demux.py` returning
   `(IpProto.UDP | IpProto.TCP, four_tuple)` or `None`. Reused
   by all four error handlers (v4/v6 × Dest-Unreachable/PTB).

2. **Add the missing protocol/error combinations:**
   - ICMPv4 Type 3 (any code) → TCP demux: 4-tuple lookup in
     `stack.sockets` (or session table), route to matching
     `TcpSession`.
   - ICMPv6 Type 1 → TCP demux (closes the existing TODO at
     `packet_handler__icmp6__rx.py:185-187`).
   - ICMPv4 Type 3 Code 4 (Frag-Needed) → UDP and TCP demux,
     extracts next-hop MTU from ICMP `unused`/`mtu` field.
   - ICMPv6 Type 2 (Packet-Too-Big) → UDP and TCP demux,
     extracts next-hop MTU from ICMP MTU field.

3. **Add receiver callbacks on the matched session/socket:**
   - `UdpSocket.notify_pmtu(next_hop_mtu)` — analogous to
     existing `notify_unreachable()`.
   - `TcpSession.on_unreachable(icmp_type, icmp_code)` — dispatches
     by code: Net/Host Unreachable → mark session for soft error;
     Port Unreachable on a SYN-SENT session → abort.
   - `TcpSession.on_pmtu(next_hop_mtu)` — update per-destination
     MTU cache, recompute MSS, possibly retransmit smaller.

4. **RFC 5927 hardening (TCP only).** Before acting on an
   ICMP-error-for-TCP, validate that the embedded TCP sequence
   number falls within `SND.UNA..SND.NXT` of the matched session.
   Otherwise an attacker can forge ICMP errors for arbitrary
   4-tuples to abort or PMTU-poison sessions. UDP has no
   equivalent state to validate against.

5. **Per-destination MTU cache at the IP/stack layer.** Lives at
   `stack.pmtu_cache: dict[Ip4Address | Ip6Address, int]`, **not**
   under `TcpStack` — UDP needs to consult it too (so applications
   sending UDP datagrams over a low-MTU path get told their
   datagrams are too big). If Refactor #3 lands first, it goes on
   the unified stack object alongside `TcpStack`.

6. **Wire DF=1 on outbound IPv4 packets** carrying TCP **and**
   UDP. Required for RFC 1191 to work at all (without DF, routers
   silently fragment instead of returning Frag-Needed). RFC 8899
   PLPMTUD also assumes DF=1.

7. **MSS recompute on MTU update** for TCP. Couples with the
   existing `tcp__mss.py` helper.

This refactor is the prerequisite for RFC 1191 + RFC 8201 + RFC
4821 + RFC 8899 PMTUD implementation. The audit records for
those RFCs already reference "cross-cut with ICMP refactor" as
the blocker.

### Refactor #5 — Split `_transmit_packet` into option-builder + send pipeline — SHIPPED

**Effort:** 3 commits. **Risk:** Medium. **Closes:** Concern #2.

> **SHIPPED.** Items 4 and 5 (`_advance_send_state`,
> `_compose_ecn_flags`) landed with the decomposition as
> `_phase4_advance_send_state` / `_phase1_compose_ecn_flags`. Items 2
> and 3 were split out of the old `_phase0_pre_send_hygiene` as
> `_apply_idle_reset_if_needed` / `_handle_rtt_sample_tracker`, and
> item 1 landed as `_compute_outbound_options` returning the frozen
> `OutboundOptions` value object, alongside `_compute_outbound_window`
> and `_compute_ip_ecn`. `transmit_packet` went from 202 to ~104
> lines. One ordering constraint is now explicit in the code: the
> option builder MUST run after `_phase1_compose_ecn_flags`, because
> the AccECN counter build reads state the ACE-field composition
> advances.

Decompose into:

1. `_compute_outbound_options(seq, flags, data)` returning a
   dataclass of all option fields (mss, wscale, sackperm,
   sack_blocks, tsval, tsecr, fastopen_cookie, accecn0_counters,
   accecn1_counters).
2. `_apply_idle_reset_if_needed()` — RFC 6298 §5.7 + RFC 5681 §4.1.
3. `_handle_rtt_sample_tracker(seq, data, flag_syn, flag_fin)` —
   RFC 6298 §4 + Karn taint flag.
4. `_advance_send_state(seq, flags, data, len)` — SND.NXT / SND.MAX
   / partial-Minshall / `_last_send_time_ms` update.
5. `_compose_ecn_flags(flag_syn, flag_ack, flag_rst, data)` — RFC
   3168 §6.1.1/§6.1.2 + RFC 9768 ACE encoding + RFC 3168 §6.1.5
   retransmit-ECT-suppression.

`_transmit_packet` becomes a coordinator that calls each helper
in sequence and dispatches to the packet handler. Each helper
is one-page and independently testable.

Higher risk than #2 because the option-emission paths are
intricate (TSopt + SACK + AccECN + TFO + ECN flags interact),
but the existing test surface is dense.

---

## 3. What NOT to change

### Stay-as-is #1 — Pure-helper modules

`tcp__cwnd.py`, `tcp__cubic.py`, `tcp__rto.py`, `tcp__sack.py`,
`tcp__rack.py`, `tcp__loss_recovery.py`, `tcp__hystart.py`,
`tcp__iss.py`, `tcp__seq.py`. Each is testable in isolation; the
session integrates them. Already correctly factored.

### Stay-as-is #2 — FSM split per state per dispatch type

`tcp__fsm__<state>.py` with separate `_packet` / `_syscall` /
`_timer` dispatch functions per file. The recent refactor was
the right move and the dispatch tables in `tcp__fsm.py` make
the wiring explicit.

### Stay-as-is #3 — Adherence-record format

The per-RFC `docs/rfc/tcp/rfcXXXX__name/adherence.md` format
(RFC text + paragraph audit + test coverage table + Overall
Assessment table) works. Reviewers can navigate from clause to
implementation to test. Don't touch.

### Stay-as-is #4 — `unittest`-native tests with `parameterized_class` + `msg=`

The §7.2 self-audit script catches drift; the
`Reference: RFC X §Y` docstring trailer makes every test
traceable. Established convention; works.

### Stay-as-is #5 — 80-char copyright + module docstring + `ver 3.0.x`

Consistent across the codebase, low maintenance.

---

## 4. Net assessment

The codebase is in **good shape for an educational/research
stack with production-grade-correctness aspirations**. The RFC
conformance is genuinely strong (41 audited RFCs, modern Linux/
BSD/Windows feature parity); the issues are organisational
rather than functional.

`tcp__session.py` being 4000 lines is the main thing to chip at
over time, and it can be done incrementally without breaking
tests because the helpers are already factored.

If a week of cleanup time were available, the highest-value
sequence is:

1. **Refactor #1** (CcState extraction)
2. **Refactor #2** (`_process_ack_packet` phase split)
3. **Refactor #4** (ICMP→TCP demux) — unblocks PMTUD

Those three together meaningfully improve maintainability and
unblock the next major RFC work item, without changing one byte
of wire-level behaviour.

---

## 5. Reference points

- Last conformance commit: `943698f2` (test-framework TFO state isolation)
- Last RFC commit before that: `962667ae` (RFC 9406 HyStart++)
- Test counts: 8382 passing, 0 skipped, lint clean
- Tier 3 deferrals: RFC 8257 (DCTCP), RFC 9331 (L4S) — see audit records
- Tier 3 pending: RFC 1191 (PMTUD), RFC 4821 (PLPMTUD) — blocked on Refactor #4
