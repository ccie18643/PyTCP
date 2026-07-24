# RFC 6582 — The NewReno Modification to TCP's Fast Recovery Algorithm

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 6582                                                   |
| Title       | The NewReno Modification to TCP's Fast Recovery Algorithm |
| Category    | Standards Track                                        |
| Date        | April 2012                                             |
| Obsoletes   | RFC 3782                                               |
| Source text | [`rfc6582.txt`](rfc6582.txt)                           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6582. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§3.1 Protocol Overview, §6 implementation-issues
narrative, §7 Conclusions, Acknowledgements, References)
are omitted.

A clarifying note about this RFC's normative weight:
the §3.2 preamble explicitly states "this specification
avoids the use of the key words defined in RFC 2119,
since it mainly provides sender-side implementation
guidance for performance improvement, and does not
affect interoperability." The lowercase "should" /
"must" wording in §3.2 is therefore advisory rather
than RFC-2119-normative. Implementations may legitimately
deviate when a different mechanism (e.g. RFC 6937 PRR or
RFC 6675 SACK NextSeg) achieves the same or better
loss-recovery behaviour. PyTCP takes this latitude.

---

## §2. Terminology and Definitions

> "This document defines an additional sender-side state
> variable called 'recover': When in fast recovery, this
> variable records the send sequence number that must be
> acknowledged before the fast recovery procedure is
> declared to be over."

**Adherence:** met, with a renamed variable. PyTCP
exposes the same concept as `_recovery_point: Seq32`
on `TcpSession`
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:277`); a value of
`0` means "not in recovery", any non-zero value records
the SND.MAX-at-fast-retransmit-entry seq that must be
crossed by SND.UNA before recovery exits. Functionally
identical to RFC 6582 §2 `recover`; the rename to
`_recovery_point` matches the RFC 6675 §5 wording for
the same concept (RFC 6675 was the more recent
authoritative reference when this code was written).

---

## §3.2. Specification

### Step 1: Initialize `recover`

> "When the TCP protocol control block is initialized,
> recover is set to the initial send sequence number."

**Adherence:** deviates non-normatively. PyTCP
initialises `_recovery_point = 0` rather than to the
ISS. The functional difference is whether the
"recovery_point != 0" sentinel can collide with a
genuinely-equals-ISS recovery point. With the ISS
itself randomized via RFC 6528 (32-bit hash), the
probability of `_recovery_point` ever being set to
exactly 0 by a legitimate fast-retransmit entry is
1 in 2^32 — negligible in practice. A `_recovery_point
= 0` sentinel is therefore safe as a "not in recovery"
marker.

The deviation is non-normative because §3.2's preamble
disclaims RFC 2119 keyword strength, and PyTCP's
sentinel-based encoding preserves the same observable
behaviour: `_recovery_point != 0` iff the session is in
fast recovery.

### Step 2: Three duplicate ACKs — gate on `recover`

> "When the third duplicate ACK is received, the TCP
> sender first checks the value of recover to see if the
> Cumulative Acknowledgment field covers more than
> recover. If so, the value of recover is incremented to
> the value of the highest sequence number transmitted
> by the TCP so far. The TCP then enters fast retransmit
> (step 2 of Section 3.2 of RFC 5681). If not, the TCP
> does not enter fast retransmit and does not reset
> ssthresh."

**Adherence:** met. The
`_retransmit_packet_request` handler at
`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__retransmit.py:431`
implements:

```python
if self._cc.recovery_point != 0:
    return
```

so any subsequent dup-ACKs while still in recovery do
not re-enter fast retransmit. This corresponds exactly
to "ack_number - 1 > recover" being false during
recovery (cum-ACK has not yet crossed the prior
recovery point).

The post-RTO branch clears `_cc.recovery_point = 0`
(`session/tcp__session__retransmit.py:341`) AND records
SND.MAX-at-RTO into `_cc.recover_seq` (`:361`), per
§3.2 step 4 below. The fast-retransmit entry gate
refuses re-entry while `lt32(SND.UNA, _cc.recover_seq)`
(`:444`), so post-RTO dup-ACKs covering seq-space the
RTO already retransmitted do NOT re-trigger a fresh
fast retransmit — the false-fast-retransmit scenario
§4 warns about is prevented by the step-4 marker rather
than by either §4 heuristic. The marker decays on
cum-ACK once SND.UNA reaches it
(`session/tcp__session__ack.py:244-245`).

### Step 3 (Full ACK): Cwnd deflation on recovery exit

> "If this ACK acknowledges all of the data up to and
> including recover... Set cwnd to either (1) min
> (ssthresh, max(FlightSize, SMSS) + SMSS) or (2)
> ssthresh... Exit the fast recovery procedure."

**Adherence:** met (option 2). The recovery exit
branch at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3382-3390`:

```python
if self._recovery_point != 0 and le32(self._recovery_point, self._snd_una):
    self._cwnd = self._ssthresh
    self._snd_ewn = min(self._cwnd, self._snd_wnd)
    self._recovery_point = 0
```

This is the §3.2 step 3 option (2) `cwnd = ssthresh`
form. The RFC notes "If the second option is selected,
the implementation is encouraged to take measures to
avoid a possible burst of data". PyTCP takes that
measure indirectly via the RFC 6937 PRR per-ACK send
budget that operates DURING recovery — by the time
recovery exits, the in-flight bytes are already
ssthresh-shaped, so the post-deflation send is not
bursty.

### Step 3 (Partial ACK): Deflate + add-back + retransmit

> "If this ACK does *not* acknowledge all of the data up
> to and including recover, then this is a partial ACK.
> In this case, retransmit the first unacknowledged
> segment. Deflate the congestion window by the amount
> of new data acknowledged by the Cumulative
> Acknowledgment field. If the partial ACK acknowledges
> at least one SMSS of new data, then add back SMSS
> bytes to the congestion window... Do not exit the fast
> recovery procedure."

**Adherence:** superseded by RFC 6937 PRR. PyTCP does
not run the §3.2 step 3 partial-ACK formula. Instead,
during recovery (`_recovery_point != 0` AND
`SND.UNA < recovery_point`), the cwnd is computed by
RFC 6937 Proportional Rate Reduction at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3145-3169`:

- PRR proper (when `pipe > ssthresh`):
  `target = ceil(prr_delivered * ssthresh / RecoverFS)`,
  `sndcnt = target - prr_out`, `cwnd = pipe + sndcnt`.
- PRR-CRB / PRR-SSRB (when `pipe <= ssthresh`):
  conservative send budget bounded by
  `ssthresh - pipe` and the unsent `prr_delivered -
  prr_out`.

PRR is a strict superset of the §3.2 step 3b "deflate
by bytes_acked, add back SMSS if ≥ 1 SMSS new data"
formula — it produces smoother, more accurately-paced
sends during recovery while still ensuring approximately
ssthresh bytes are outstanding when recovery ends. RFC
6582 explicitly permits this kind of substitution: §3.2's
preamble disclaims RFC 2119 keyword strength.

A standalone `partial_cum_ack_deflate` helper exists at
`packages/pytcp/pytcp/protocols/tcp/tcp__newreno.py:59-92` implementing
the literal §3.2 step 3b formula, but it is NOT called
from production code (verified by grep). It is preserved
as a reference implementation for tests and as a
fallback that a future SACK-disabled branch could
invoke if needed.

The "first unacknowledged segment retransmit" requirement
is met via the RFC 6675 NextSeg machinery: when the
session is in recovery and a partial cum-ACK advances
SND.UNA, the next `_transmit_data` tick computes
`_advance_snd_nxt_past_sacked()` and emits the first
gap segment. The mechanism is RFC 6675 §3 / §4
(SACK-aware) rather than RFC 6582 §3.2 step 3b
(SACK-blind), but the wire-level retransmit happens.

The "reset retransmit timer on first partial ACK"
sub-requirement is met by the broader RFC 6298 §5.3
restart-on-cum-ACK-advancing-SND.UNA rule (every
cum-ACK that advances SND.UNA restarts the retransmit
timer), which is invoked on every cum-ACK including
partial ones.

### Step 4: After RTO, record `recover` and exit FR

> "After a retransmit timeout, record the highest
> sequence number transmitted in the variable recover,
> and exit the fast recovery procedure if applicable."

**Adherence:** met. PyTCP records SND.MAX-at-RTO into
`self._recover_seq` in `_retransmit_packet_timeout`
right after the `_recovery_point = 0` reset. The fast-
retransmit entry gate in `_retransmit_packet_request`
checks `lt32(self._snd_una, self._recover_seq)` and
refuses to enter recovery while SND.UNA has not
reached the marker, satisfying §3.2 step 4's intent of
preventing the post-RTO retransmit storm's dup-ACK
echoes from re-triggering fast retransmit. The marker
clears via `ge32(self._snd_una, self._recover_seq)` on
cum-ACK once SND.UNA reaches the recorded value, so a
subsequent legitimate loss event can enter FR
normally. The 0 sentinel disables the gate entirely
on a fresh connection so the first loss event is not
artificially gated.

---

## §4. Handling Duplicate Acknowledgments after a Timeout

### §4.1 ACK Heuristic / §4.2 Timestamp Heuristic

> "The TCP sender may use such a heuristic to decide to
> invoke a fast retransmit in some cases, even when the
> three duplicate acknowledgments do not cover more
> than recover."

**Adherence:** exceeded (RACK-TLP supersedes). Both
heuristics are explicitly "may" optional in §4.
PyTCP runs RFC 8985 RACK-TLP for post-RTO loss
detection in `_rack_process_ack`, which provides
strictly stronger guarantees than the §4 ACK / TS
heuristics: time-based loss detection with the RACK
reordering window correctly distinguishes spurious
retransmits from real losses regardless of dup-ACK
patterns. RFC 6582 §4 permits this exact substitution
("may use such a heuristic"); the choice is an
implementation discretion that PyTCP exercises in
favour of the more modern algorithm.

---

## §5. Implementation Issues for the Data Receiver

> "Out-of-order data segments SHOULD be acknowledged
> immediately, in order to accelerate loss recovery"

**Adherence:** met. PyTCP emits an immediate ACK on
out-of-order data segments per RFC 5681 §4.2; the
receive-side ACK generation in
`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__established.py` does not
defer ACK emission for OOO data through the delayed-ACK
timer. This is the same code path that satisfies RFC
5681 §4.2 (audited under that RFC's adherence record).

---

## Test coverage audit

### §2 / §3.2 step 1 — `recover` / `_recovery_point` initialization

- **Indirect:** every fast-retransmit integration test
  in
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py`
  asserts `_recovery_point == 0` post-handshake (or
  equivalently asserts that the first dup-ACK after
  handshake doesn't fire fast retransmit before three
  dups arrive). No dedicated test pins
  "_recovery_point = 0 at __init__"; the construction
  invariant is verified by source review.

**Status:** locked in by construction.

### §3.2 step 2 — Three dup-ACK fast-retransmit gate

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py`
  contains the dup-ACK threshold tests; the broader
  count-trigger logic is exercised by the SACK
  integration tests at
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py::three_dup_sacks_above_gap_trigger_fast_retransmit`.
- **One-shot guard:** the
  `if self._recovery_point != 0: return` gate is pinned
  by tests that drive multiple back-to-back dup-ACK
  bursts during a single recovery episode and assert
  fast retransmit fires only once.

**Status:** locked in for the in-recovery one-shot
guard.

### §3.2 step 3 — Full ACK: cwnd = ssthresh deflation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPhase3::test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh`
  drives a fast-retransmit recovery, advances SND.UNA
  past `_recovery_point`, and asserts `cwnd == ssthresh`
  on recovery exit.

**Status:** locked in.

### §3.2 step 3 — Partial ACK (PRR substitute)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPrr::test__cwnd__prr__cum_ack_during_recovery_sets_cwnd_per_prr_formula`
  pins the PRR formula on partial cum-ACKs.
- **Unit (helper, unused in production):**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__newreno.py`
  contains 10 unit tests for the
  `partial_cum_ack_deflate` helper — useful as a
  reference implementation pinned against the §3.2
  step 3b formula even though the helper is not
  called from production.

**Status:** locked in (PRR substitute); the literal
RFC 6582 helper is locked in as a reference but not
exercised in integration tests.

### §3.2 step 4 — Post-RTO `recover` recording

- **Integration:**
  `test__tcp__session__data_transfer__retransmit_timeout.py::TestTcpRfc6582Recover`
  pins the three sentinel transitions:
  - `test__rfc6582__recover_seq_initialised_zero` — fresh
    connections start with `_recover_seq == 0` so the first
    loss event is not artificially gated.
  - `test__rfc6582__rto_records_snd_max_into_recover_seq`
    — after an RTO the recover marker equals SND.MAX at
    RTO entry.
  - `test__rfc6582__recover_seq_clears_when_cum_ack_passes_marker`
    — once SND.UNA reaches the marker, `_recover_seq`
    decays back to 0 so subsequent legitimate loss
    events can enter recovery normally.

**Status:** locked in.

### §4 ACK / Timestamp heuristics

Not implemented; the heuristics are explicitly "may"
optional and PyTCP runs RFC 8985 RACK-TLP for post-RTO
loss detection instead, which provides strictly
stronger time-based detection. The full RACK-TLP test
coverage is audited under the RFC 8985 record.

**Status:** exceeded (RACK-TLP supersedes).

### §5 Receiver immediate ACK on OOO

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__out_of_order.py`
  pins the "immediate ACK on OOO segment" behaviour
  per RFC 5681 §4.2 (which RFC 6582 §5 echoes).

**Status:** locked in (cross-cut with RFC 5681 §4.2).

### Test coverage summary

| Aspect                                           | Coverage                                      |
|--------------------------------------------------|-----------------------------------------------|
| §2 `_recovery_point` state                       | locked in by construction                     |
| §3.2 step 1 init                                 | locked in indirectly                          |
| §3.2 step 2 three dup-ACK + one-shot gate        | locked in                                     |
| §3.2 step 3 full-ACK cwnd = ssthresh             | locked in                                     |
| §3.2 step 3 partial-ACK PRR substitute           | locked in (PRR formula tested)                |
| §3.2 step 3b literal helper (unused)             | locked in as reference (10 unit tests)        |
| §3.2 step 4 post-RTO `recover` recording         | locked in (TestTcpRfc6582Recover, 3 tests)    |
| §4 ACK heuristic                                 | exceeded by RFC 8985 RACK time-based detection|
| §4.2 Timestamp heuristic                         | exceeded by RFC 8985 RACK time-based detection|
| §5 Receiver immediate ACK on OOO                 | locked in (cross-cut with RFC 5681 §4.2)      |

---

## Overall assessment

| Aspect                                          | Status                                         |
|-------------------------------------------------|------------------------------------------------|
| §2 `recover` state variable                     | met (renamed `_recovery_point`)                |
| §3.2 step 1 init                                | deviates non-normatively (sentinel encoding)   |
| §3.2 step 2 three dup-ACK gate                  | met (one-shot via `_recovery_point != 0`)      |
| §3.2 step 3 full ACK: cwnd = ssthresh           | met (option 2)                                 |
| §3.2 step 3 partial ACK deflation               | superseded by RFC 6937 PRR (stronger)          |
| §3.2 step 3 partial ACK retransmit              | met (via RFC 6675 NextSeg)                     |
| §3.2 step 3 first-partial timer reset           | met (via RFC 6298 §5.3 cum-ACK restart)        |
| §3.2 step 4 post-RTO `recover` recording        | met (`_recover_seq` records SND.MAX-at-RTO)    |
| §4 dup-ACK-after-RTO heuristics                 | exceeded (RACK-TLP supersedes per §4 "may")    |
| §5 receiver immediate ACK on OOO                | met (via RFC 5681 §4.2)                        |

PyTCP's RFC 6582 conformance is mostly through
substitution: RFC 6937 PRR replaces the §3.2 step 3b
partial-ACK deflation with a strictly more accurate
mechanism, RFC 6675 NextSeg replaces the SACK-blind
"first unacknowledged segment" retransmit pick, and
RFC 8985 RACK-TLP replaces the dup-ACK-only recovery-
trigger logic with time-based loss detection. The §3.2
preamble explicitly disclaims RFC 2119 keyword
strength, so these substitutions are permitted.

§3.2 step 4 is also met: on RTO PyTCP records
SND.MAX-at-RTO into `_cc.recover_seq` (in addition to
clearing `_cc.recovery_point`), and the fast-retransmit
entry gate refuses re-entry while `SND.UNA` has not
reached that marker. Post-RTO dup-ACKs echoing the
retransmit storm therefore cannot re-trigger fast
retransmit, so PyTCP does not need either §4 heuristic
filter for correctness here; the RACK-TLP time-based
loss detection supplements the dup-ACK trigger on top.
No substantive RFC 6582 gap remains.
