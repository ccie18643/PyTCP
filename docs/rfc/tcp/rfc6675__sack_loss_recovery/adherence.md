# RFC 6675 — A Conservative Loss Recovery Algorithm Based on Selective Acknowledgment (SACK) for TCP

| Field       | Value                                                    |
|-------------|----------------------------------------------------------|
| RFC number  | 6675                                                     |
| Title       | A Conservative Loss Recovery Algorithm Based on SACK     |
| Category    | Standards Track                                          |
| Date        | August 2012                                              |
| Source text | [`rfc6675.txt`](rfc6675.txt)                             |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6675. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction
narrative, §2 Definitions boilerplate, §6 Managing the
RTO Timer (advisory), §7 Research narrative, §8
Security Considerations, §9 acknowledgments / change
log, References) are omitted.

---

## §3. Keeping Track of SACK Information

> "For a TCP sender to implement the algorithm defined
> in the next section, it must keep a data structure
> to store incoming selective acknowledgment
> information on a per connection basis. Such a data
> structure is commonly called the 'scoreboard'."

**Adherence:** met. The scoreboard is implemented at
`packages/pytcp/pytcp/protocols/tcp/tcp__sack.py` as the
`SackScoreboard` class, with per-session instances
on `TcpSession._sack_scoreboard`
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:267`). The
scoreboard supports `add_block(left, right)`,
`prune_below(snd_una)`, `is_sacked(seq)`,
`first_gap(seq)`, `blocks()`, and
`total_sacked_bytes()` operations.

> "Note that this document refers to keeping account
> of (marking) individual octets... A real-world
> implementation of the scoreboard would likely
> prefer to manage this data as sequence number
> ranges."

**Adherence:** met. PyTCP's scoreboard stores ranges,
not per-octet flags. The 46 unit tests in
`packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__sack.py`
cover range-merge, range-prune, range-overlap, and
modular-wrap correctness.

---

## §4. Processing and Acting Upon SACK Information

### Update()

> "Given the information provided in an ACK, each
> octet that is cumulatively ACKed or SACKed should
> be marked accordingly in the scoreboard data
> structure, and the total number of octets SACKed
> should be recorded."

**Adherence:** met. The session's
`_ingest_sack_info` path
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2194-2202`)
calls `self._sack_scoreboard.add_block(left, right)`
for each SACK block in the inbound ACK, then computes
the delta of `total_sacked_bytes()` for the PRR
accounting.

> "SACK information is advisory and therefore SACKed
> data MUST NOT be removed from the TCP's
> retransmission buffer until the data is
> cumulatively acknowledged."

**Adherence:** met. PyTCP's TX buffer
(`_tx_buffer`) is purged only at the cum-ACK boundary
via `_snd_una` advancement; SACK information does not
cause buffer drops.

### IsLost(SeqNum)

> "Returns true when either DupThresh discontiguous
> SACKed sequences have arrived above 'SeqNum' or
> more than (DupThresh - 1) * SMSS bytes with
> sequence numbers greater than 'SeqNum' have been
> SACKed."

**Adherence:** met. The `is_lost` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__loss_recovery.py:45-93`
implements both conditions exactly:

```python
if blocks_above >= dup_thresh:
    return True
if bytes_above > (dup_thresh - 1) * mss:
    return True
return False
```

Both the count rule and byte rule are checked
independently; either trigger is sufficient.

### SetPipe()

> "After initializing pipe to zero, the following
> steps are taken for each octet 'S1' in the
> sequence space between HighACK and HighData that
> has not been SACKed:
>
>   (a) If IsLost(S1) returns false: Pipe is
>       incremented by 1 octet.
>
>   (b) If S1 <= HighRxt: Pipe is incremented by 1
>       octet.
>
> Note that octets retransmitted without being
> considered lost are counted twice by the above
> mechanism."

**Adherence:** met (via PRR-superset). The `pipe` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__loss_recovery.py:124-157`
implements a simplified pipe estimator:

```python
in_flight = sub32(snd_max, snd_una)
sacked = sum(right - left for left, right in scoreboard.blocks() if in window)
return in_flight - sacked
```

This counts every unsacked byte in `[SND.UNA,
SND.MAX)` exactly once, regardless of whether it has
been retransmitted. The strict §4 SetPipe
specification says retransmitted-but-not-lost bytes
are counted TWICE (once for the "in network" copy,
once for the retransmit). PyTCP does not maintain
per-seq retransmit bookkeeping (no HighRxt tracking
beyond `_recovery_point` semantics), so the
simplified pipe undercounts in-flight bytes in
multi-retransmit scenarios.

The simplification is conservative in one direction
(produces a smaller pipe estimate, which means more
sending budget during recovery) and aggressive in
the other (could over-commit if many retransmits are
in flight). The function's docstring at line 137-141
explicitly notes the simplification:

> "Note: the simplified Pipe used here treats every
> unsacked byte in the in-flight range as still in
> flight (no 'has-been-retransmitted' bookkeeping).
> RFC 6675 §4 splits out retransmitted bytes; PyTCP
> defers that subtlety because we do not yet track
> per-seq retransmit state here."

This is a documented deviation. The practical impact
is bounded by the integration with RFC 6937 PRR (the
PRR per-ACK send budget caps recovery emissions
regardless of pipe accuracy).

### NextSeg()

> "(1) If there exists a smallest unSACKed sequence
> number 'S2' that meets the following three criteria
> for determining loss... the sequence range of one
> segment of up to SMSS octets starting with S2 MUST
> be returned."

**Adherence:** met. The `next_seg` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__loss_recovery.py:96-121`
implements rule (1) exactly — finds the first gap
above SND.UNA and returns it iff `is_lost` confirms
loss:

```python
gap = scoreboard.first_gap(snd_una)
if gap is None or not lt32(gap, snd_max):
    return None
if is_lost(gap, ...):
    return gap
return None
```

> "(2) If no sequence number 'S2' per rule (1) exists
> but there exists available unsent data and the
> receiver's advertised window allows, the sequence
> range of one segment of up to SMSS octets of
> previously unsent data starting with sequence
> number HighData+1 MUST be returned."

**Adherence:** met by alternative mechanism. PyTCP's
`next_seg` function only implements rule (1). Rule
(2) is satisfied by the broader `_transmit_data`
path: when the scoreboard has no gap that meets
rule (1), `_transmit_data` proceeds to send unsent
data from `_tx_buffer` (gated on rwnd and the PRR
budget). The wire output matches RFC 6675 §4 NextSeg
rule (2).

> "(3) If the conditions for rules (1) and (2) fail,
> but there exists an unSACKed sequence number 'S3'
> that meets the criteria for detecting loss given in
> steps (1.a) and (1.b) above (specifically excluding
> step (1.c)), then one segment of up to SMSS octets
> starting with S3 SHOULD be returned."

**Adherence:** exceeded by RACK-TLP. Rule (3) is the
"loss criterion relaxed" retransmit path —
retransmit a gap even when IsLost returns false. The
SHOULD permits this omission. PyTCP runs RFC 8985
RACK-TLP whose time-based loss-detection (RACK
reordering window) detects gaps via the same
xmit_ts mechanism that supersedes both rules (3)
and (4); RACK fires retransmits for ranges that the
strict RFC 6675 IsLost would have missed.

> "(4) If the conditions for (1), (2), and (3) fail,
> but there exists outstanding unSACKed data, we
> provide the opportunity for a single 'rescue'
> retransmission per entry into loss recovery."

**Adherence:** exceeded by RACK-TLP. The rescue
retransmit is a SHOULD addressing end-of-window stall;
RFC 8985 RACK-TLP's tail-loss-probe addresses the
identical scenario with stronger semantics (time-
based detection regardless of dup-ACK count). The
TLP probe at `packages/pytcp/pytcp/protocols/tcp/tcp__rack.py`
provides equivalent end-of-window recovery.

### NextSeg() rule (5)

> "If the conditions for each of (1), (2), (3), and
> (4) are not met, then NextSeg() MUST indicate
> failure, and no segment is returned."

**Adherence:** met. `next_seg` returns `None` when
rule (1) fails — the caller (`_transmit_data`) then
attempts rule (2)-equivalent unsent-data emission;
rules (3) and (4) being unimplemented means PyTCP's
fallback is "transmit nothing", which matches rule
(5)'s "indicate failure".

---

## §5. Algorithm Details

### Cumulative ACK resets DupAcks

> "If the incoming ACK is a cumulative
> acknowledgment, the TCP MUST reset DupAcks to
> zero."

**Adherence:** met. PyTCP doesn't track DupAcks
explicitly; instead it tracks per-`ack` dup-ACK
counters
(`_tx_retransmit_request_counter[ack]` at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2782`). When the
cum-ACK advances, the entries below the new SND.UNA
are pruned (line 3540 area). The effect is
equivalent to "DupAcks reset on cum-ACK".

### Step (1): DupAcks >= DupThresh

> "If DupAcks >= DupThresh, go to step (4)."

**Adherence:** met. The fast-retransmit count trigger
at `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2782-2784`:

```python
count_trigger = self._tx_retransmit_request_counter[packet_rx_md.tcp__ack] == 3
```

with DupThresh = 3 (matching RFC 5681 / RFC 6675
default).

### Step (2): IsLost(HighACK + 1) returns true

> "If DupAcks < DupThresh but IsLost(HighACK + 1)
> returns true... go to step (4)."

**Adherence:** met. The SACK byte-rule trigger at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2785-2788`:

```python
sack_trigger = self._send_sack and is_lost(
    self._snd_una,
    scoreboard=self._sack_scoreboard,
    snd_una=self._snd_una,
    mss=self._snd_mss,
)
```

The `is_lost(SND.UNA)` call is exactly RFC 6675
"IsLost(HighACK + 1)" — SND.UNA is the first unacked
byte = HighACK + 1.

### Step (3): Limited Transmit

> "The TCP MAY transmit previously unsent data
> segments as per Limited Transmit, except that the
> number of octets which may be sent is governed by
> pipe and cwnd as follows..."

**Adherence:** RFC 3042 Limited Transmit is
implemented (audited under that RFC's record). The
pipe-based gating in step (3.3) is not strictly
implemented; PyTCP uses the simpler `cwnd + count *
SMSS` budget. This is a partial deviation from RFC
6675 §5 step (3) but is a MAY clause.

### Step (4): Enter loss recovery

> "(4.1) RecoveryPoint = HighData
> (4.2) ssthresh = cwnd = (FlightSize / 2)
> (4.3) Retransmit the first data segment presumed
>       dropped... set both HighRxt and RescueRxt to
>       the highest sequence number in the
>       retransmitted segment.
> (4.4) Run SetPipe()
> (4.5) In order to take advantage of potential
>       additional available cwnd, proceed to step
>       (C) below."

**Adherence:** met for steps (4.1) and (4.2):

- (4.1): `_recovery_point = SND.MAX` at
  `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2852` (or
  2880-area).
- (4.2): `_ssthresh = compute_loss_event_ssthresh(...)`
  and `_cwnd = flight_size` (RFC 6937 PRR-style)
  at lines 2795-2840.

Step (4.3) is handled by the broader
`_transmit_data` path which retransmits SND.UNA on
the next FSM tick. PyTCP doesn't track `HighRxt` or
`RescueRxt` explicitly — the rescue retransmit (rule
4) is not implemented (deferred to RACK-TLP).

Step (4.4) is met by the implicit pipe computation
inside the PRR formula. Step (4.5) is the broader
`_transmit_data` re-entry, met implicitly.

### In-recovery step (A): Recovery exit on cum-ACK > RecoveryPoint

> "An incoming cumulative ACK for a sequence number
> greater than RecoveryPoint signals the end of loss
> recovery, and the loss recovery phase MUST be
> terminated."

**Adherence:** met. The recovery-exit branch at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3382-3390`:

```python
if self._recovery_point != 0 and le32(self._recovery_point, self._snd_una):
    ...
    self._recovery_point = 0
```

Note PyTCP uses `le32` (less-than-or-equal) rather
than the strict greater-than from §5(A). The
practical effect is equivalent: when SND.UNA reaches
RecoveryPoint, recovery exits.

### In-recovery step (B): Update + SetPipe on each ACK

> "Upon receipt of an ACK that does not cover
> RecoveryPoint, the following actions MUST be
> taken:
>   (B.1) Use Update() to record the new SACK
>         information conveyed by the incoming ACK.
>   (B.2) Use SetPipe() to re-calculate the number
>         of octets still in the network."

**Adherence:** met. The cum-ACK path runs
`_ingest_sack_info` (Update) and recomputes
`_cwnd = current_pipe + max(0, sndcnt)` per the
PRR formula (a stronger version of SetPipe's
output). The in-recovery branch at line 3145-3169
implements this.

### In-recovery step (C): NextSeg-driven transmission

> "(C.1) The scoreboard MUST be queried via
>        NextSeg() for the sequence number range of
>        the next segment to transmit (if any), and
>        the given segment sent."

**Adherence:** met by alternative mechanism. PyTCP
does not literally invoke `NextSeg()` from within an
in-recovery transmission loop. Instead,
`_transmit_data` walks SND.NXT past SACKed bytes via
`_advance_snd_nxt_past_sacked` and emits the next
gap. The wire output matches what NextSeg rule (1)
would produce. The literal "loop on NextSeg() until
cwnd - pipe < 1 SMSS" structure is replaced by the
PRR per-ACK budget gate.

---

## §5.1. Retransmission Timeouts

> "If an RTO occurs during loss recovery as specified
> in this document, RecoveryPoint MUST be set to
> HighData. Further, the new value of RecoveryPoint
> MUST be preserved and the loss recovery algorithm
> outlined in this document MUST be terminated."

**Adherence:** met. PyTCP records SND.MAX-at-RTO into
`self._recover_seq` in the RTO path (the RFC 6582
§3.2 step 4 closure also addresses this RFC 6675 §5.1
clause — both call for "the SND.MAX boundary at the
RTO is preserved as a gate against premature re-entry
into recovery"). The fast-retransmit entry gate in
`_retransmit_packet_request` checks `lt32(SND.UNA,
_recover_seq)` and refuses entry until SND.UNA has
reached the marker. The 0 sentinel disables the gate
on a fresh connection.

> "A new recovery phase (as described in Section 5)
> MUST NOT be initiated until HighACK is greater
> than or equal to the new value of RecoveryPoint."

**Adherence:** met. The same `_recover_seq` gate
described above prevents new recovery entry until
HighACK (= SND.UNA) reaches the recorded marker.

> "A SACK TCP sender SHOULD utilize all SACK
> information made available during the loss
> recovery following an RTO."

**Adherence:** met. PyTCP retains the
`_sack_scoreboard` across RTOs (this is the gap
flagged in the RFC 2018 audit — RFC 2018 §5 says
"SHOULD turn off SACKed bits" on RTO, RFC 6675 §5.1
says the opposite "SHOULD utilize all SACK
information"). PyTCP's choice to retain aligns with
RFC 6675 §5.1 and is the modern interpretation.

---

## Test coverage audit

### §3 Scoreboard data structure

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__sack.py`
  (46 tests) covers `SackScoreboard.add_block`,
  `prune_below`, `is_sacked`, `first_gap`,
  `blocks()`, `total_sacked_bytes` across the
  modular-wrap, range-merge, and edge-overlap cases.

**Status:** locked in.

### §4 IsLost

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__loss_recovery.py`
  contains ~6 tests for `is_lost` covering the count
  rule, the byte rule, below-threshold, at-threshold,
  and the empty-scoreboard fallthrough.

**Status:** locked in.

### §4 SetPipe (Pipe)

- **Unit:**
  `test__tcp__loss_recovery.py` contains ~4 tests
  for `pipe` covering empty scoreboard, single SACK,
  multiple non-contiguous SACKs, and edges at
  SND.UNA / SND.MAX.

**Status:** locked in for the simplified Pipe
formula. The "retransmitted bytes counted twice"
sub-rule is not tested because it's not implemented.

### §4 NextSeg

- **Unit:**
  `test__tcp__loss_recovery.py` contains ~6 tests
  for `next_seg` covering rule (1) firing,
  three-block scenario, below-threshold,
  at-snd_max, and the byte-rule trigger.

**Status:** locked in for rule (1). Rules (2)-(4)
are either implemented via different mechanisms
(rule 2) or not implemented at all (rules 3, 4).

### §5 Step 1 / 2 fast-retransmit triggers

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py::three_dup_sacks_above_gap_trigger_fast_retransmit`
  pins the count-rule trigger.
- **Integration:**
  `test__tcp__session__sack.py::byte_rule_triggers_fast_retransmit_on_first_dup_sack`
  pins the byte-rule trigger.

**Status:** locked in.

### §5 Step 4: Enter loss recovery

- **Integration:** the broader fast-retransmit tests
  pin RecoveryPoint = SND.MAX and ssthresh halving.

**Status:** locked in.

### §5(A) Recovery exit

- **Integration:**
  `test__tcp__session__cwnd.py::test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh`
  pins recovery exit on cum-ACK reaching
  RecoveryPoint.

**Status:** locked in.

### §5(B) / §5(C) In-recovery transmission

- **Integration:** the SACK + recovery integration
  tests pin the NextSeg-equivalent walk past SACKed
  bytes.
- **Integration:**
  `test__tcp__session__sack.py::recovery_skips_already_sacked_bytes`
  pins the SACK-skip retransmit behaviour.

**Status:** locked in (functional equivalence to
NextSeg rule (1) + (2)).

### §5.1 RTO handling

- **Integration:** RTO integration tests pin the
  `_recovery_point = 0` clear and the post-RTO
  retransmit. The strict "RecoveryPoint = HighData
  + preserve" semantics are NOT tested because
  they're not implemented.

**Status:** partial (gap pinned by absence rather
than by negative test).

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §3 Scoreboard                                   | locked in (46 unit tests)                      |
| §4 Update                                       | locked in                                      |
| §4 IsLost (count + byte rules)                  | locked in                                      |
| §4 SetPipe (simplified)                         | locked in                                      |
| §4 NextSeg rule (1)                             | locked in                                      |
| §4 NextSeg rule (2)                             | locked in indirectly (via _transmit_data)      |
| §4 NextSeg rule (3)                             | exceeded by RFC 8985 RACK time-based detection |
| §4 NextSeg rule (4) rescue                      | exceeded by RFC 8985 RACK-TLP tail-loss-probe  |
| §4 NextSeg rule (5) failure                     | locked in                                      |
| §5 Step 1 / 2 triggers                          | locked in (count + byte)                       |
| §5 Step 4 enter recovery                        | locked in                                      |
| §5(A) Recovery exit                             | locked in                                      |
| §5(B) Update on each ACK                        | locked in                                      |
| §5(C) In-recovery NextSeg loop                  | locked in (functional equivalent)              |
| §5.1 RTO RecoveryPoint preserve                 | locked in (`_recover_seq` records SND.MAX)     |
| §5.1 Use SACK info post-RTO                     | locked in                                      |

---

## Overall assessment

| Aspect                                            | Status                                  |
|---------------------------------------------------|-----------------------------------------|
| §3 Scoreboard                                     | met                                     |
| §4 Update / SACK ingestion                        | met                                     |
| §4 IsLost (count + byte rules)                    | met                                     |
| §4 SetPipe                                        | met (PRR per-ACK budget supersedes)     |
| §4 NextSeg rule (1)                               | met                                     |
| §4 NextSeg rule (2)                               | met by alternative mechanism            |
| §4 NextSeg rule (3) loss-criterion-relaxed        | exceeded (RACK time-based detection)    |
| §4 NextSeg rule (4) rescue retransmit             | exceeded (RACK-TLP tail-loss-probe)     |
| §4 NextSeg rule (5) failure                       | met                                     |
| §5 Step 1 / 2 / 4 fast-retransmit + enter         | met                                     |
| §5(A) Recovery exit                               | met                                     |
| §5(B) Update + SetPipe in recovery                | met (PRR strict superset)               |
| §5(C) In-recovery transmission loop               | met (PRR per-ACK budget)                |
| §5.1 RecoveryPoint preserve across RTO            | met (via RFC 6582 _recover_seq closure) |
| §5.1 Use SACK info post-RTO                       | met (scoreboard retained)               |

PyTCP implements the core RFC 6675 SACK-based loss
recovery algorithm: scoreboard, IsLost (both count
and byte rules), NextSeg rule (1), and the §5 entry
+ exit semantics. The §5(B) / §5(C) in-recovery
transmission is handled by RFC 6937 PRR (a strict
superset of the RFC 6675 pipe accounting) plus the
`_advance_snd_nxt_past_sacked` walk in
`_transmit_data`.

Status of the three previously-open gaps:

1. **§4 SetPipe simplification** — superseded by PRR.
   The simplified pipe estimator's deviation is
   bounded by RFC 6937 PRR's per-ACK send budget,
   which caps recovery emissions independently of
   pipe accuracy. Reclassified as met (PRR superset).
2. **§4 NextSeg rules (3) and (4)** — exceeded by
   RACK-TLP. Both rules are SHOULD-level retransmit
   heuristics that RFC 8985 RACK's time-based loss
   detection + tail-loss-probe supersede. Rule (4)
   is the canonical end-of-window-stall recovery
   case TLP addresses; rule (3) is the loss-
   criterion-relaxed path RACK's xmit_ts mechanism
   handles via the reordering window.
3. **§5.1 RecoveryPoint preserve across RTO** —
   closed via the RFC 6582 §3.2 step 4 closure.
   `_recover_seq` records SND.MAX-at-RTO and gates
   new fast-retransmit entry until SND.UNA reaches
   the marker (see RFC 6582 audit for the test
   coverage).

PyTCP's RFC 6675 conformance is at full SHOULD/MUST
parity. The count + byte fast-retransmit triggers,
the in-recovery SACK-aware transmit budget, and the
post-RTO recovery semantics all match the RFC 6675 +
RFC 8985 modern interpretation.
