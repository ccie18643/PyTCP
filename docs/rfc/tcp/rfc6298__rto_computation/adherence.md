# RFC 6298 — Computing TCP's Retransmission Timer

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 6298                                   |
| Title       | Computing TCP's Retransmission Timer   |
| Category    | Standards Track                        |
| Date        | June 2011                              |
| Obsoletes   | RFC 2988                               |
| Updates     | RFC 1122                               |
| Source text | [`rfc6298.txt`](rfc6298.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6298. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§6 Security Considerations boilerplate, §7 Changes from
RFC 2988, §8 Acknowledgments, §9 References,
Appendix A rationale) are omitted.

---

## §2. The Basic Algorithm

### (2.1) Initial RTO before any RTT sample

> "Until a round-trip time (RTT) measurement has been
> made for a segment sent between the sender and
> receiver, the sender SHOULD set RTO ← 1 second,
> though the 'backing off' on repeated retransmission
> discussed in (5.5) still applies."

**Adherence:** met. `INITIAL_RTO_MS = 1000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:66`); `initial_state()`
(line 115) constructs the RtoState with `rto_ms =
INITIAL_RTO_MS`. The backoff machinery still applies to
this initial value via `back_off()` (line 160) on RTO
events.

### (2.2) First RTT measurement

> "When the first RTT measurement R is made, the host
> MUST set:
>
>     SRTT <- R
>     RTTVAR <- R/2
>     RTO <- SRTT + max(G, K*RTTVAR)
>
> where K = 4."

**Adherence:** met. The `update()` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:126-157` handles
`state.srtt_ms is None` (first sample) at line 145-148:

```python
if state.srtt_ms is None:
    srtt = sample_ms
    rttvar = sample_ms // 2
```

Then computes `rto = srtt + max(CLOCK_GRANULARITY_MS,
K * rttvar)` at line 156. `K = 4` at line 81, exactly
matching the RFC's specified value.

### (2.3) Subsequent RTT measurement (EWMA)

> "When a subsequent RTT measurement R' is made, a host
> MUST set:
>
>     RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
>     SRTT <- (1 - alpha) * SRTT + alpha * R'
>
> The value of SRTT used in the update to RTTVAR is its
> value before updating SRTT itself using the second
> assignment. That is, updating RTTVAR and SRTT MUST
> be computed in the above order.
>
> The above SHOULD be computed using alpha=1/8 and
> beta=1/4 (as suggested in [JK88]).
>
> After the computation, a host MUST update
> RTO <- SRTT + max(G, K*RTTVAR)"

**Adherence:** met. The subsequent-sample branch at
lines 149-156:

```python
rttvar = ((BETA_DEN - BETA_NUM) * state.rttvar_ms + BETA_NUM * abs(state.srtt_ms - sample_ms)) // BETA_DEN
srtt = ((ALPHA_DEN - ALPHA_NUM) * state.srtt_ms + ALPHA_NUM * sample_ms) // ALPHA_DEN
rto = srtt + max(CLOCK_GRANULARITY_MS, K * rttvar)
```

with `α = ALPHA_NUM / ALPHA_DEN = 1/8` (lines 87-88)
and `β = BETA_NUM / BETA_DEN = 1/4` (lines 92-93).
Critically, RTTVAR is computed BEFORE SRTT (line 154
runs before line 155) and uses the OLD `state.srtt_ms`
(not the new value), satisfying the RFC's "RTTVAR and
SRTT MUST be computed in the above order" mandate.

### (2.4) RTO floor at 1 second

> "Whenever RTO is computed, if it is less than 1
> second, then the RTO SHOULD be rounded up to 1
> second."

**Adherence:** met. `MIN_RTO_MS = 1000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:69`); `clamp_rto()`
at line 177 enforces `max(MIN_RTO_MS, min(rto_ms,
MAX_RTO_MS))`. Both `update()` and `back_off()` route
their results through this clamp (or its inline
equivalent), so any computed RTO < 1 s is rounded up.

### (2.5) RTO ceiling

> "A maximum value MAY be placed on RTO provided it is
> at least 60 seconds."

**Adherence:** met. `MAX_RTO_MS = 60_000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:73`) — exactly the
60-second floor specified by §2.5. The clamp is
applied in `update()` via `clamp_rto` and in
`back_off()` via the inline `min(state.rto_ms * 2,
MAX_RTO_MS)`.

---

## §3. Taking RTT Samples

### Karn's algorithm (no samples from retransmits)

> "TCP MUST use Karn's algorithm [KP87] for taking RTT
> samples. That is, RTT samples MUST NOT be made using
> segments that were retransmitted (and thus for which
> it is ambiguous whether the reply was for the first
> instance of the packet or a later instance)."

**Adherence:** met. The `_rtt_sample_retransmitted`
flag (`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:586`) is set
in `_retransmit_packet_timeout` whenever the in-flight
sample's segment is retransmitted. The covering-ACK
harvest path in `_process_ack_packet` checks this flag
before invoking `update()`; if True, the sample is
discarded and SRTT / RTTVAR remain unchanged. Karn's
algorithm fully implemented.

### Timestamp-option exception

> "The only case when TCP can safely take RTT samples
> from retransmitted segments is when the TCP timestamp
> option [JBB92] is employed, since the timestamp
> option removes the ambiguity..."

**Adherence:** met (when negotiated). The RFC 7323
audit (separately) covers PyTCP's bilateral timestamp
negotiation. When `_send_ts` is True, the
`_process_ack_packet` path uses the TSecr field from
the inbound ACK to compute an unambiguous RTT sample,
bypassing the Karn-taint flag. This is the §3
exception path implemented exactly as specified.

### At least one RTT measurement per RTT

> "A TCP implementation MUST take at least one RTT
> measurement per RTT (unless that is not possible per
> Karn's algorithm)."

**Adherence:** met. PyTCP samples once per RTT via the
`_rtt_sample_seq` / `_rtt_sample_send_time_ms` /
`_rtt_sample_retransmitted` triple
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:570-586`). When
RFC 7323 timestamps are bilateral, the sampling
cadence increases to once-per-ACK (also satisfying
"at least one per RTT"). The Karn-skip path correctly
exempts retransmits, satisfying the parenthetical
"unless not possible per Karn's algorithm".

---

## §4. Clock Granularity

### G must round up RTTVAR if K*RTTVAR is zero

> "However, if the K*RTTVAR term in the RTO calculation
> equals zero, the variance term MUST be rounded to G
> seconds (i.e., use the equation given in step 2.3).
>
>     RTO <- SRTT + max(G, K*RTTVAR)"

**Adherence:** met. The `update()` function uses
`max(CLOCK_GRANULARITY_MS, K * rttvar)` at line 156
exactly as specified. With `CLOCK_GRANULARITY_MS = 1`
(line 78), the floor fires when `K * rttvar == 0`
(i.e., when SRTT and the sample are exactly equal,
yielding RTTVAR = 0).

### Finer granularity preferred

> "Experience has shown that finer clock granularities
> (≤ 100 msec) perform somewhat better than coarser
> granularities."

**Adherence:** met (with margin). PyTCP's
`CLOCK_GRANULARITY_MS = 1` is two orders of magnitude
finer than the 100 ms threshold the RFC suggests. The
underlying timer subsystem advances in 1 ms ticks
(`packages/pytcp/pytcp/stack/__init__.py` and the FakeTimer in tests
both use 1 ms resolution).

---

## §5. Managing the RTO Timer

### Don't retransmit too early

> "An implementation MUST manage the retransmission
> timer(s) in such a way that a segment is never
> retransmitted too early, i.e., less than one RTO
> after the previous transmission of that segment."

**Adherence:** met. The session-level retransmit timer
`f"{self}-retransmit"` is registered with the current
`_rto_state.rto_ms` value; the timer fires only after
that interval elapses. There is no code path that
retransmits before the timer expires.

### (5.1) Start timer on every data send

> "Every time a packet containing data is sent
> (including a retransmission), if the timer is not
> running, start it running so that it will expire
> after RTO seconds."

**Adherence:** met. The `_transmit_packet` path
includes a register-if-not-already check that arms
the timer at `rto_ms` whenever a data segment, SYN, or
FIN is emitted. The "if the timer is not running"
gate is the canonical "arm-once" semantic.

### (5.2) Turn off timer when all data acked

> "When all outstanding data has been acknowledged,
> turn off the retransmission timer."

**Adherence:** met.
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3256-3257`:

```python
if self._snd_una == self._snd_max:
    stack.timer.unregister_timers_with_prefix(f"{self}-retransmit")
```

The cum-ACK path checks for SND.UNA reaching SND.MAX
(all in-flight bytes acknowledged) and unregisters
the retransmit timer.

### (5.3) Restart timer on cum-ACK that advances SND.UNA

> "When an ACK is received that acknowledges new data,
> restart the retransmission timer so that it will
> expire after RTO seconds (for the current value of
> RTO)."

**Adherence:** met. The cum-ACK path in
`_process_ack_packet` re-registers the timer with the
current `rto_ms` whenever `lt32(_snd_una, ack)` (i.e.,
the ACK advances SND.UNA). When SND.UNA == SND.MAX
post-update, §5.2 takes precedence and the timer is
turned off rather than restarted.

### (5.4) Retransmit earliest unacked segment

> "Retransmit the earliest segment that has not been
> acknowledged by the TCP receiver."

**Adherence:** met. `_retransmit_packet_timeout` at
the RTO firing point rewinds `_snd_nxt` to `_snd_una`
and lets `_transmit_data` re-emit from the earliest
unacked byte. The TX buffer slicing logic at
`tcp__session.py:2310-2350` always starts from
`_tx_buffer_nxt = _snd_nxt - _snd_ini`, so post-rewind
the next emission is exactly the earliest unacked
segment.

### (5.5) Back off RTO

> "The host MUST set RTO ← RTO * 2 ('back off the
> timer'). The maximum value discussed in (2.5) above
> may be used to provide an upper bound to this
> doubling operation."

**Adherence:** met. `back_off()` at
`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:160-174` doubles
`rto_ms` and clamps to `MAX_RTO_MS`. Invoked from
`_retransmit_packet_timeout` on every RTO firing.

### (5.6) Restart timer with backed-off RTO

> "Start the retransmission timer, such that it
> expires after RTO seconds (for the value of RTO
> after the doubling operation outlined in 5.5)."

**Adherence:** met. The `_retransmit_packet_timeout`
handler invokes `back_off()` BEFORE re-registering the
timer; the new registration uses the doubled
`rto_ms`.

### (5.7) SYN-RTO 3-second floor

> "If the timer expires awaiting the ACK of a SYN
> segment and the TCP implementation is using an RTO
> less than 3 seconds, the RTO MUST be re-initialized
> to 3 seconds when data transmission begins (i.e.,
> after the three-way handshake completes)."

**Adherence:** met. Both active-open and passive-open
paths implement this:

- Active open
  (`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__syn_sent.py:218`):

  ```python
  if session._syn_retransmit_count > 0 and session._rto_state.rto_ms < 3000:
      ...
  ```

- Passive open
  (`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__syn_rcvd.py:128`):
  same shape.

The `_syn_retransmit_count` field
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:599`) is
incremented in `_retransmit_packet_timeout` whenever
the retransmitted segment is a SYN. The 3000 ms
threshold matches the §5.7 "3 seconds" specification
exactly. When data transmission begins (post-
handshake-ack), the floor is applied if the SYN was
ever retransmitted.

### Post-RTO RTO collapse via fresh sample (informational)

> "Note that after retransmitting, once a new RTT
> measurement is obtained (which can only happen when
> new data has been sent and acknowledged), the
> computations outlined in Section 2 are performed,
> including the computation of RTO, which may result
> in 'collapsing' RTO back down after it has been
> subject to exponential back off (rule 5.5)."

**Adherence:** met. The `update()` formula does not
consult prior `rto_ms`; it computes a fresh value from
SRTT + max(G, K*RTTVAR). Any backed-off RTO is
naturally replaced by the next non-tainted sample's
result.

### MAY clear SRTT/RTTVAR after multiple backoffs

> "Note that a TCP implementation MAY clear SRTT and
> RTTVAR after backing off the timer multiple times..."

**Adherence:** the MAY is permissive. PyTCP does have
an "estimator reset on idle" path at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1239-1251`:

```python
if (
    (data or flag_syn or flag_fin)
    and self._last_send_time_ms is not None
    and stack.timer.now_ms - self._last_send_time_ms > self._rto_state.rto_ms
):
    self._rto_state = initial_state()
```

which fires when the session has been silent longer
than the in-flight `rto_ms`. The inline comment cites
"RFC 6298 §5.7 restart-after-idle" — this citation is
inaccurate (RFC 6298 §5.7 is the SYN-RTO 3 s floor
clause; idle-restart is from RFC 5681 §4.1). The
behaviour is permissible under §5's closing MAY, but
the comment should reference RFC 5681 §4.1 instead of
RFC 6298 §5.7. This is a documentation polish item,
not a behavioural defect.

---

## Test coverage audit

### (2.1) Initial RTO ≥ 1 s

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__rto.py::TestRtoInitialState`
  pins `initial_state().rto_ms == INITIAL_RTO_MS == 1000`.
- **Constants:**
  `test__rto__initial_rto_is_1_second` and
  `test__rto__min_rto_is_at_least_1_second` pin the
  constant values.

**Status:** locked in.

### (2.2) First-sample formula

- **Unit:**
  `test__tcp__rto.py::TestRtoUpdateFirstSample::test__rto__update__first_sample_500ms_canonical_values`
  drives `update(initial_state(), R)` and pins the
  resulting `srtt == R`, `rttvar == R // 2`,
  `rto = srtt + K * rttvar` formula.

**Status:** locked in.

### (2.3) Subsequent-sample EWMA

- **Unit:**
  `test__tcp__rto.py::TestRtoUpdateSubsequentSample`
  cases cover multiple sample-vs-SRTT deltas, asserting the
  EWMA formula and verifying the RTTVAR-before-SRTT
  ordering.

**Status:** locked in.

### (2.4) RTO floor at 1 s

- **Unit:** `test__tcp__rto.py::TestRtoClamp` pins the
  clamp behaviour.

**Status:** locked in.

### (2.5) RTO ceiling 60 s

- **Unit:** `TestRtoClamp::test__rto__clamp_rto__above_max_clamped_down`
  and `TestRtoBackOff::test__rto__back_off__caps_at_max_rto`
  pin the upper bound.

**Status:** locked in.

### §3 Karn's algorithm

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py::TestTcpRtoSampling::test__rto__retransmit_marks_pending_sample_as_karn_tainted`
  drives a retransmit and asserts the in-flight
  sample is flagged.
- **Integration:**
  `test__rto__ack_of_karn_tainted_sample_clears_but_does_not_update_state`
  drives the covering ACK and asserts SRTT / RTTVAR
  remain unchanged.

**Status:** locked in.

### §3 Timestamp exception

Covered by RFC 7323 audit (separately).

**Status:** locked in (cross-reference).

### §3 At least one RTT/round

- **Integration:** the once-per-RTT cadence is
  exercised by every multi-segment integration test;
  no dedicated test pins the "at least once per RTT"
  requirement.

**Status:** locked in indirectly.

### §4 Clock granularity

- **Unit:** the formula `max(G, K*RTTVAR)` is
  exercised in every `update()` unit test;
  specifically when RTTVAR = 0 the
  `CLOCK_GRANULARITY_MS = 1` floor fires.

**Status:** locked in.

### §5.1 Arm timer on data send

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py::TestTcpRtoRetransmitTimer::test__rto__data_transmit_arms_session_level_retransmit_timer`
  pins the "if not running, arm" semantic.

**Status:** locked in.

### §5.2 Stop timer on all-acked

- **Integration:**
  `test__tcp__session__rto.py::test__rto__cumulative_ack_draining_in_flight_stops_retransmit_timer`
  pins the unregister-on-SND.UNA-equals-SND.MAX path.

**Status:** locked in.

### §5.3 Restart timer on cum-ACK

- **Integration:** the timer-restart path is
  exercised by every RTO-related integration test
  that drives multi-segment transfers with cum-ACKs.

**Status:** locked in.

### §5.4 Retransmit earliest unacked

- **Integration:**
  `test__tcp__session__data_transfer__retransmit_timeout.py`
  exercises the rewind + retransmit path.

**Status:** locked in.

### §5.5 Back off RTO

- **Unit:** `TestRtoBackOff` covers the doubling +
  clamping logic.
- **Integration:**
  `test__tcp__session__rto.py::test__rto__retransmit_timeout_backs_off_rto_state`
  drives an RTO and asserts the doubled `rto_ms`.

**Status:** locked in.

### §5.6 Restart with backed-off RTO

- **Integration:**
  `test__tcp__session__rto.py` includes "after back_off,
  the retransmit timer must..." assertion that pins
  the post-backoff timer registration uses the new
  RTO value.

**Status:** locked in.

### §5.7 SYN-RTO 3 s floor

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__active.py`
  and `__handshake__passive.py` contain dedicated
  tests that drive a SYN retransmit before handshake
  completion and assert the post-handshake `rto_ms >=
  3000`.

**Status:** locked in.

### §5 closing MAY (clear SRTT / RTTVAR)

The estimator-reset-on-idle path at
`tcp__session.py:1239-1251` is exercised by RTO
integration tests, but no test specifically asserts
the MAY clause. The behaviour is permitted, not
required.

**Status:** locked in indirectly (no required
behaviour to pin).

### Test coverage summary

| Aspect                                          | Coverage                              |
|-------------------------------------------------|---------------------------------------|
| (2.1) Initial RTO ≥ 1 s                         | locked in                             |
| (2.2) First-sample formula                      | locked in                             |
| (2.3) Subsequent EWMA                           | locked in                             |
| (2.4) RTO floor at 1 s                          | locked in                             |
| (2.5) RTO ceiling 60 s                          | locked in                             |
| §3 Karn's algorithm                             | locked in                             |
| §3 Timestamp exception                          | locked in (cross-ref RFC 7323)        |
| §3 At least one sample per RTT                  | locked in indirectly                  |
| §4 Clock granularity floor                      | locked in                             |
| §5.1 Arm timer on data send                     | locked in                             |
| §5.2 Stop timer on all-acked                    | locked in                             |
| §5.3 Restart on cum-ACK                         | locked in                             |
| §5.4 Retransmit earliest unacked                | locked in                             |
| §5.5 Back off RTO                               | locked in                             |
| §5.6 Restart with backed-off RTO                | locked in                             |
| §5.7 SYN-RTO 3 s floor                          | locked in                             |
| §5 MAY clear SRTT/RTTVAR after backoffs         | n/a (MAY; behaviour exercised)        |

---

## Overall assessment

| Aspect                                          | Status                                       |
|-------------------------------------------------|----------------------------------------------|
| (2.1) Initial RTO ≥ 1 s                         | met                                          |
| (2.2) First-sample formula                      | met                                          |
| (2.3) Subsequent EWMA + ordering                | met (RTTVAR-before-SRTT correct)             |
| (2.3) α=1/8 / β=1/4                             | met                                          |
| (2.4) RTO floor at 1 s                          | met                                          |
| (2.5) RTO ceiling ≥ 60 s                        | met                                          |
| §3 Karn's algorithm                             | met                                          |
| §3 Timestamp exception                          | met (via RFC 7323)                           |
| §3 At least one sample per RTT                  | met                                          |
| §4 Granularity floor                            | met (G = 1 ms)                               |
| §5.1 Arm timer on data send                     | met                                          |
| §5.2 Stop timer on all-acked                    | met                                          |
| §5.3 Restart on cum-ACK                         | met                                          |
| §5.4 Retransmit earliest unacked                | met                                          |
| §5.5 Back off RTO                               | met                                          |
| §5.6 Restart with backed-off RTO                | met                                          |
| §5.7 SYN-RTO 3 s floor                          | met (active + passive open paths)            |
| §5 MAY clear SRTT/RTTVAR (idle reset)           | implemented as idle-reset; comment misattributed |

PyTCP fully implements every RFC 6298 normative
requirement. The single observation is documentation:
the inline comment at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1229` claims the
idle-reset path is "RFC 6298 §5.7", but RFC 6298 §5.7
is the SYN-RTO 3 s floor (which is implemented
elsewhere). The idle-reset behaviour is permissible
under RFC 6298 §5's closing MAY ("a TCP implementation
MAY clear SRTT and RTTVAR after backing off the timer
multiple times...") but is more naturally cited as
RFC 5681 §4.1 ("Restarting Idle Connections"). This is
a comment-attribution issue, not a behavioural defect.
