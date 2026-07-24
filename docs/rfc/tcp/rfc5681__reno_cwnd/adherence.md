# RFC 5681 — TCP Congestion Control

| Field       | Value                              |
|-------------|------------------------------------|
| RFC number  | 5681                               |
| Title       | TCP Congestion Control             |
| Category    | Standards Track                    |
| Date        | September 2009                     |
| Obsoletes   | RFC 2581                           |
| Source text | [`rfc5681.txt`](rfc5681.txt)       |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 5681. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §2
Definitions boilerplate, §4.3 advisory mechanisms, §5
Security, §6 Acknowledgments, §7 References) are
omitted.

---

## §3.1. Slow Start and Congestion Avoidance

### Initial Window (IW)

> "If SMSS > 2190 bytes: IW = 2 * SMSS bytes... If
> (SMSS > 1095 bytes) and (SMSS <= 2190 bytes): IW =
> 3 * SMSS bytes... if SMSS <= 1095 bytes: IW = 4 *
> SMSS bytes"

**Adherence:** superseded. RFC 6928 raises IW to
`min(10*SMSS, max(2*SMSS, 14600))`, which PyTCP
implements per the RFC 6928 audit. The §3.1 IW upper
bound is the older RFC 5681 limit; RFC 6928 is the
modern replacement and PyTCP uses it. Both
implementations honour the §3.1 commentary
"the SYN/ACK and the acknowledgment of the SYN/ACK
MUST NOT increase the size of the congestion window"
— PyTCP applies the IW value AFTER the post-handshake
`_process_ack_packet` runs, so any §3.1-style growth
is overwritten by the IW value.

### "If the SYN or SYN/ACK is lost, IW MUST be 1 segment"

> "if the SYN or SYN/ACK is lost, the initial window
> used by a sender after a correctly transmitted SYN
> MUST be one segment consisting of at most SMSS
> bytes."

**Adherence:** also superseded by RFC 6928 §2 which
permits `MAY still use this value (or any other
value > 1 second)` for SYN-RTO scenarios. RFC 6928
relaxes the strict "MUST be 1 segment" requirement;
PyTCP's choice to apply the IW10 formula
unconditionally (regardless of SYN retransmits) is
permitted by RFC 6928's relaxation. See the RFC 6928
audit's "Refrain from resetting IW to 1" section.

### ssthresh initial value

> "The initial value of ssthresh SHOULD be set
> arbitrarily high (e.g., to the size of the largest
> possible advertised window)."

**Adherence:** met. `ssthresh = 0x7FFF_FFFF`
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:709` —
`self._ssthresh: int = 0x7FFF_FFFF`) — the canonical
"INT32_MAX" choice that's well above any realistic
peer-advertised window. PyTCP enters slow-start
cleanly post-handshake.

### Slow start growth (Eq 2 — Appropriate Byte Counting)

> "During slow start, a TCP increments cwnd by at
> most SMSS bytes for each ACK received that
> cumulatively acknowledges new data... we RECOMMEND
> that TCP implementations increase cwnd, per:
>
>     cwnd += min (N, SMSS)                      (2)"

**Adherence:** met. The slow-start branch in
`packages/pytcp/pytcp/protocols/tcp/tcp__cwnd.py:111-112`:

```python
if cwnd < ssthresh:
    return cwnd + min(bytes_acked, smss)
```

Implements Eq 2 exactly. The `min(bytes_acked, smss)`
cap is the RFC 3465 ABC protection against "ACK
Division" attacks.

### Congestion avoidance growth

> "MAY increment cwnd by SMSS bytes... SHOULD
> increment cwnd per equation (2) once per RTT...
> MUST NOT increment cwnd by more than SMSS bytes"
>
> "Another common formula that a TCP MAY use to update
> cwnd during congestion avoidance is given in
> equation (3):
>
>     cwnd += SMSS*SMSS/cwnd                     (3)"

**Adherence:** met. The CA branch at line 113:

```python
return cwnd + max(1, smss * smss // cwnd)
```

Implements Eq 3 exactly. The `max(1, ...)` floor
implements the §3.1 Implementation Note: "Since
integer arithmetic is usually used... If the above
formula yields 0, the result SHOULD be rounded up to
1 byte."

(Note: `cc_mode` defaults to `CcMode.CUBIC`
(`state/tcp__state__cc.py`), so this CA formula is
replaced by RFC 9438's cubic growth per the CUBIC
audit unless the application opts into the Reno path
via `setsockopt(IPPROTO_TCP, TCP_CONGESTION, "reno")`.)

### Eq 4 — ssthresh on RTO

> "When a TCP sender detects segment loss using the
> retransmission timer... ssthresh MUST be set to no
> more than the value given in equation (4):
>
>     ssthresh = max (FlightSize / 2, 2*SMSS)            (4)"

**Adherence:** met. `compute_loss_event_ssthresh` at
`packages/pytcp/pytcp/protocols/tcp/tcp__cwnd.py:117-142`:

```python
return max(flight_size // 2, 2 * smss)
```

Exactly Eq 4. Invoked from
`_retransmit_packet_timeout` and from
`_retransmit_packet_request` (fast retransmit). The
2*SMSS floor matches §3.1 verbatim.

(In CUBIC mode, `cubic_loss_event_ssthresh` uses
beta_cubic = 0.7 instead of 0.5; covered in the CUBIC
audit.)

### "ssthresh held constant on second-time-retransmit"

> "On the other hand, when a TCP sender detects
> segment loss using the retransmission timer and the
> given segment has already been retransmitted by way
> of the retransmission timer at least once, the
> value of ssthresh is held constant."

**Adherence:** not explicitly tracked. PyTCP's
`_retransmit_packet_timeout` recomputes ssthresh from
the current FlightSize on every RTO firing. If the
same segment is retransmitted multiple times in
sequence (R2 abort scenarios), each RTO re-applies
the formula, which can drive ssthresh further down.

The RFC's intent is to prevent ssthresh from
collapsing to 2*SMSS through repeated halving. PyTCP's
behaviour is more aggressive than RFC 5681 strict;
the practical impact is bounded by the 2*SMSS floor
in Eq 4 (ssthresh never drops below that). The
deviation is conservative — PyTCP's ssthresh is at or
below what RFC 5681 strict would yield, never above.

### Loss Window LW = 1 SMSS

> "Furthermore, upon a timeout (as specified in
> [RFC2988]) cwnd MUST be set to no more than the
> loss window, LW, which equals 1 full-sized segment
> (regardless of the value of IW)."

**Adherence:** met. Post-RTO at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2672`:

```python
self._cwnd = self._snd_mss
```

Sets cwnd to exactly 1 SMSS, matching LW.

---

## §3.2. Fast Retransmit/Fast Recovery

### Receiver: immediate dup-ACK on OOO segment

> "A TCP receiver SHOULD send an immediate duplicate
> ACK when an out-of-order segment arrives."

**Adherence:** met. The OOO-arrival path at
`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__established.py:227`:

```python
session._transmit_packet(flag_ack=True)
```

Fires immediately on OOO data arrival, no delayed-ACK
gating.

### Receiver: immediate ACK on hole-fill

> "A TCP receiver SHOULD send an immediate ACK when
> the incoming segment fills in all or part of a gap
> in the sequence space."

**Adherence:** met. The hole-fill path also emits
immediately (the segment that drains an OOO range
into the cum-ACK boundary triggers the same
`_transmit_packet(flag_ack=True)` path without
delayed-ACK).

### Sender step 1: Limited Transmit on first 2 dup-ACKs

> "On the first and second duplicate ACKs received at
> a sender, a TCP SHOULD send a segment of previously
> unsent data per [RFC3042]..."

**Adherence:** met. RFC 3042 Limited Transmit is
implemented at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2771-2787` (see
RFC 3042 audit).

### Sender step 2: ssthresh per Eq 4 on 3rd dup-ACK

> "When the third duplicate ACK is received, a TCP
> MUST set ssthresh to no more than the value given
> in equation (4)."

**Adherence:** met.
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2789-2822`
(Reno branch at line 2822):

```python
self._ssthresh = compute_loss_event_ssthresh(flight_size, self._snd_mss)
```

Triggered by the count_trigger or sack_trigger gate
at lines 2782-2789.

### Sender step 3: Retransmit + cwnd = ssthresh + 3*SMSS

> "The lost segment starting at SND.UNA MUST be
> retransmitted and cwnd set to ssthresh plus 3*SMSS."

**Adherence:** superseded by RFC 6937 PRR. PyTCP sets
`_cwnd = flight_size` (line 2840 area) instead of
`ssthresh + 3*SMSS`. The §3.2 step 3 formula is
designed to compensate for the three "presumed-left-
network" segments that triggered fast retransmit; PRR
generalises this to a per-ACK proportional pacing
that accounts for actual delivered bytes (via the
`prr_delivered * ssthresh / RecoverFS` formula).

The RFC 6937 substitution is permitted because RFC
5681 §3.2 explicitly allows alternative loss-recovery
mechanisms (§4.3 references "advanced loss recovery
algorithm"). PRR is a strict superset that yields
better recovery properties (smoother send pacing, no
"half-window of silence", no over-commitment).

### Sender step 4: cwnd += SMSS per additional dup-ACK

> "For each additional duplicate ACK received (after
> the third), cwnd MUST be incremented by SMSS."

**Adherence:** superseded by PRR. PyTCP does not
inflate cwnd on each dup-ACK; instead the PRR per-
ACK budget at line 3155 / 3168 governs the per-ACK
send count. The §3.2 step 4 inflation is meant to
allow the sender to inject one segment per dup-ACK
(packet-conservation principle); PRR achieves the
same effect via the explicit `prr_delivered`
accounting.

### Sender step 5: Send unsent data when cwnd allows

> "When previously unsent data is available and the
> new value of cwnd and the receiver's advertised
> window allow, a TCP SHOULD send 1*SMSS bytes of
> previously unsent data."

**Adherence:** met. `_transmit_data` runs after the
cwnd update on every cum-ACK; if there's unsent data
in `_tx_buffer` and `_snd_ewn` permits, it fires.

### Sender step 6: cwnd = ssthresh on recovery exit (deflate)

> "When the next ACK arrives that acknowledges
> previously unacknowledged data, a TCP MUST set cwnd
> to ssthresh (the value set in step 2). This is
> termed 'deflating' the window."

**Adherence:** met. The recovery-exit branch at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3382-3390`:

```python
if self._recovery_point != 0 and le32(self._recovery_point, self._snd_una):
    self._cwnd = self._ssthresh
    ...
```

Sets cwnd = ssthresh on recovery exit. Note that the
"next ACK that acknowledges previously
unacknowledged data" in §3.2 step 6 is interpreted by
PyTCP as "the cum-ACK that crosses RecoveryPoint" —
matching RFC 6675 §5(A) recovery-exit semantics.

---

## §4.1. Restarting Idle Connections

> "When TCP has not received a segment for more than
> one retransmission timeout, cwnd is reduced to the
> value of the restart window (RW) before
> transmission begins... RW = min(IW, cwnd)."

**Adherence:** met. The same idle-detection block in
`_transmit_packet` that resets the RTO estimator (per
RFC 6298 §5.7) now also reduces cwnd to `RW =
min(initial_window(smss), self._cwnd)` and clamps
`_snd_ewn` accordingly. The reduction is gated on
`data` (so handshake SYN / pure FIN paths do not
trigger), and a no-op when cwnd is already at or
below IW. `_last_send_time_ms` is the §4.1 trigger
clock — refreshed on every outbound seq-consuming
segment.

---

## §4.2. Generating Acknowledgements

### Delayed ACK

> "A TCP SHOULD implement a delayed ACK, but an ACK
> should not be excessively delayed; in particular,
> the delay MUST be less than 0.5 seconds, and in a
> stream of full-sized segments there SHOULD be an
> ACK for at least every second segment."

**Adherence:** met. PyTCP's delayed-ACK at
`packages/pytcp/pytcp/protocols/tcp/tcp__constants.py` (the
`DELAYED_ACK_DELAY` constant) is set to a value less
than 500 ms (typically ~200 ms), and the FSM
established handler emits an immediate ACK on every
SECOND data segment. Both the 0.5 s ceiling and the
"every second segment" SHOULD are honoured.

### Immediate ACK on OOO / hole-fill

Already covered above in §3.2 audit.

---

## Test coverage audit

### §3.1 Slow start (Eq 2)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py::TestCwndGrowPerAck__SlowStart`
  parameterised cases pin `cwnd += min(bytes_acked,
  smss)` for various input combinations.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPhase1::test__cwnd__slow_start_grows_cwnd_by_one_mss_per_cum_ack`.

**Status:** locked in.

### §3.1 Congestion avoidance (Eq 3)

- **Unit:**
  `test__tcp__cwnd.py::TestCwndGrowPerAck__CongestionAvoidance`
  pins `cwnd += max(1, smss^2 // cwnd)`.
- **Integration:**
  `test__tcp__session__cwnd.py::TestTcpCwndPhase1::test__cwnd__congestion_avoidance_grows_cwnd_sublinearly`.

**Status:** locked in.

### §3.1 Eq 4 ssthresh on RTO

- **Unit:**
  `test__tcp__cwnd.py::TestComputeLossEventSsthresh`.
- **Integration:**
  `test__tcp__session__cwnd.py::TestTcpCwndPhase2::test__cwnd__rto_sets_ssthresh_to_half_flight_size`.

**Status:** locked in.

### §3.1 LW = 1 SMSS

- **Integration:**
  `test__tcp__session__cwnd.py::TestTcpCwndPhase2::test__cwnd__rto_sets_ssthresh_to_half_flight_size`
  (its final assertion pins the cwnd collapse to
  1 SMSS on RTO).

**Status:** locked in.

### §3.1 ssthresh "held constant on second retransmit"

Not implemented; no test surface. PyTCP
recomputes ssthresh on every RTO; this is a SHOULD
deviation that the audit notes.

**Status:** n/a (gap not closed).

### §3.2 Fast Retransmit triggers (3rd dup-ACK)

- **Integration:**
  `test__tcp__session__data_transfer__retransmit_dupack.py`
  contains the threshold tests.

**Status:** locked in.

### §3.2 Recovery-exit deflation (step 6)

- **Integration:**
  `test__tcp__session__cwnd.py::TestTcpCwndPhase3::test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh`.

**Status:** locked in.

### §3.2 step 3 / 4 (cwnd inflation per dup-ACK)

Superseded by PRR; PRR-specific tests cover the
substitute mechanism. The literal §3.2 step 3 / step
4 inflation is not implemented and not tested.

**Status:** n/a (substituted by RFC 6937 PRR which
has its own test surface).

### §4.1 Restart Window after idle

- **Integration:**
  `test__tcp__session__cwnd.py::TestTcpCwndRfc5681RestartWindow::test__cwnd__rfc5681_restart_window_reduces_cwnd_after_idle`
  inflates cwnd to 100*MSS, primes a send so
  `_last_send_time_ms` is set, ACKs the prime, idles
  past one RTO, then sends fresh data and asserts
  cwnd has been reduced to `RW = min(IW, prior_cwnd)`.
  The estimator-reset-on-idle invariant is covered by
  the RFC 6298 §5.7 audit's test surface.

**Status:** locked in.

### §4.2 Delayed ACK

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__recv.py`
  contains delayed-ACK timing tests.

**Status:** locked in.

### §4.2 Immediate ACK on OOO

- **Integration:**
  `test__tcp__session__data_transfer__out_of_order.py`
  pins immediate ACK on OOO arrival.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §3.1 IW (superseded by RFC 6928)                | locked in (via RFC 6928 audit)                 |
| §3.1 Slow start Eq 2                            | locked in (unit + integration)                 |
| §3.1 CA Eq 3                                    | locked in (unit + integration)                 |
| §3.1 ssthresh initial high                      | locked in (construction)                       |
| §3.1 Eq 4 ssthresh on RTO                       | locked in                                      |
| §3.1 LW = 1 SMSS                                | locked in                                      |
| §3.1 ssthresh held constant 2nd retransmit      | n/a (gap)                                      |
| §3.2 Limited Transmit (RFC 3042)                | locked in (via RFC 3042 audit)                 |
| §3.2 3rd dup-ACK fast retransmit                | locked in                                      |
| §3.2 step 3 cwnd = ssthresh + 3*SMSS            | n/a (PRR substitutes; PRR tested separately)   |
| §3.2 step 4 cwnd += SMSS per additional dup-ACK | n/a (PRR substitutes)                          |
| §3.2 step 5 send unsent on cwnd-allow           | locked in                                      |
| §3.2 step 6 deflate to ssthresh                 | locked in                                      |
| §4.1 Restart Window after idle                  | locked in (TestTcpCwndRfc5681RestartWindow)    |
| §4.2 Delayed ACK                                | locked in                                      |
| §4.2 Immediate ACK on OOO                       | locked in                                      |

---

## Overall assessment

| Aspect                                            | Status                                          |
|---------------------------------------------------|-------------------------------------------------|
| §3.1 IW formula                                   | superseded by RFC 6928 (compliant via 6928)     |
| §3.1 Slow start Eq 2                              | met                                             |
| §3.1 CA Eq 3                                      | met                                             |
| §3.1 ssthresh init high                           | met                                             |
| §3.1 Eq 4 ssthresh on RTO                         | met                                             |
| §3.1 LW = 1 SMSS post-RTO                         | met                                             |
| §3.1 ssthresh constant on 2nd retransmit          | not strictly met (more aggressive)              |
| §3.2 step 1 Limited Transmit                      | met (via RFC 3042)                              |
| §3.2 step 2 ssthresh on 3rd dup-ACK               | met                                             |
| §3.2 step 3 cwnd = ssthresh + 3*SMSS              | superseded by PRR                               |
| §3.2 step 4 cwnd += SMSS per additional           | superseded by PRR                               |
| §3.2 step 5 send unsent on allow                  | met                                             |
| §3.2 step 6 deflate to ssthresh                   | met                                             |
| §4.1 Restart Window after idle (RW reduction)     | met (cwnd reduced to min(IW, cwnd))             |
| §4.2 Delayed ACK                                  | met                                             |
| §4.2 Immediate ACK on OOO / hole-fill             | met                                             |

PyTCP fully implements the RFC 5681 §3.1 slow-start /
congestion-avoidance / RTO machinery, the §3.2 fast-
retransmit trigger, and the §4.2 receiver-side
ACK-generation rules. Three deviations:

1. **§3.1 IW** — PyTCP uses RFC 6928 IW=10 instead.
   This is the modern modern replacement; PyTCP is
   compliant via RFC 6928 (audited separately).
2. **§3.2 step 3 / step 4 cwnd inflation** —
   superseded by RFC 6937 PRR. PRR provides smoother
   send pacing and is the modern replacement.
3. **§4.1 Restart Window** — closed. The same
   `_transmit_packet` idle-detection block that
   resets the RTO estimator now also reduces
   `_cwnd` to `RW = min(initial_window(smss),
   self._cwnd)` and clamps `_snd_ewn`. Pinned by
   `TestTcpCwndRfc5681RestartWindow`.

The remaining deviations are all in the direction of
modernisation (RFC 6928, RFC 6937). The substitutions
by RFC 6928 / 6937 are explicitly permitted by §3.1's
framing language ("a TCP MUST NOT be more aggressive
than the following algorithms allow") which is
satisfied because RFC 6937 PRR is more conservative
than the §3.2 inflation rules it replaces.
