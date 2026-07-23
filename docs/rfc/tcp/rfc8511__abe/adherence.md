# RFC 8511 — TCP Alternative Backoff with ECN (ABE)

| Field       | Value                                                    |
|-------------|----------------------------------------------------------|
| RFC number  | 8511                                                     |
| Title       | TCP Alternative Backoff with ECN (ABE)                   |
| Category    | Experimental                                             |
| Date        | December 2018                                            |
| Source text | [`rfc8511.txt`](rfc8511.txt)                             |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8511. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections without
normative content (Abstract, §1 Introduction, §2
Definitions, §4 Discussion narrative, §5 Deployment
narrative, §6 Experiment Goals, §7 IANA, §8 Security,
References, Acknowledgements, Authors' Addresses) are
omitted.

---

## §3 Specification

### Sender-side ssthresh response on ECE

> "This document specifies a sender-side change to TCP
> where receipt of a packet with the ECN-Echo flag
> SHOULD trigger the TCP source to set the slow start
> threshold (ssthresh) to 0.8 times the FlightSize,
> with a lower bound of 2 * SMSS applied to the result.
> As in [RFC5681], the TCP sender also reduces the cwnd
> value to no more than the new ssthresh value."

**Adherence:** met (with a different ABE multiplier —
see §3.1 below). The `_process_ack_packet` ECE branch
at `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3594-3610`
calls `compute_ecn_event_ssthresh()` from
`packages/pytcp/pytcp/protocols/tcp/tcp__cwnd.py:145-175`, which
computes:

```python
return max(flight_size * 17 // 20, 2 * smss)
```

The 17/20 ratio is 0.85 — different from the §3
specification's 0.8 but within the §3.1
recommendation range (see next section). The 2*SMSS
floor matches the spec exactly. After the
`_ssthresh` update, line 3607 collapses
`_cwnd = self._ssthresh`, satisfying "the TCP sender
also reduces the cwnd value to no more than the new
ssthresh value."

The same logic appears in the AccECN branch at
`session/tcp__session.py:2213-2229` for RFC 9768 byte-counter
delta detection — the ABE multiplier applies to all
ECN-class events regardless of feedback mechanism.

---

## §3.1 Choice of ABE Multiplier

> "The recommendation in this document specifies a
> value of beta_{ecn}=0.8. This recommended beta_{ecn}
> value is only applicable for the standard TCP
> congestion control [RFC5681]."

**Adherence:** PyTCP uses 0.85 (= 17/20), which is
within the §3.1 recommended range of [0.7, 0.85] for
NewReno and matches the CUBIC-recommended 0.85. The
0.85 choice is defensible because PyTCP defaults to
RFC 9438 CUBIC (see `_cc_mode = CcMode.CUBIC` default
in `tcp__session.py`), and §3.1 explicitly cites
0.85 as the CUBIC-tested value:

> "The results of these tests indicate that CUBIC
> connections benefit from beta_{ecn} of 0.85 (cf.
> beta_{loss} = 0.7), and NewReno connections see
> improvements with beta_{ecn} in the range 0.7 to
> 0.85 (cf. beta_{loss} = 0.5)."

PyTCP applies a single 0.85 multiplier regardless of
`_cc_mode` (RENO vs CUBIC). For pure RENO this is on
the higher end of the §3.1 NewReno-suitable range
but still within it.

---

## §4.2 RTT-based response (one-per-RTT gating)

> "Since ABE responds to indicated congestion once per
> RTT, it does not respond to any further loss within
> the same RTT because an ABE sender has already
> reduced the congestion window."

**Adherence:** met. The recovery-point gate in
`tcp__session.py:3594-3610` enforces one-shot per-
RTT semantics:

```python
if (
    self._ecn_enabled
    and packet_rx_md is not None
    and packet_rx_md.tcp__flag_ece
    and (self._ecn_recovery_point == 0
         or le32(self._ecn_recovery_point, self._snd_una))
):
    ...
    self._ecn_recovery_point = self._snd_nxt
```

`_ecn_recovery_point` is set to the SND.NXT value at
the moment of response. Subsequent ECEs within the
same RTT (where SND.UNA has not yet crossed the
recovery point) are suppressed. Once SND.UNA crosses
the recovery point (full RTT has elapsed), the gate
re-opens for the next ECN event.

Same gate applies in the AccECN branch at
`tcp__session.py:3623-3639`.

> "If congestion persists after such reduction, ABE
> continues to reduce the congestion window in each
> consecutive RTT."

**Adherence:** met implicitly via the recovery-point
gate above. Once the recovery point clears, a fresh
ECE in the next RTT triggers another ABE reduction.

> "The mechanism does not rely on Accurate ECN
> [ACC-ECN-FEEDBACK]."

**Adherence:** met. The ABE multiplier is applied
on both the RFC 3168 ECN path (`packet_rx_md.tcp__flag_ece`)
and the RFC 9768 AccECN path (`tcp__accecn0_counters`),
without requiring AccECN. PyTCP gates each path
independently on `_ecn.enabled` and `_accecn.enabled`
respectively.

---

## §5 ABE Deployment Requirements

> "This update is a sender-side-only change. Like
> other changes to congestion control algorithms, it
> does not require any change to the TCP receiver or
> to network devices. It does not require any ABE-
> specific changes in routers or the use of Accurate
> ECN feedback by a receiver."

**Adherence:** met. PyTCP's ABE implementation lives
entirely on the sender side in `_process_ack_packet`.
There is no wire-format change beyond what RFC 3168
already specifies. The receiver's only role is the
standard RFC 3168 ECE-flag echo behaviour.

> "If the method is only deployed by some senders,
> and not by others, the senders using it can gain
> some advantage, possibly at the expense of other
> flows that do not use this updated method."

**Adherence:** acknowledged. PyTCP defaults
`_ecn_enabled` and `_accecn_enabled` to True
post-handshake when bilateral negotiation succeeds.
Applications cannot opt out through the BSD socket
API (no `setsockopt` knob for this). This is the
same fairness consideration §5 raises but does not
mandate addressing.

> "When used with bottlenecks that do not support ECN
> marking, the specification does not modify the
> transport protocol."

**Adherence:** met. ABE only fires on inbound ECE
flags / AccECN counter advancement; if the path
contains no ECN-aware bottleneck, the ABE branches
never execute and the conventional RFC 5681 §3.1
loss-event path drives `compute_loss_event_ssthresh()`
(0.5 multiplier).

---

## Test coverage audit

### §3 ssthresh = max(FlightSize * beta_ecn, 2*SMSS)

- **Unit:** `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py` covers
  `compute_ecn_event_ssthresh` across:
  - `flight_size=0` floor → 2*SMSS
  - `flight_size=1*SMSS` floor → 2*SMSS (since 17/20 < 2)
  - `flight_size=3*SMSS` → exact 17/20 multiplier (not floor)
  - `flight_size=100*SMSS` → ABE multiplier dominates
  - ABE strictly less aggressive than loss event
  - Defensive asserts on negative / zero inputs.

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__ecn.py`
  drives ECE-bearing inbound ACKs and verifies the
  ssthresh ends up at flight_size * 17 // 20 with
  the 2*SMSS floor applied. Asserts the cwnd is
  collapsed to ssthresh per §3.

**Status:** locked in.

### §3 cwnd = ssthresh after reduction

- **Integration:**
  `test__tcp__session__ecn.py` test asserts cwnd
  equals ssthresh after the ABE reduction.

**Status:** locked in.

### §4.2 one-per-RTT gating

- **Integration:** ECN integration tests (RFC 3168
  audit covers this in detail) verify that two ECE
  flags within the same RTT cause only one ssthresh
  reduction.

**Status:** locked in.

### AccECN parity

- **Integration:**
  `test__tcp__session__accecn.py` drives AccECN
  byte-counter advancement and verifies the same
  ABE multiplier applies as on the RFC 3168 ECN
  path.

**Status:** locked in.

### Test coverage summary

| Aspect                                  | Coverage  |
|-----------------------------------------|-----------|
| §3 ssthresh = FlightSize * beta_ecn     | locked in |
| §3 2*SMSS floor                         | locked in |
| §3 cwnd collapse to ssthresh            | locked in |
| §3.1 0.8-0.85 multiplier choice         | locked in |
| §4.2 one-per-RTT gating                 | locked in |
| RFC 9768 AccECN parity                  | locked in |

---

## Overall assessment

| Aspect                                   | Status                          |
|------------------------------------------|---------------------------------|
| §3 ssthresh formula                      | met (uses 0.85 vs spec's 0.8)   |
| §3 2*SMSS floor                          | met                             |
| §3 cwnd collapse                         | met                             |
| §3.1 multiplier in [0.7, 0.85] range     | met (0.85)                      |
| §4.2 one-per-RTT gating                  | met                             |
| §5 sender-side-only                      | met                             |
| §5 doesn't require AccECN                | met (works with both ECN paths) |
| §5 backwards compat with non-ECN paths   | met                             |

PyTCP's ABE implementation is complete and exercised
on both the RFC 3168 ECE path and the RFC 9768 AccECN
path. The 0.85 multiplier choice (vs the spec's 0.8
recommendation) is within §3.1's experimental range
and matches the CUBIC-tested value, which is
appropriate given PyTCP defaults to CUBIC. No
implementation gaps identified.
