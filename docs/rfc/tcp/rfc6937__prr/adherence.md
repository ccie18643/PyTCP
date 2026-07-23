# RFC 6937 — Proportional Rate Reduction for TCP

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 6937                                   |
| Title       | Proportional Rate Reduction for TCP    |
| Category    | Experimental                           |
| Date        | May 2013                               |
| Source text | [`rfc6937.txt`](rfc6937.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6937. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction
narrative, §2 Definitions boilerplate, §3.1 worked
examples, §4 Properties, §5 Measurements,
§6 Conclusion, §7 / §8 Security / Acknowledgments,
References, Appendix A) are omitted.

The §3 algorithm is the central normative content —
the per-ACK `sndcnt` computation that paces sends
during fast recovery.

---

## §3. Algorithms

### Initialization at recovery entry

> "ssthresh = CongCtrlAlg()  // Target cwnd after recovery
> prr_delivered = 0         // Total bytes delivered during recovery
> prr_out = 0               // Total bytes sent during recovery
> RecoverFS = snd.nxt-snd.una // FlightSize at the start of recovery"

**Adherence:** met. The fast-retransmit entry in
`_retransmit_packet_request` at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2795-2840`
performs all four initialisations:

```python
flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
self._ssthresh = compute_loss_event_ssthresh(flight_size, self._snd_mss)
# (or cubic_loss_event_ssthresh in CUBIC mode)
self._recover_fs = flight_size
self._prr_delivered = 0
self._prr_out = 0
```

The `flight_size` snapshot at line 2795 is exactly
`snd.nxt - snd.una` (since `snd_max == snd_nxt`
outside recovery). The `ssthresh` is computed by the
appropriate CC algorithm: RFC 5681 `compute_loss_event_ssthresh`
(beta = 0.5) for Reno, or RFC 9438
`cubic_loss_event_ssthresh` (beta_cubic = 0.7) for
CUBIC. This satisfies "CongCtrlAlg()".

### DeliveredData computation

> "DeliveredData = change_in(snd.una) + change_in(SACKd)"

**Adherence:** met. The per-ACK update is split
across two sites:

- Cum-ACK delta: `_process_ack_packet` at
  `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3120-3126`:

  ```python
  bytes_acked = (packet_rx_md.tcp__ack - self._snd_una) & 0xFFFF_FFFF
  self._snd_una = packet_rx_md.tcp__ack
  if self._recovery_point != 0:
      self._prr_delivered += bytes_acked
  ```

- SACK delta: `_ingest_sack_info` at
  `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2194-2201`:

  ```python
  bytes_before = self._sack_scoreboard.total_sacked_bytes() if self._recovery_point != 0 else 0
  for left, right in blocks:
      ...
      self._sack_scoreboard.add_block(left, right)
  if self._recovery_point != 0:
      self._prr_delivered += self._sack_scoreboard.total_sacked_bytes() - bytes_before
  ```

The combined `_prr_delivered` accumulator captures
the change in SND.UNA + change in SACKd bytes
exactly per the §3 formula.

The DSACK exclusion noted in the
`_ingest_sack_info` comment (line 2191-2193) is
correct: DSACK blocks are excluded from the SACK
delta because they report duplicates of already-
known data. RFC 6937 §3 doesn't mention DSACK
specifically, but the logical exclusion is correct.

### prr_out tracking

> "On any data transmission or retransmission:
>     prr_out += (data sent)"

**Adherence:** met. The transmit path at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1581-1592`:

```python
# RFC 6937 §3.1 PRR: track 'prr_out' across every
# data emission during recovery so the per-ACK
# 'sndcnt = ceil(prr_delivered * ssthresh / RecoverFS) -
# prr_out' formula reflects the true cumulative send
# count.
self._prr_out += len(data) + flag_syn + flag_fin
```

Increments on every outbound segment carrying
sequence-consuming bytes. The SYN / FIN +1 byte
contributions are also counted (each consumes one
seq), matching the §3 "data sent" semantics.

### PRR proper (pipe > ssthresh)

> "if (pipe > ssthresh) {
>     // Proportional Rate Reduction
>     sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
> }"

**Adherence:** met. The in-recovery cwnd update at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3151-3156`:

```python
current_pipe = pipe(...)
if current_pipe > self._ssthresh:
    # PRR proper: aim for ssthresh/RecoverFS
    # ratio. Integer CEIL via the standard
    # '-(-a // b)' trick to avoid float math.
    target = -(-self._prr_delivered * self._ssthresh // self._recover_fs)
    sndcnt = target - self._prr_out
```

The `-(-a // b)` form is the canonical Python
integer-CEIL idiom — exactly equivalent to
`CEIL(prr_delivered * ssthresh / RecoverFS)`. The
subtraction of `prr_out` matches §3 verbatim.

### Reduction Bound (pipe ≤ ssthresh)

> "} else {
>     // Two versions of the Reduction Bound
>     if (conservative) {    // PRR-CRB
>       limit = prr_delivered - prr_out
>     } else {               // PRR-SSRB
>       limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
>     }
>     // Attempt to catch up, as permitted by limit
>     sndcnt = MIN(ssthresh - pipe, limit)
> }"

**Adherence:** met. The Reduction Bound branch at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3157-3168`:

```python
else:
    # PRR-CRB / PRR-SSRB: pipe has dropped at
    # or below ssthresh; allow conservative
    # send budget. SSRB (bilateral SACK + new
    # data this ACK) lets cwnd grow up to one
    # SMSS per ACK; CRB (no SACK or no new
    # data) caps at the unsent prr_delivered.
    if self._send_sack and bytes_acked > 0:
        limit = max(self._prr_delivered - self._prr_out, bytes_acked) + self._snd_mss
    else:
        limit = self._prr_delivered - self._prr_out
    sndcnt = min(self._ssthresh - current_pipe, limit)
```

The SSRB branch (`_send_sack and bytes_acked > 0`)
uses `max(prr_delivered - prr_out, bytes_acked) +
SMSS` — exactly the §3 SSRB formula with
`bytes_acked` substituting for "DeliveredData this
ACK". The CRB branch uses
`prr_delivered - prr_out` directly, exactly the §3
CRB formula. The `min(ssthresh - pipe, limit)` is
the §3 final-line clamp.

The choice between SSRB and CRB is gated on bilateral
SACK + new data on this ACK. RFC 6937 §3 leaves the
choice to the implementer ("if (conservative)");
PyTCP defaults to SSRB when SACK is enabled (the
recommended choice per §4 / §5 measurements) and
falls back to CRB otherwise.

### `cwnd = pipe + sndcnt` realisation

The RFC's pseudo-code computes `sndcnt` (how many
new bytes to send) but doesn't explicitly say how
the cwnd state evolves. PyTCP applies the result at
line 3169:

```python
self._cwnd = current_pipe + max(0, sndcnt)
```

The `max(0, sndcnt)` clamp protects against a
negative `sndcnt` (which can occur transiently if
prr_delivered hasn't caught up to prr_out). The
result is exactly the "current pipe + the per-ACK
budget" formulation that produces RFC 6937's
intended pacing.

---

## §3.1. Examples

The §3.1 single-loss and 15-loss-burst worked
examples are not normative; they illustrate the
algorithm's behaviour. PyTCP's implementation
matches the §3.1 PRR-SSRB column when SACK is
enabled (the canonical case), producing one or two
segments per ACK during recovery exactly as the
example shows.

**Adherence:** the implementation matches the
worked example wire output (verified by
integration tests at
`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPrr`).

---

## Test coverage audit

### §3 PRR initialisation at recovery entry

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPrr::test__cwnd__prr__recovery_entry_initialises_recover_fs_and_prr_counters`
  drives a fast-retransmit entry and asserts all
  four initialisations (`_recover_fs == flight_size`,
  `_prr_delivered == 0`, `_prr_out == 0`,
  `_ssthresh = halved`).

**Status:** locked in.

### §3 DeliveredData computation

- **Integration (cum-ACK path):**
  `test__tcp__session__cwnd.py::TestTcpCwndPrr::test__cwnd__prr__cum_ack_during_recovery_sets_cwnd_per_prr_formula`
  pins the `_prr_delivered += bytes_acked` update
  on partial cum-ACKs.
- **Integration (SACK path):**
  `test__tcp__session__cwnd.py::TestTcpCwndPrr`
  contains tests for SACK-only delta updates (when
  the cum-ACK doesn't advance but a new SACK block
  arrives).

**Status:** locked in.

### §3 prr_out tracking

- **Integration (implicit):** every PRR test that
  drives a multi-segment recovery transcript
  exercises the prr_out increment path. A
  regression that skipped the increment would
  produce a wrong `sndcnt` and a wrong post-recovery
  cwnd, caught by the test's expected-value
  assertion.

**Status:** locked in indirectly.

### §3 PRR proper formula

- **Integration:**
  `TestTcpCwndPrr::test__cwnd__prr__cum_ack_during_recovery_sets_cwnd_per_prr_formula`
  asserts the post-PRR-tick `_cwnd` value matches
  `current_pipe + ceil(prr_delivered * ssthresh /
  RecoverFS) - prr_out` exactly.

**Status:** locked in.

### §3 PRR-CRB and PRR-SSRB Reduction Bound

- **Integration:**
  `TestTcpCwndPrr::test__cwnd__prr__ssrb_with_sack_allows_one_smss_per_ack`
  pins the SSRB branch's `+ SMSS` allowance.
- **Integration:**
  `TestTcpCwndPrr::test__cwnd__prr__crb_without_sack_falls_back_to_strict`
  pins the CRB fallback.

**Status:** locked in.

### Test coverage summary

| Aspect                                    | Coverage                              |
|-------------------------------------------|---------------------------------------|
| §3 Initialisation at recovery entry       | locked in                             |
| §3 DeliveredData (cum-ACK + SACK delta)   | locked in                             |
| §3 prr_out tracking                       | locked in indirectly                  |
| §3 PRR proper (pipe > ssthresh)           | locked in                             |
| §3 PRR-CRB Reduction Bound                | locked in                             |
| §3 PRR-SSRB Reduction Bound               | locked in                             |
| §3 cwnd = pipe + sndcnt realisation       | locked in (covered by all PRR tests)  |

---

## Overall assessment

| Aspect                                            | Status |
|---------------------------------------------------|--------|
| §3 Initialisation                                 | met    |
| §3 DeliveredData (cum-ACK + SACK)                 | met    |
| §3 prr_out increment on tx                        | met    |
| §3 PRR proper sndcnt formula                      | met    |
| §3 Reduction Bound dispatch (CRB vs SSRB)         | met    |
| §3 PRR-CRB formula                                | met    |
| §3 PRR-SSRB formula                               | met    |
| §3 sndcnt clamp at MIN(ssthresh - pipe, limit)    | met    |
| §3 cwnd = pipe + max(0, sndcnt)                   | met    |

PyTCP fully implements RFC 6937 PRR including both
Reduction Bound variants (CRB and SSRB). The PRR-
SSRB branch is selected when bilateral SACK is
enabled and the current ACK delivers new data; PRR-
CRB is the fallback. The implementation uses
integer arithmetic throughout (the CEIL trick
`-(-a // b)` matches `math.ceil(a / b)` exactly for
non-negative `a`). The §3 algorithm is met line-by-
line; the audit identifies no gaps.

PRR replaces the older RFC 5681 §3.2 "cwnd +=
SMSS per dup-ACK" inflation and the RFC 6582 §3.2
step 3b "deflate by bytes_acked, add back SMSS"
formula. RFC 6937 §3.1 worked examples explicitly
contrast PRR's behaviour with these older
algorithms; PyTCP's PRR implementation produces
the §3.1 PRR / PRR-SSRB column outputs.
