# RFC 7661 — Updating TCP to Support Rate-Limited Traffic (New CWV)

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 7661                                               |
| Title       | Updating TCP to Support Rate-Limited Traffic       |
| Category    | Experimental                                       |
| Date        | October 2015                                       |
| Obsoletes   | RFC 2861                                           |
| Source text | [`rfc7661.txt`](rfc7661.txt)                       |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 7661.

---

## Top-line adherence

PyTCP has **zero New CWV support**. A grep across
`packages/pytcp/pytcp/`, `packages/net_proto/net_proto/`, and `packages/net_addr/net_addr/` returns no
references to CWV, pipeACK, NVP, validated capacity,
or any RFC 7661 identifier.

PyTCP does implement RFC 6298 §5.7 idle reset (audited
under `rfc6298__rto_computation/adherence.md`) — the
closest mechanism in PyTCP that handles the "idle then
resume" case. PyTCP's idle behaviour is the
conservative RFC 6298 §5.7 reset to initial RTO state
on idle longer than RTO; what it does NOT implement is
the RFC 7661 CWV cwnd-preservation across rate-limited
periods.

---

## §4 New Congestion Window Validation Method — Gaps

### §4.2 Estimating Validated Capacity (pipeACK)

> "An implementation MUST measure pipeACK as the
> volume of acknowledged data divided by the time
> period required to acknowledge it."

**Adherence:** not implemented. PyTCP does not
maintain a pipeACK estimator.

### §4.3 Preserving cwnd during a Rate-Limited Period

> "When the application is sending less than its cwnd
> allows, the sender SHOULD preserve cwnd for a
> bounded period (the 'Non-Validated Period' or NVP)
> rather than reduce it via the conventional CWV
> behavior."

**Adherence:** not implemented.

### §4.4 Congestion Control during the Non-validated Phase

> "When in the non-validated phase, on a congestion
> event the sender reduces cwnd to half of the
> pipeACK estimate (rather than to half of the
> conventional cwnd)."

**Adherence:** not implemented.

### §4.4.2 Sender Burst Control

**Adherence:** not implemented.

### §4.4.3 Adjustment at the End of NVP

**Adherence:** not implemented.

---

## §5 Determining a Safe Period

> "The NVP duration is bounded by an interval such
> that the path's properties have not significantly
> changed."

**Adherence:** not implemented.

---

## Test coverage audit

No CWV-related tests exist.

### Test coverage summary

| Aspect                                  | Coverage  |
|-----------------------------------------|-----------|
| §4.2 pipeACK measurement                | n/a (gap) |
| §4.3 cwnd preservation during NVP       | n/a (gap) |
| §4.4.1 NVP-phase congestion response    | n/a (gap) |
| §4.4.2 burst control                    | n/a (gap) |
| §5 NVP duration bound                   | n/a (gap) |

---

## Overall assessment

| Aspect                                  | Status          |
|-----------------------------------------|-----------------|
| §4.2 pipeACK measurement                | not implemented |
| §4.3 cwnd preservation during NVP       | not implemented |
| §4.4.1 NVP-phase congestion response    | not implemented |
| §4.4.2 sender burst control             | not implemented |
| §4.4.3 NVP exit adjustment              | not implemented |
| §5 NVP safe-period bound                | not implemented |

PyTCP does not implement RFC 7661 New CWV. Rate-
limited applications using PyTCP will see cwnd
reset behavior per RFC 6298 §5.7 (idle longer than
RTO) which forces a fresh slow-start when the
application resumes. This is conservative but
correct; it does not benefit from the "preserve
cwnd if validated" heuristic RFC 7661 introduces.

The simpler RFC 5681 idle-reset behavior at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:_transmit_packet`
guarded by `_last_send_time_ms` is what's
implemented. RFC 7661 is a refinement that requires
significant new state (pipeACK / NVP / NVP-aware
cwnd reduction).

Implementing this would require:
- A pipeACK estimator (windowed average of bytes-
  acked / interval).
- An "is-cwnd-limited" detector (cwnd vs flightsize).
- An NVP timer that gates the §4.4.1 alternative
  cwnd-reduction formula.
- An §4.4.2 burst limiter.

Estimated effort: ~6-8 commits.
