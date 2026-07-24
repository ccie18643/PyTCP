# RFC 8961 — Requirements for Time-Based Loss Detection

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 8961                                           |
| Title       | Requirements for Time-Based Loss Detection     |
| Category    | Best Current Practice (BCP 233)                |
| Date        | November 2020                                  |
| Source text | [`rfc8961.txt`](rfc8961.txt)                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8961. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§2 Context, §3 Scope statements (S.1)–(S.4), §5
Discussion, §6 Security Considerations boilerplate,
§7 IANA Considerations, References) are omitted.

RFC 8961 is a protocol-agnostic BCP whose requirements
apply to any "primary or last-resort time-based loss
detection mechanism". For PyTCP the mechanism in
question is the RFC 6298 RTO; this audit cross-checks
that PyTCP's RTO meets the §4 BCP requirements.

---

## §4. Requirements

### Requirement (1) — Initial RTO ≥ 1 second

> "In the absence of any knowledge about the latency of
> a path, the initial RTO MUST be conservatively set to
> no less than 1 second."

**Adherence:** met. The RTO module defines
`INITIAL_RTO_MS = 1000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:66`) with an inline
citation of both RFC 6298 §2.1 and RFC 8961. The
`initial_state()` factory at line 115 returns
`RtoState(srtt_ms=None, rttvar_ms=None,
rto_ms=INITIAL_RTO_MS)`, so a fresh session's RTO
starts at exactly 1 second before any RTT sample
arrives. The `MIN_RTO_MS = 1000` clamp at line 69
ensures the first sample cannot drive RTO below 1 s
either.

### Requirement (2)(a) — RTO based on multiple FT samples

> "The RTO SHOULD be set based on multiple observations
> of the FT when available... For example, TCP's RTO
> [RFC6298] would satisfy this requirement due to its
> use of an exponentially weighted moving average
> (EWMA) to combine multiple FT samples into a
> 'smoothed RTT'."

**Adherence:** met. The `update()` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:126-157` implements
the canonical RFC 6298 §2.3 EWMA:

```python
rttvar = ((BETA_DEN - BETA_NUM) * state.rttvar_ms + BETA_NUM * abs(state.srtt_ms - sample_ms)) // BETA_DEN
srtt = ((ALPHA_DEN - ALPHA_NUM) * state.srtt_ms + ALPHA_NUM * sample_ms) // ALPHA_DEN
rto = srtt + max(CLOCK_GRANULARITY_MS, K * rttvar)
```

with `α = 1/8` (line 87-88) and `β = 1/4` (line 92-93)
matching RFC 6298 exactly. Multiple samples are
combined; the variance term `K * rttvar` is included
per RFC 6298's "TCP goes further to also include an
explicit variance term" — the §4(a) commentary
explicitly endorses this stronger form.

### Requirement (2)(b) — Sample at least once per RTT

> "FT observations SHOULD be taken and incorporated
> into the RTO at least once per RTT or as frequently
> as data is exchanged in cases where that happens
> less frequently than once per RTT."

**Adherence:** met. PyTCP samples once per RTT via the
`_rtt_sample_seq` / `_rtt_sample_send_time_ms` /
`_rtt_sample_retransmitted` triple
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:570-586`). When
RFC 7323 timestamps are bilateral, the more aggressive
once-per-ACK timestamp-based sampling kicks in (audited
under the RFC 7323 adherence record); both modes
satisfy "at least once per RTT".

### Requirement (2)(c) — FT MAY be from non-data exchanges

> "FT observations MAY be taken from non-data
> exchanges."

**Adherence:** the MAY is permissive. PyTCP currently
takes FT samples only from data + ACK exchanges; the
SYN+ACK handshake provides the first sample (counted
as a "data exchange" because the SYN consumes a
sequence-number byte). Keep-alive probes and zero-
window persist probes do NOT produce FT samples in
PyTCP — but the MAY does not require them to.

### Requirement (2)(d) — RTO MUST NOT use ambiguous FT samples

> "An RTO mechanism MUST NOT use ambiguous FT samples
> ... in this situation, an implementation MUST NOT use
> either version of the FT sample and hence not update
> the RTO (as discussed in [KP87] and [RFC6298])."

**Adherence:** met. PyTCP implements Karn's algorithm
(RFC 6298 §3) via the `_rtt_sample_retransmitted` flag
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:586`). When a
segment carrying an in-flight RTT sample is
retransmitted, the flag is set; the sample-harvest
path in `_process_ack_packet` skips the `update()` call
when the flag is True, leaving SRTT / RTTVAR unchanged
until a fresh non-retransmitted sample arrives. This is
exactly the §2(d) MUST NOT.

When RFC 7323 timestamps are bilateral, the §4(d)
commentary's exception ("TCP's timestamp option
[RFC7323] allows for packets to be uniquely identified
and hence avoid the ambiguity") applies: the TSecr
field disambiguates which copy was acknowledged, so
samples from retransmitted segments are usable. PyTCP's
RFC 7323 implementation (audited separately) honours
this.

### Requirement (3) — Loss detected by RTO MUST trigger CC adaptation

> "Loss detected by the RTO mechanism MUST be taken as
> an indication of network congestion and the sending
> rate adapted using a standard mechanism (e.g., TCP
> collapses the congestion window to one packet
> [RFC5681])."

**Adherence:** met. The RTO timeout handler at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:_retransmit_packet_timeout`
(line 2540 area) collapses cwnd to 1 SMSS via:

```python
self._cwnd = self._snd_mss
```

(line 2672) and halves ssthresh via
`compute_loss_event_ssthresh` (line 2666) for the Reno
path or `cubic_loss_event_ssthresh` (RFC 9438 §4.6
beta_cubic = 0.7) for the CUBIC path. Both responses
satisfy "the sending rate adapted using a standard
mechanism".

The §4(3) exception ("an IETF standardized mechanism
determines that a particular loss is due to a
non-congestion event") applies to RFC 5682 F-RTO,
which PyTCP also implements (audited under the
RFC 6298 record). When F-RTO determines an RTO was
spurious, the cwnd / ssthresh restoration path
reverses the congestion control action — exactly the
§4(3) commentary's "post facto" reversal.

### Requirement (4) — Exponential backoff on every RTO use

> "Each time the RTO is used to detect a loss, the
> value of the RTO MUST be exponentially backed off
> such that the next firing requires a longer
> interval."

**Adherence:** met. The `back_off()` function at
`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:160-174` doubles
`rto_ms` and clamps to `MAX_RTO_MS`:

```python
return RtoState(
    srtt_ms=state.srtt_ms,
    rttvar_ms=state.rttvar_ms,
    rto_ms=min(state.rto_ms * 2, MAX_RTO_MS),
)
```

The `_retransmit_packet_timeout` handler invokes
`back_off()` on every RTO firing. SRTT and RTTVAR are
preserved (Karn's algorithm again — they cannot be
updated from a retransmit, but the RTO doubles to
provide more space for the path to recover).

### Requirement (4) — Backoff SHOULD be removed after successful tx

> "The backoff SHOULD be removed after either (a) the
> subsequent successful transmission of non-
> retransmitted data, or (b) an RTO passes without
> detecting additional losses."

**Adherence:** met. The next non-retransmitted RTT
sample folds through `update()` and produces a fresh
RTO from SRTT + K*RTTVAR (no carry-over of the
backoff). This corresponds to alternative (a). The
mechanism is implicit in the `update()` function's
formula: it does not consult the prior `rto_ms` when
computing the new value, so any prior backoff is
naturally discarded.

Alternative (b) — "an RTO passes without detecting
additional losses" — is not specifically implemented
as a separate path; if a backed-off RTO fires without
new loss being detected (which would be unusual), the
back_off path runs again and doubles further. PyTCP
relies on (a) being the common case.

### Requirement (4) — Maximum RTO

> "A maximum value MAY be placed on the RTO. The
> maximum RTO MUST NOT be less than 60 seconds (as
> specified in [RFC6298])."

**Adherence:** met. `MAX_RTO_MS = 60_000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__rto.py:73`) — exactly the
60-second floor specified by §4(4) and RFC 6298 §2.5.
The clamp is applied both in `update()` (via
`clamp_rto`) and in `back_off()` (via the explicit
`min(... * 2, MAX_RTO_MS)`).

---

## Test coverage audit

### Requirement (1) — Initial RTO = 1 s

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__rto.py::TestRtoInitialState::test__rto__initial_state__rto_is_initial_rto_ms`
  pins `initial_state().rto_ms == INITIAL_RTO_MS`.
- **Unit:** `test__rto__initial_rto_is_1_second`
  pins the constant value.
- **Integration:** every handshake test that fires the
  first SYN-ack RTT sample asserts the post-sample
  `rto_ms` is at or above 1 s.

**Status:** locked in.

### Requirement (2)(a) — Multiple FT samples / EWMA

- **Unit:** `test__tcp__rto.py::TestRtoUpdateFirstSample`
  and `TestRtoUpdateSubsequentSample` contain tests
  covering the first-sample case, subsequent-sample EWMA
  with various sample-vs-SRTT deltas, and the variance
  term contribution.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py`
  exercises the EWMA across multiple ACKs.

**Status:** locked in.

### Requirement (2)(b) — At least once per RTT

- **Integration:** the once-per-RTT cadence is pinned
  by RTO integration tests that drive multi-segment
  transfers and assert `_rto_state.rto_ms` updates on
  each new sample.

**Status:** locked in.

### Requirement (2)(c) — Non-data exchanges (MAY)

Not implemented as a separate path; no test surface.
The MAY is permissive, so absence is conformant.

### Requirement (2)(d) — Karn's algorithm (no ambiguous samples)

- **Unit:** `test__tcp__rto.py::TestRtoUpdateFirstSample`
  and `TestRtoUpdateSubsequentSample` include cases
  where the helper is called only with non-tainted
  samples (the function itself is unconditional).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py::TestTcpRtoSampling::test__rto__retransmit_marks_pending_sample_as_karn_tainted`
  and
  `test__rto__ack_of_karn_tainted_sample_clears_but_does_not_update_state`
  pin the Karn skip path: a retransmit sets the
  taint flag, the harvest skips `update()`, SRTT /
  RTTVAR remain unchanged.

**Status:** locked in.

### Requirement (3) — RTO triggers CC adaptation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPhase2::test__cwnd__rto_sets_ssthresh_to_half_flight_size`
  pins both the cwnd → 1 SMSS collapse and the ssthresh
  halving on RTO.
- **Integration (CUBIC):**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py::TestTcpCubicPhase3::test__cubic__rto_uses_beta_cubic`
  pins the CUBIC mode's beta_cubic = 0.7 ssthresh
  reduction.

**Status:** locked in (both Reno and CUBIC paths).

### Requirement (4) — Exponential backoff

- **Unit:** `test__tcp__rto.py::TestRtoBackOff` covers
  the doubling logic and the MAX_RTO_MS clamp.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py::TestTcpRtoRetransmitTimer::test__rto__retransmit_timeout_backs_off_rto_state`
  drives an RTO and asserts `rto_ms` doubles.

**Status:** locked in.

### Requirement (4) — Backoff removed after success

- **Indirect:** the `update()` formula does not
  consult prior `rto_ms`, so any backed-off value is
  naturally replaced by the next sample's
  SRTT + K*RTTVAR. The `update` unit tests pin this
  behaviour: after `back_off`, calling `update` with
  a fresh sample yields a value derived from SRTT /
  RTTVAR, not from the backed-off `rto_ms`.

**Status:** locked in indirectly.

### Requirement (4) — Max RTO ≥ 60 s

- **Unit:** `test__tcp__rto.py::test__rto__max_rto_is_at_least_60_seconds`
  pins the constant.
- **Unit:** `TestRtoBackOff::test__rto__back_off__caps_at_max_rto`
  pins the clamp behaviour.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                              |
|-------------------------------------------------|---------------------------------------|
| (1) Initial RTO ≥ 1 s                           | locked in                             |
| (2)(a) Multiple FT samples / EWMA               | locked in                             |
| (2)(b) Sample at least once per RTT             | locked in                             |
| (2)(c) Non-data exchanges (MAY)                 | n/a (not implemented; MAY allows)     |
| (2)(d) Karn's algorithm                         | locked in                             |
| (3) RTO triggers CC adaptation                  | locked in (Reno + CUBIC)              |
| (4) Exponential backoff                         | locked in                             |
| (4) Backoff removed after success               | locked in indirectly                  |
| (4) Max RTO ≥ 60 s                              | locked in                             |

---

## Overall assessment

| Aspect                                          | Status   |
|-------------------------------------------------|----------|
| (1) Initial RTO ≥ 1 s                           | met      |
| (2)(a) Multiple FT samples / EWMA               | met      |
| (2)(b) Sample at least once per RTT             | met      |
| (2)(c) Non-data exchanges (MAY)                 | not used (MAY permits) |
| (2)(d) Karn's algorithm                         | met      |
| (3) RTO triggers CC adaptation                  | met      |
| (4) Exponential backoff                         | met      |
| (4) Backoff removal after success               | met (implicit via `update`) |
| (4) Max RTO ≥ 60 s                              | met      |

PyTCP fully meets every RFC 8961 requirement. The
underlying RFC 6298 RTO machinery satisfies the BCP's
high-level requirements as RFC 8961 §4(2)(a) explicitly
acknowledges ("TCP's RTO [RFC6298] would satisfy this
requirement"). PyTCP's additional support for RFC 7323
timestamp-based RTT sampling provides the §4(2)(d)
"unambiguous sample" advantage when negotiated, and the
RFC 9438 CUBIC integration provides a second standards-
compliant CC adaptation path on top of the Reno default.
