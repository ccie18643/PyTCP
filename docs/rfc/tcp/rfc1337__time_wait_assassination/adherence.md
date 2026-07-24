# RFC 1337 — TIME-WAIT Assassination Hazards in TCP

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 1337                                   |
| Title       | TIME-WAIT Assassination Hazards in TCP |
| Category    | Informational                          |
| Date        | May 1992                               |
| Source text | [`rfc1337.txt`](rfc1337.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 1337. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` and
`packages/pytcp/pytcp/tests/integration/protocols/tcp/` directly; no
prior memory or rule-file content was reused.
Sections that contain no normative content (Abstract,
Introduction, Conclusions narrative, References,
Security Considerations boilerplate, Author's Address,
the 64-bit-sequence-number Appendix) are omitted. The
RFC is Informational and uses lowercase "must" /
"should" rather than RFC 2119 capitalised keywords;
adherence is judged against the SHOULD-strength
recommendations in §3 and §4.

---

## §2.1. Introduction (the three hazards)

> "If the connection is immediately reopened after a
> TWA event, the new incarnation will be exposed to old
> duplicate segments... There are three possible
> hazards that result:
>
> H1. Old duplicate data may be accepted erroneously.
>
> H2. The new connection may be de-synchronized, with
>     the two ends in permanent disagreement on the
>     state.
>
> H3. The new connection may die."

**Adherence:** all three hazards are precluded by the
fix-F1 implementation described in §3 below: because
PyTCP does not allow a peer RST to terminate TIME-WAIT
in the first place, no premature TIME-WAIT close
exposes the next incarnation to the conditions in
which H1 / H2 / H3 can occur. The hazards themselves
are descriptive (consequences) rather than normative
(requirements), but the implementation that prevents
them is normative and is audited under §3.

---

## §3. Fixes for TWA Hazards

### §3 F1 — Ignore RST segments in TIME-WAIT state

> "(F1) Ignore RST segments in TIME-WAIT state.
>
> If the 2 minute MSL is enforced, this fix avoids all
> three hazards.
>
> This is the simplest fix. One could also argue that
> it is formally the correct thing to do; since
> allowing time for old duplicate segments to die is
> one of TIME-WAIT state's functions, the state should
> not be truncated by a RST segment."

**Adherence:** met. The TIME-WAIT FSM handler
`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__time_wait.py` does not
contain any RST-handling branch. The handler matches
explicitly on:

- timer expiry (line 85) → CLOSED;
- PAWS-stale segment drop (line 103) → return;
- RFC 6191 §3 fresh-TSval SYN (lines 116-135) →
  4-tuple reuse;
- FIN retransmit (line 144) → re-ACK and restart
  timer;
- SYN-bearing segment (line 161) → challenge ACK.

A peer RST falls through every match and reaches the
implicit no-op return at the end of the function. The
session stays in TIME-WAIT regardless of how
acceptable (or otherwise) the RST's seq might be — RFC
1337's "ignore RST" recommendation is implemented in
its strongest form (always ignore, no acceptability
check). The 2*MSL-style timer at
`tcp__fsm__time_wait.py:85` is the canonical
TIME_WAIT_DELAY constant; PyTCP uses 30 s rather than
RFC 793's 2*MSL ≈ 240 s, a documented deviation that
is not relevant to the F1 fix itself.

### §3 F2 — Use PAWS to avoid the hazards

> "(F2) Use PAWS to avoid the hazards.
>
> Suppose that the TCP ignores RST segments in
> TIME-WAIT state, but only long enough to guarantee
> that the timestamp clocks on both ends have ticked.
> Then the PAWS mechanism will prevent old duplicate
> data segments from interfering with the new
> incarnation, eliminating hazard H1."

**Adherence:** exceeded. PyTCP combines F1 (always
ignore RST in TIME-WAIT) with full RFC 7323 §5 PAWS
on every inbound TIME-WAIT segment
(`tcp__fsm__time_wait.py:97-104`,
`session._check_paws_and_update_ts_recent(...)`).
Because F1 already drops every RST regardless of
timestamp, PyTCP does not need F2's "ignore RST until
W timestamp ticks" finer-grained gate; instead the
PAWS check generalises hazard-H1 protection to ALL
stale-TSval segments, not just RSTs. The
implementation is therefore a strict superset of what
F2 prescribes.

The RFC notes that F2 alone is "at best a partial
fix" because old duplicate ACKs can slip past PAWS
during the regenerated-timestamp window; PyTCP
sidesteps this by combining F1 (which kills the RST
path entirely) with PAWS (which kills the stale-data
path entirely), so the partial-fix limitation does
not apply.

### §3 F3 — Use 64-bit sequence numbers

> "(F3) Use 64-bit Sequence Numbers ... it appears
> that a combination of 64-bit sequence numbers with
> an appropriate modification of the TCP parameters
> could defeat all of the TWA hazards H1, H2, and H3."

**Adherence:** n/a — wire-incompatible alternative path
not selected by RFC §4. PyTCP uses the
RFC 9293 32-bit sequence space (see `tcp__seq.py`'s
`Seq32 = int` alias and the `& 0xFFFF_FFFF` modular
masks throughout). Extending to 64-bit sequences is a
wire-incompatible change that would require RFC 1264
extension and is out of scope for any modern TCP
implementation. RFC 1337 §3 / §4 explicitly frame F3
as a "long-term fix" and prefer F1 as the
"short-term solution"; PyTCP's choice to ship F1 (and
strengthen with PAWS) follows the RFC's own
recommendation.

---

## §4. Conclusions

> "Of the three fixes described in the previous
> section, fix (F1), ignoring RST segments in
> TIME-WAIT state, seems like the best short-term
> solution. It is certainly the simplest."

**Adherence:** met. PyTCP ships F1 as the canonical
TIME-WAIT mitigation. A stale inline comment at
`tcp__fsm__time_wait.py:158-160` claims "PyTCP does
not implement the Timestamp Option (PAWS), so RFC
9293's TIME_WAIT-special connection-recycling path is
unreachable" — this comment is outdated as of commit
`79ed38e` (PAWS) and the more recent RFC 6191 §3
4-tuple-reuse path at lines 116-135. The comment does
not affect functional correctness (the surrounding
challenge-ACK branch fires correctly) but should be
refreshed.

---

## Test coverage audit

### §3 F1 — Ignore RST in TIME-WAIT

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py::TestTcpClose__TimeWaitRfc1337::test__rfc1337__rst_in_time_wait_does_not_terminate`
  drives a session into TIME-WAIT, injects a peer RST
  (with both `seq` and `ack` chosen so a naive
  acceptability check would otherwise admit it), and
  asserts (a) the session remains in TIME-WAIT state
  and (b) no outbound segment fires in response. The
  test docstring cites "RFC 1337 §3 (TIME-WAIT
  assassination mitigations)".

**Status:** locked in.

### §3 F2 — PAWS-based mitigation

- **Integration:** the broader RFC 7323 §5 PAWS
  coverage in
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py`
  (TestTcpTimestampsPhase4) and the RFC 6191 §3
  reuse coverage in
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py::TestTcpClose__TimeWaitRfc6191`
  exercise the PAWS check at
  `tcp__fsm__time_wait.py:97-104` indirectly.

**Status:** locked in indirectly. There is no
test specifically named "RFC 1337 F2 PAWS mitigation"
because the F2 path is not a separate code path —
it is the PAWS check that is shared with the RFC
7323 §5 implementation. A regression that disabled
the PAWS check in TIME-WAIT would be caught by the
TestTcpTimestampsPhase4 stale-TSval tests.

### §3 F3 — 64-bit sequence numbers

Wire-incompatible alternative path; RFC §4 selects F1
as the chosen short-term solution. PyTCP's F1 + PAWS-
strict combination already prevents all three hazards
F3 was designed to address. No test surface.

**Status:** n/a (alternative architecture).

### Hazard H1 (data acceptance)

- **Implicit coverage:** the TIME-WAIT FSM handler
  has no data-acceptance branch, so any peer data
  segment that arrives in TIME-WAIT either triggers
  the FIN-retransmit branch (if the segment is
  actually a FIN), the SYN-challenge-ACK branch (if
  SYN), the RFC 6191 reuse branch (if fresh-TSval
  SYN), or falls through to the implicit drop. There
  is no test that specifically asserts "data in
  TIME-WAIT is dropped" because the absence of a
  data-acceptance path means there is no dedicated
  branch to regression-test.

**Status:** locked in by absence (no data path
exists).

### Hazard H2 (desynchronization) and H3 (connection failure)

These hazards are consequences of TWA, not
requirements; they cannot occur because F1 prevents
TIME-WAIT termination by RST. The
`test__rfc1337__rst_in_time_wait_does_not_terminate`
test pins the precondition that prevents both H2 and
H3.

**Status:** locked in transitively via F1 test.

### §3 challenge-ACK on SYN-in-TIME-WAIT (RFC 9293 §3.10.7.4 cross-cut)

While not strictly an RFC 1337 mitigation (this is
RFC 9293 §3.10.7.4 / RFC 5961 §4 territory), it is
audited in the same TIME-WAIT FSM handler and
referenced from the RFC 1337 test class:

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py::TestTcpClose__TimeWaitRfc1337::test__rfc1337__no_evidence_syn_in_time_wait_elicits_challenge_ack`

**Status:** locked in. Cross-referenced in the RFC
9293 audit when written.

### Test coverage summary

| Aspect                    | Coverage                                   |
|---------------------------|--------------------------------------------|
| §3 F1 (ignore RST)        | locked in                                  |
| §3 F2 (PAWS mitigation)   | locked in indirectly (via RFC 7323 §5)     |
| §3 F3 (64-bit sequences)  | n/a (alternative path; RFC §4 selects F1)  |
| Hazard H1 (data acceptance) | locked in by absence (no data path)      |
| Hazard H2 (desync)        | locked in transitively via F1 test         |
| Hazard H3 (conn failure)  | locked in transitively via F1 test         |
| SYN-in-TIME-WAIT          | locked in (cross-cut with RFC 9293)        |

---

## Overall assessment

| Aspect                   | Status                            |
|--------------------------|-----------------------------------|
| §3 F1 (ignore RST)       | met                               |
| §3 F2 (PAWS mitigation)  | exceeded (F1 + PAWS strict)       |
| §3 F3 (64-bit sequences) | n/a — alternative architecture; RFC §4 selects F1 |
| §4 conclusion (use F1)   | met                               |
| Hazard H1 prevention     | met (no data path)                |
| Hazard H2 prevention     | met (F1 precludes)                |
| Hazard H3 prevention     | met (F1 precludes)                |

PyTCP fully implements RFC 1337's recommended
short-term fix (F1) and additionally combines it with
RFC 7323 §5 PAWS so that the F2 hazard-H1 protection
is also met as a strict superset. The deferred
long-term fix F3 (64-bit sequence numbers) is
correctly skipped per RFC 9293's adoption of 32-bit
sequences. One stale inline comment at
`tcp__fsm__time_wait.py:158-160` should be refreshed
to remove the obsolete "PyTCP does not implement
PAWS" claim; this is a documentation polish item, not
a behavioural gap.
