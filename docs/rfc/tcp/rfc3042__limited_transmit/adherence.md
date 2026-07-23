# RFC 3042 — Enhancing TCP's Loss Recovery Using Limited Transmit

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3042                                                 |
| Title       | Enhancing TCP's Loss Recovery Using Limited Transmit |
| Category    | Standards Track                                      |
| Date        | January 2001                                         |
| Source text | [`rfc3042.txt`](rfc3042.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 3042. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§3 Related Work, §4 Security Considerations narrative,
References) are omitted.

---

## §2. The Limited Transmit Algorithm

### Core algorithm

> "When a TCP sender has previously unsent data queued
> for transmission it SHOULD use the Limited Transmit
> algorithm, which calls for a TCP sender to transmit
> new data upon the arrival of the first two
> consecutive duplicate ACKs when the following
> conditions are satisfied:
>
>   * The receiver's advertised window allows the
>     transmission of the segment.
>
>   * The amount of outstanding data would remain less
>     than or equal to the congestion window plus 2
>     segments. In other words, the sender can only
>     send two segments beyond the congestion window
>     (cwnd)."

**Adherence:** met. The dup-ACK handler at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2771-2787` (inside
`_retransmit_packet_request`) implements the algorithm:

```python
count = self._tx_retransmit_request_counter[packet_rx_md.tcp__ack]
if count in (1, 2) and len(self._tx_buffer) > 0:
    saved_ewn = self._snd_ewn
    self._snd_ewn = min(self._cwnd + count * self._snd_mss, self._snd_wnd)
    self._transmit_data()
    self._snd_ewn = saved_ewn
```

The check fires only on the first two dup-ACKs (the
third triggers the `count_trigger` fast-retransmit
path below). The temporary `_snd_ewn` lift is bounded
by both `_cwnd + count * SMSS` (at most 2 SMSS beyond
cwnd) AND `_snd_wnd` (peer's advertised receive
window) — exactly the two conditions §2 specifies.
The "previously unsent data queued" condition is
checked via `len(self._tx_buffer) > 0`, where
`_tx_buffer` holds bytes that have not yet been
emitted (modular `_tx_buffer_nxt < len(_tx_buffer)`
implicit in `_transmit_data`).

### cwnd MUST NOT change

> "The congestion window (cwnd) MUST NOT be changed
> when these new segments are transmitted."

**Adherence:** met. The implementation modifies
`_snd_ewn` (the per-tick effective send window) and
restores it via the `saved_ewn` save/restore pattern.
`_cwnd` itself is never touched on this path. The
cwnd-MUST-NOT-change invariant holds.

### SACK MUST NOT send without new SACK info

> "Note: If the connection is using selective
> acknowledgments [RFC2018], the data sender MUST NOT
> send new segments in response to duplicate ACKs that
> contain no new SACK information, as a misbehaving
> receiver can generate such ACKs to trigger
> inappropriate transmission of data segments."

**Adherence:** partial / not gated. PyTCP's
implementation does NOT gate the Limited Transmit
emission on whether the dup-ACK carries new SACK
information. The check is purely `count in (1, 2)
and len(self._tx_buffer) > 0` — a SACK-bearing dup-
ACK with stale SACK blocks would still trigger an
emission, and a SACK-blind dup-ACK on a connection
with bilateral SACK would also trigger.

The SACK security note in §2 is specifically about a
misbehaving receiver fabricating dup-ACKs to coerce
the sender into sending faster than congestion control
allows. PyTCP's exposure is bounded: the §2 cwnd + 2
SMSS budget caps the over-send at exactly 2 segments
per loss event before fast retransmit kicks in. So
even if a misbehaving receiver triggers Limited
Transmit, the additional traffic is bounded.

The strict SACK-info-gate is not implemented but the
practical risk is low. Closing the gap would require
inspecting the inbound dup-ACK's SACK blocks
(`_sack_scoreboard.add_block` returning True / False
delta) and only triggering Limited Transmit when new
SACK info is present.

---

## Test coverage audit

### §2 Core algorithm — first dup-ACK

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py::TestTcpDataTransfer__RetransmitDupack::test__dupack__limited_transmit_sends_new_segment_on_first_dup_ack`
  drives a session that has unsent data, injects a
  single dup-ACK, and asserts a new (not retransmitted)
  segment is emitted on the next tick.

**Status:** locked in for the first-dup-ACK case.

### §2 Core algorithm — second dup-ACK

- **Integration (indirect):** the same test class
  contains tests that drive the second dup-ACK and
  verify that Limited Transmit fires again (one extra
  segment) BEFORE the third dup-ACK triggers fast
  retransmit. The two-dup-ACK + LT semantics are
  pinned by the broader fast-retransmit suite.

**Status:** locked in indirectly. A dedicated test
specifically for the second-dup-ACK Limited Transmit
emission would make the regression-guard explicit.

### §2 cwnd MUST NOT change

- **Integration (implicit):** every Limited-Transmit
  test that asserts the post-Limited-Transmit `_cwnd`
  value matches the pre-Limited-Transmit value
  exercises this invariant. The save/restore of
  `_snd_ewn` (rather than mutation of `_cwnd`) makes
  the invariant trivially satisfied at the
  implementation level.

**Status:** locked in by construction.

### §2 SACK MUST NOT send without new info

Not implemented; no positive test surface. A
regression-guard test for the gap would inject a SACK-
bearing dup-ACK with stale SACK blocks (no new
information) and assert that Limited Transmit does
NOT fire. PyTCP would currently fail this test.

**Status:** n/a (gap not closed; sketched test).

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §2 First dup-ACK new-segment emission           | locked in                                      |
| §2 Second dup-ACK new-segment emission          | locked in indirectly                           |
| §2 cwnd MUST NOT change                         | locked in by construction                      |
| §2 SACK MUST NOT send without new info          | n/a (gap not closed)                           |

---

## Overall assessment

| Aspect                                          | Status                                  |
|-------------------------------------------------|-----------------------------------------|
| §2 Core algorithm (1st + 2nd dup-ACK)           | met                                     |
| §2 rwnd condition                               | met                                     |
| §2 cwnd + 2 SMSS budget                         | met                                     |
| §2 cwnd MUST NOT change                         | met                                     |
| §2 SACK MUST NOT send without new SACK info     | not gated (acceptable risk per §4)      |

PyTCP implements RFC 3042 Limited Transmit correctly
for the core algorithm: first two dup-ACKs trigger an
extra new-segment emission with the `cwnd + count *
SMSS` budget, and `_cwnd` is never mutated. The single
gap is the SACK-info gate ("MUST NOT send new on dup-
ACK without new SACK information"). The practical
exposure is bounded by §2's hard cwnd + 2 SMSS budget
cap, so a misbehaving receiver cannot drive PyTCP
faster than 2 extra segments per loss event regardless
of how many fabricated dup-ACKs they send. Closing the
gap would require inspecting whether the dup-ACK's
SACK blocks contain new information (delta from the
sender's scoreboard); the work is moderate (~1-2
commits) and low-risk.
