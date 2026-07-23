# RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks

| Field       | Value                                                       |
|-------------|-------------------------------------------------------------|
| RFC number  | 5961                                                        |
| Title       | Improving TCP's Robustness to Blind In-Window Attacks       |
| Category    | Standards Track                                             |
| Date        | August 2010                                                 |
| Source text | [`rfc5961.txt`](rfc5961.txt)                                |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 5961. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction
narrative, §1.1–§1.3 attack description / probability,
§2 Terminology boilerplate, §6 Suggested Mitigation
Strengths summary, §8 Backward Compatibility, §9
Middlebox Considerations, §10 Security Considerations,
References) are omitted.

---

## §3.2. Mitigation — Blind Reset Attack Using the RST Bit

> "Implementations SHOULD implement the following steps:
>
>   1) If the RST bit is set and the sequence number is
>      outside the current receive window, silently
>      drop the segment.
>
>   2) If the RST bit is set and the sequence number
>      exactly matches the next expected sequence
>      number (RCV.NXT), then TCP MUST reset the
>      connection.
>
>   3) If the RST bit is set and the sequence number
>      does not exactly match the next expected
>      sequence value, yet is within the current
>      receive window... TCP MUST send an
>      acknowledgment (challenge ACK)... After sending
>      the challenge ACK, TCP MUST drop the
>      unacceptable segment and stop processing the
>      incoming packet further."

**Adherence:** met. The
`_check_rst_acceptability` helper at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1823-1864`
implements the three-case algorithm exactly:

```python
seq = packet_rx_md.tcp__seq
ack_acceptable = (not packet_rx_md.tcp__flag_ack) or in_range32(
    packet_rx_md.tcp__ack, self._snd_una, self._snd_max
)
# Case 1: exact match → reset
if seq == self._rcv_nxt and ack_acceptable:
    return True
# Case 3: in-window mismatch → challenge ACK + drop
if lt32(self._rcv_nxt, seq) and lt32(seq, add32(self._rcv_nxt, self._rcv_wnd)):
    self._emit_challenge_ack()
return False
# Case 2 (out-of-window): falls through, returns False, caller silently drops
```

The helper is invoked from every synchronized-state
FSM handler that processes RST. The exact-match case
returns True (caller transitions to CLOSED); the
in-window-mismatch case emits a rate-limited
challenge ACK and returns False (caller drops); the
out-of-window case falls through to silent drop.
Mapping cleanly onto §3.2 cases 2, 3, 1 respectively.

The additional `ack_acceptable` guard for case 1 is
defensive (a strict reading of RFC 5961 §3.2 does not
require it; RFC 9293 §3.10.7.4 step 3 / 4 does);
PyTCP's behaviour is conservative.

---

## §4.2. Mitigation — Blind Reset Attack Using the SYN Bit

> "If the SYN bit is set, irrespective of the sequence
> number, TCP MUST send an ACK (also referred to as
> challenge ACK) to the remote peer... After sending
> the acknowledgment, TCP MUST drop the unacceptable
> segment and stop processing further."

**Adherence:** met across all synchronized states.
Every FSM handler in synchronized state checks for
the SYN flag and emits a challenge ACK:

- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__established.py:83-94`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__fin_wait_1.py:68-73`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__fin_wait_2.py:62-64`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__close_wait.py:70-72`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__closing.py:62-64`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__last_ack.py:66-68`
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__time_wait.py:161-167`
  (covered also by RFC 1337 audit)
- `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__syn_rcvd.py:66`

Each handler invokes `session._emit_challenge_ack()`
and returns without further processing of the
segment. The challenge-ACK content is
`<SEQ=SND.NXT, ACK=RCV.NXT, CTL=ACK>` as required.

---

## §5.2. Mitigation — Blind Data Injection Attack

> "TCP stacks that implement this mitigation MUST add
> an additional input check to any incoming segment.
> The ACK value is considered acceptable only if it
> is in the range of ((SND.UNA - MAX.SND.WND) <=
> SEG.ACK <= SND.NXT). All incoming segments whose
> ACK value doesn't satisfy the above condition MUST
> be discarded and an ACK sent back."

**Adherence:** met. PyTCP implements the full §5
ACK acceptability check at
`packages/pytcp/pytcp/protocols/tcp/tcp__fsm__established.py:271-284`:

```python
ack_lower_bound = sub32(session._snd_una, session._max_window)
if lt32(packet_rx_md.tcp__ack, ack_lower_bound):
    session._emit_challenge_ack()
    ...
```

with `_max_window` tracked at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:685` (initial
value `_snd_mss`) and updated at
`tcp__session.py:3515-3516`:

```python
if self._snd_wnd > self._max_window:
    self._max_window = self._snd_wnd
```

— exactly the §5.2 "MAX.SND.WND is defined as the
largest window that the local sender has ever
received from its peer". The window value is also
properly scaled (§5.2 commentary: "may be scaled to
a value larger than 65,535 bytes"); the
`_snd_wnd << _snd_wsc` happens inside the post-
WSCALE-update code path, so the stored
`_max_window` reflects the post-shift value.

The ACK-too-high case (`SEG.ACK > SND.NXT`) is also
handled: it falls through to the existing
RFC 9293 §3.10.7.4 unacceptable-ACK path which
emits a challenge ACK.

The §5 mitigation is tagged as MAY in the RFC's §6
("DATA mitigation is tagged as MAY"); PyTCP
implements it anyway.

---

## §7. ACK Throttling

> "An implementation SHOULD include an ACK throttling
> mechanism to be conservative."

**Adherence:** met. The `_emit_challenge_ack` helper
at `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1989-2017`
implements per-session sliding-window throttling:

```python
rate_limit_timer = f"{self}-challenge_ack"
if not stack.timer.is_expired(rate_limit_timer):
    return  # suppressed
self._transmit_packet(flag_ack=True)
stack.timer.register_timer(name=rate_limit_timer, timeout=tcp__constants.TCP__CHALLENGE_ACK__RATE_LIMIT_MS)
```

with `TCP__CHALLENGE_ACK__RATE_LIMIT_MS = 1000`
(`packages/pytcp/pytcp/protocols/tcp/tcp__constants.py:74`) — at
most one challenge ACK per second per session. This
is more conservative than RFC 5961 §7's example of
"10 challenge ACKs in any 5 second window"; the §7
language explicitly notes the values are "empirical
in nature" and "tunable", so PyTCP's stricter
1-per-second is a permitted choice.

The sliding-window behaviour matches §7's
"timestamp and a counter" approach (the timer
expiration acts as both timestamp and counter
combined into a single boolean predicate).

---

## Test coverage audit

### §3.2 RST mitigation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__close__rst.py`
  contains comprehensive tests covering the three-case
  algorithm:
  - `test__close_rst__rst_in_established_drops_to_closed_and_wakes_blocked_recv`
    (and the bare-RST variant
    `test__close_rst__bare_rst_in_established_must_drop_to_closed`,
    plus per-state `..._in_fin_wait_1_drops_to_closed` /
    `..._in_fin_wait_2_drops_to_closed` /
    `..._in_last_ack_drops_to_closed`) — case 1 exact
    match at RCV.NXT.
  - `test__close_rst__in_window_rst_not_at_rcv_nxt_must_elicit_challenge_ack`
    and the per-state variants
    (`test__close_rst__in_window_rst_in_fin_wait_1_must_elicit_challenge_ack`,
    similar for FIN_WAIT_2, CLOSE_WAIT, LAST_ACK) —
    case 3 in-window mismatch.
  - Case 2 (out-of-window RST silent drop) is exercised
    implicitly by the acceptability helper but has no
    dedicated named test.

**Status:** locked in across all synchronized states
(cases 1 and 3; case 2 not separately pinned).

### §4.2 SYN mitigation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__robustness__blind_attacks.py`
  pins the SYN-in-synchronized challenge-ACK across the
  synchronized states:
  - `test__robustness__syn_in_fin_wait_1_must_elicit_challenge_ack`
  - `test__robustness__syn_in_fin_wait_2_must_elicit_challenge_ack`
  - and similar for CLOSE_WAIT, CLOSING, LAST_ACK, plus
    `test__robustness__no_evidence_syn_in_time_wait_must_elicit_challenge_ack`.

  The ESTABLISHED and SYN_RCVD variants live in the
  handshake tests:
  `test__tcp__session__handshake__passive.py::test__passive_open__syn_to_established_child_emits_challenge_ack`,
  `test__tcp__session__handshake__active.py::test__active_open__retransmitted_syn_ack_in_established_emits_challenge_ack`,
  and
  `test__tcp__session__handshake__passive.py::test__passive_open__retransmitted_syn_in_syn_rcvd_emits_challenge_ack`.

**Status:** locked in.

### §5.2 ACK acceptability

- **Integration:**
  `test__tcp__session__robustness__blind_attacks.py::test__ack__below_snd_una_minus_max_window_emits_challenge_ack`
  drives an ACK with a value below `_snd_una -
  _max_window` and asserts a challenge ACK is
  emitted.
- The ACK-too-high case is covered by the
  pre-RFC-5961 unacceptable-ACK tests in the same
  file.

**Status:** locked in.

### §7 ACK throttling

- **Integration:**
  `test__tcp__session__robustness__blind_attacks.py::test__blind_attack__challenge_ack_burst_is_rate_limited_per_rfc_5961_3`
  drives a burst of challenge-eliciting segments and
  asserts only one outbound challenge ACK fires
  within the 1-second window.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §3.2 RST case 1 (exact match)                   | locked in                                      |
| §3.2 RST case 2 (out-of-window drop)            | helper-covered; no dedicated test              |
| §3.2 RST case 3 (in-window mismatch challenge)  | locked in across all synchronized states       |
| §4.2 SYN-in-synchronized challenge ACK          | locked in across all synchronized states       |
| §5.2 ACK below SND.UNA - MAX.SND.WND            | locked in                                      |
| §5.2 ACK above SND.NXT                          | locked in (pre-existing path)                  |
| §5.2 _max_window tracking                       | locked in (covered by §5.2 challenge-ACK test) |
| §7 ACK throttling                               | locked in (1 ACK / 1000 ms rate-limit)         |

---

## Overall assessment

| Aspect                                          | Status                                |
|-------------------------------------------------|---------------------------------------|
| §3.2 RST blind-attack mitigation                | met                                   |
| §4.2 SYN blind-attack mitigation                | met (all synchronized states)         |
| §5.2 DATA blind-injection mitigation            | met (MAY upgraded to implemented)     |
| §7 ACK throttling                               | met (1/sec, stricter than §7 example) |

PyTCP fully implements every RFC 5961 mitigation,
including the §5 DATA mitigation that the RFC tags as
MAY (and many implementations skip). The challenge-
ACK rate limit of 1 per second per session is more
conservative than the §7 example "10 per 5 seconds",
which the RFC explicitly permits as a tunable
parameter. The audit identifies no gaps.
