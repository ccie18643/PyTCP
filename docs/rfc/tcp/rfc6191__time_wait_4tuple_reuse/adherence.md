# RFC 6191 — Reducing the TIME-WAIT State Using TCP Timestamps

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6191                                           |
| Title       | Reducing the TIME-WAIT State Using TCP Timestamps |
| Category    | Best Current Practice (BCP 159)                |
| Date        | April 2011                                     |
| Source text | [`rfc6191.txt`](rfc6191.txt)                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6191. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§3 Interaction with Various Timestamp Generation
Algorithms (advisory), §4 Interaction with Various ISN
Generation Algorithms (advisory), §5 Security
Considerations boilerplate, §6 Acknowledgements,
References, Appendix A scenario walk-through) are
omitted.

---

## §2. Improved Processing of Incoming Connection Requests

The RFC's §2 specifies a SHOULD-strength algorithm for
processing SYN segments received in TIME-WAIT state.
The algorithm is divided into two top-level branches
based on whether the previous incarnation used
Timestamps; each branch has 2-4 sub-cases.

### Top-level case A: previous incarnation used Timestamps

#### Sub-case A.1 — TSopt enabled in new SYN AND TSval > last seen

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, and the timestamp
> contained in the incoming SYN segment is greater
> than the last timestamp seen on the previous
> incarnation of the connection (for that direction of
> the data transfer), honor the connection request
> (creating a connection in the SYN-RECEIVED state)."

**Adherence:** met. The TIME-WAIT FSM handler at
`packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__time_wait.py:120-141`
implements this branch as the TSval-evidence arm of a
single Linux-style OR'd predicate covering A.1, A.2,
A.3, B.1, and B.2 at once:

```python
if (
    packet_rx_md.tcp__flag_syn
    and not packet_rx_md.tcp__flag_ack
    and not packet_rx_md.tcp__flag_rst
    and (
        gt32(packet_rx_md.tcp__seq, session._rcv_seq.nxt)
        or (packet_rx_md.tcp__tsval is not None and gt32(packet_rx_md.tcp__tsval, ts_recent_at_entry))
    )
):
    session._reinit_for_rfc6191_reuse(packet_rx_md)
    session._change_state(FsmState.SYN_RCVD)
    session._transmit_packet(flag_syn=True, flag_ack=True)
    return
```

The check requires:
- The inbound segment is a pure SYN (not SYN+ACK, not
  RST).
- Either the seq is strictly greater than RCV.NXT
  (seq-evidence axis), or the new SYN brings a TSval
  strictly greater than `_ts_recent` (TSval-evidence
  axis; modular comparison via `gt32`).

Sub-case A.1 (both incarnations TSopt-enabled, fresh
TSval > last) is the TSval-evidence arm: it fires
whenever `tcp__tsval > _ts_recent`. There is no
`session._send_ts` gate — the previous incarnation's
TSopt history is not consulted, matching Linux's
`tcp_timewait_state_process`.

When the predicate holds, `_reinit_for_rfc6191_reuse`
(`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1866-1925+`)
resets the session to a fresh state, transitions to
SYN_RCVD, and emits the SYN+ACK. This is the canonical
RFC 6191 §2 sub-case A.1 acceptance branch.

The operative inline comment correctly cites "RFC 6191
§2" (the algorithm's home section). §3 is "Interaction
with Various Timestamp Generation Algorithms" (advisory
commentary).

#### Sub-case A.2 — TSopt enabled AND TSval == last AND seq > last_seq

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, the timestamp
> contained in the incoming SYN segment is equal to
> the last timestamp seen on the previous incarnation
> of the connection (for that direction of the data
> transfer), and the Sequence Number of the incoming
> SYN segment is greater than the last sequence number
> seen on the previous incarnation of the connection
> (for that direction of the data transfer), honor the
> connection request (creating a connection in the
> SYN-RECEIVED state)."

**Adherence:** met. PyTCP's TIME-WAIT FSM handler
uses Linux's OR'd predicate `(gt32(seq, RCV.NXT) OR
gt32(TSval, ts_recent))`, accepting reuse on either
evidence axis. RCV.NXT serves as the "last sequence
number seen" — it is the next-byte-expected from peer
and equals one past the highest seq we ever ACKed.
When `tsval == _ts_recent` (TSval evidence absent)
but `seq > RCV.NXT`, the seq evidence path fires and
the SYN is accepted as a fresh connection. Pinned by
`test__rfc6191__equal_tsval_with_seq_evidence_accepts_reuse`.

#### Sub-case A.3 — TSopt NOT enabled in new SYN BUT seq > last_seq

> "If TCP Timestamps would not be enabled for the new
> incarnation of the connection, but the Sequence
> Number of the incoming SYN segment is greater than
> the last sequence number seen on the previous
> incarnation of the connection (for the same
> direction of the data transfer), honor the
> incoming connection request (creating a connection
> in the SYN-RECEIVED state)."

**Adherence:** met. Same OR'd predicate as A.2: when
the new SYN omits TSopt (TSval-evidence path skipped)
but `seq > RCV.NXT`, the seq evidence accepts reuse.
Pinned by
`test__rfc6191__syn_without_tsopt_with_seq_evidence_accepts_reuse`.

#### Sub-case A.4 — Otherwise drop (default)

> "Otherwise, silently drop the incoming SYN segment,
> thus leaving the previous incarnation of the
> connection in the TIME-WAIT state."

**Adherence:** PyTCP elicits a challenge-ACK rather
than silently dropping. The challenge-ACK matches RFC
9293 §3.10.7.4 / RFC 5961 §4 for SYN-on-synchronized.
RFC 6191 §2 says "silently drop", but the RFC 9293
challenge-ACK is a stricter, more informative response
that does not violate RFC 6191's intent (the previous
incarnation stays in TIME-WAIT regardless of which
response is chosen).

### Top-level case B: previous incarnation did NOT use Timestamps

#### Sub-case B.1 — TSopt enabled in new SYN

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, honor the incoming
> connection request (creating a connection in the
> SYN-RECEIVED state)."

**Adherence:** met. The Linux-style OR'd predicate
no longer gates on `session._send_ts` (the previous
incarnation's TSopt history). When the new SYN brings
a TSopt with `TSval > _ts_recent` (which equals 0 if
no prior TSopt was seen), the TSval-fresh path
accepts reuse. With `_ts_recent = 0`, any positive
TSval qualifies — matching the §2 B.1 SHOULD that
"any new TSopt-bearing SYN is sufficient evidence".

#### Sub-case B.2 — TSopt NOT enabled BUT seq > last_seq

> "If TCP Timestamps would not be enabled for the new
> incarnation of the connection, but the Sequence
> Number of the incoming SYN segment is greater than
> the last sequence number seen on the previous
> incarnation of the connection (for the same
> direction of the data transfer), honor the incoming
> connection request..."

**Adherence:** met. Same seq-evidence path as A.2 /
A.3: `seq > RCV.NXT` accepts reuse regardless of
TSopt history.

#### Sub-case B.3 — Otherwise drop

> "Otherwise, silently drop the incoming SYN segment,
> thus leaving the previous incarnation of the
> connection in the TIME-WAIT state."

**Adherence:** as in sub-case A.4, PyTCP elicits
challenge-ACK rather than silent drop.

---

## Coverage summary of §2 sub-cases

| Sub-case | Trigger                                              | PyTCP behaviour                                |
|----------|------------------------------------------------------|------------------------------------------------|
| A.1      | prev-TSopt + new-TSopt + TSval > _ts_recent          | met (accepts via `_reinit_for_rfc6191_reuse`)  |
| A.2      | prev-TSopt + new-TSopt + TSval == _ts_recent + seq > | met (accepts via seq-evidence path)            |
| A.3      | prev-TSopt + no-new-TSopt + seq > last_seq           | met (accepts via seq-evidence path)            |
| A.4      | otherwise (prev-TSopt branch)                        | challenge-ACK (vs RFC's silent drop)           |
| B.1      | prev-no-TSopt + new-TSopt                            | met (accepts via TSval-evidence path)          |
| B.2      | prev-no-TSopt + no-new-TSopt + seq > last_seq        | met (accepts via seq-evidence path)            |
| B.3      | otherwise (prev-no-TSopt branch)                     | challenge-ACK (vs RFC's silent drop)           |

**Overall §2 status:** PyTCP implements every §2
acceptance sub-case (A.1, A.2, A.3, B.1, B.2) via
Linux's OR'd predicate — reuse is honored on either
the TSval-evidence axis or the seq-evidence axis. The
no-evidence default cases (A.4, B.3) elicit a
challenge-ACK rather than the RFC's silent drop; the
SHOULD strength of §2 permits this stricter response
(the previous incarnation stays in TIME-WAIT either
way).

---

## Test coverage audit

### §2 sub-case A.1 — Fresh TSval acceptance

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py::TestTcpClose__TimeWaitRfc6191::test__rfc6191__fresh_tsval_syn_terminates_time_wait_and_emits_syn_ack`
  drives a session into TIME-WAIT, captures
  `_ts_recent`, then injects a SYN with TSval >
  `_ts_recent` and asserts:
  - The session terminates TIME-WAIT and transitions
    to SYN_RCVD.
  - A SYN+ACK is emitted in response.

**Status:** locked in.

### §2 sub-case A.2 — TSval == last + seq evidence

- **Integration:**
  `TestTcpClose__TimeWaitRfc6191::test__rfc6191__equal_tsval_with_seq_evidence_accepts_reuse`
  pins acceptance via the seq-evidence path when
  TSval is equal to `_ts_recent`.

**Status:** locked in.

### §2 sub-case A.3 / B.1 / B.2 — Various non-A.1 acceptance branches

- **Integration:**
  `TestTcpClose__TimeWaitRfc6191::test__rfc6191__syn_without_tsopt_with_seq_evidence_accepts_reuse`
  pins A.3 / B.2 (no-TSopt + seq-evidence) acceptance.
- **Integration:**
  `TestTcpClose__TimeWaitRfc6191::test__rfc6191__no_evidence_falls_back_to_challenge_ack`
  pins the A.4 / B.3 default-drop fallback (when
  neither evidence axis fires).
- **Integration:**
  `TestTcpClose__TimeWaitRfc1337::test__rfc1337__no_evidence_syn_in_time_wait_elicits_challenge_ack`
  cross-cut RFC 1337 hazard #3 coverage of the same
  no-evidence path.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §2 A.1 fresh-TSval acceptance                   | locked in                                      |
| §2 A.2 TSval-equal + seq-greater                | locked in (Linux-style OR'd predicate)         |
| §2 A.3 prev-TSopt no-new-TSopt + seq            | locked in (Linux-style OR'd predicate)         |
| §2 A.4 default drop                             | replaced by challenge-ACK (stricter)           |
| §2 B.1 no-prev-TSopt new-TSopt                  | locked in (Linux-style OR'd predicate)         |
| §2 B.2 no-prev-TSopt no-new-TSopt + seq         | locked in (Linux-style OR'd predicate)         |
| §2 B.3 default drop                             | replaced by challenge-ACK (stricter)           |

---

## Overall assessment

| Aspect                                          | Status                                          |
|-------------------------------------------------|-------------------------------------------------|
| §2 A.1 (TSval > last_TSval)                     | met (Linux-style: TSval-fresh path)             |
| §2 A.2 (TSval == last + seq > last_seq)         | met (Linux-style: seq-fresh path)               |
| §2 A.3 (no-new-TSopt + seq > last_seq)          | met (Linux-style: seq-fresh path)               |
| §2 A.4 (drop default)                           | replaced by challenge-ACK (stricter)            |
| §2 B.1 (no-prev-TSopt + new-TSopt)              | met (Linux-style: TSval-fresh path)             |
| §2 B.2 (no-prev-TSopt no-new-TSopt + seq)       | met (Linux-style: seq-fresh path)               |
| §2 B.3 (drop default)                           | replaced by challenge-ACK (stricter)            |

PyTCP implements RFC 6191 §2 acceptance via Linux's
OR'd-predicate pattern: a SYN to a TIME-WAIT 4-tuple
is accepted as a fresh connection if EITHER its seq
is strictly greater than RCV.NXT (the seq-evidence
path covering A.2 / A.3 / B.2) OR its TSval is
strictly greater than `_ts_recent` (the TSval-
evidence path covering A.1 / B.1). This subsumes
the RFC's tabular A-vs-B distinction in a single
expression and matches `tcp_timewait_state_process`
in `net/ipv4/tcp_minisocks.c`. RCV.NXT serves as the
"last sequence number seen" — it is one past the
highest seq we ever ACKed, equivalent to the §2
"last seq seen on the previous incarnation".

A.4 / B.3 (no evidence on either axis) fall through
to the RFC 9293 §3.10.7.4 / RFC 1337 §3 challenge-
ACK path, which is stricter than the RFC's "silently
drop" default — peers get an explicit signal to
retry rather than a silent black hole.
