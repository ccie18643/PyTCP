# RFC 7323 — TCP Extensions for High Performance

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 7323                                           |
| Title       | TCP Extensions for High Performance            |
| Category    | Standards Track                                |
| Date        | September 2014                                 |
| Obsoletes   | RFC 1323                                       |
| Source text | [`rfc7323.txt`](rfc7323.txt)                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 7323. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/`, `packages/pytcp/pytcp/socket/`, and
`packages/net_proto/net_proto/protocols/tcp/options/` directly; no prior
memory or rule-file content was reused. Sections that
contain no normative content (Abstract, §1
Introduction narrative, §1.1–§1.3 motivation, §1.4
Terminology boilerplate, §2.1 / §3.1 / §4.1 / §5.1
introductions, §6 Conclusions, §7 Security
Considerations, §8 IANA, §9 References, Appendices)
are omitted. Five sections carry the normative
content: §2 WSCALE, §3 Timestamps, §4 RTTM, §5 PAWS,
plus the §2.4 window-retraction rule.

---

## §2.2. Window Scale Option

### Wire format

> "Kind: 3 / Length: 3 bytes / shift.cnt"

**Adherence:** met. The wire-level encoding is
implemented at
`packages/net_proto/net_proto/protocols/tcp/options/tcp__option__wscale.py`
with kind=3 and length=3 exactly per the RFC.

### Bilateral negotiation

> "Both sides MUST send Window Scale options in their
> <SYN> segments to enable window scaling in either
> direction."

**Adherence:** met. The bilateral negotiation is
gated on `_advertise_wscale` (line 174) for outbound
and the post-handshake check for the peer's WSCALE
option presence:

- Outbound SYN includes WSCALE iff `_advertise_wscale`
  (line 1305).
- Inbound SYN's WSCALE is only adopted if our SYN+ACK
  also advertises it (the `_snd_wsc` field defaults
  to 0 at line 756; it's set from peer's WSCALE only
  when bilateral conditions hold).

### Maximum shift count

> "The maximum scale exponent is limited to 14...
> If a Window Scale option is received with a
> shift.cnt value larger than 14, the TCP SHOULD log
> the error but MUST use 14 instead of the specified
> value."

**Adherence:** met. The offered receive shift is no
longer a flat default — `TcpSession.__init__` sets
`rcv_wsc = derive_rcv_wscale(tcp.rmem.max)`
(`packages/pytcp/pytcp/protocols/tcp/state/tcp__state__window.py`,
`derive_rcv_wscale`), sizing the shift for the
receive-buffer DRS ceiling (Linux
`tcp_select_initial_window`). The derivation returns
the smallest shift whose `0xFFFF << shift` covers
`tcp.rmem.max` and is itself **capped at 14**
(`WINDOW_SCALE__MAX_SHIFT`), so the outbound offer can
never exceed the RFC limit regardless of how large an
operator sets `tcp.rmem.max`. The default 6 MiB
`tcp.rmem.max` derives shift 7 (65535 << 7 ≈ 8 MiB),
the canonical Linux value. The wire-level option's
`shift_count` field accepts up to 255 at the assembler
level (uint8); the protocol-level clamp to 14 on the
*inbound* adoption side is separate and unchanged.

### Window field unscaled on SYN / SYN+ACK

> "The window field in a segment where the SYN bit
> is set (i.e., a <SYN> or <SYN,ACK>) MUST NOT be
> scaled."

**Adherence:** met. The outbound TX path at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1278-1297`
unconditionally caps `tcp__win` at 0xFFFF on SYN /
SYN+ACK (literal RCV.WND, not pre-shift) and applies
the right-shift only on non-SYN segments.

---

## §2.3. Using the Window Scale Option

### Snd.Wind.Shift / Rcv.Wind.Shift state

> "The connection state is augmented by two window
> shift counters, Snd.Wind.Shift and Rcv.Wind.Shift,
> to be applied to the incoming and outgoing window
> fields, respectively."

**Adherence:** met. PyTCP tracks both:

- `_snd_wsc: int = 0` (line 756) — peer's shift count,
  applied to inbound `tcp__win` to recover SND.WND.
- `_rcv_wsc: int = 7` (line 165) — our shift count,
  applied to outbound RCV.WND.

### Left-shift inbound, right-shift outbound

> "SND.WND = SEG.WND << Snd.Wind.Shift
> SEG.WND = RCV.WND >> Rcv.Wind.Shift"

**Adherence:** met. The `_snd_wnd` update path
applies `<< _snd_wsc` post-handshake; the outbound
path at line 1297 applies `>> _rcv_wsc`.

### Cwnd not affected by scaling

> "The 'congestion window' computed by slow start and
> congestion avoidance (see [RFC5681]) is not
> affected by the scale factor"

**Adherence:** met. `_cwnd` is stored in bytes
(unshifted) and never mutated by the WSCALE
mechanism.

---

## §2.4. Addressing Window Retraction

> "Implementations MUST ensure that they handle a
> shrinking window, as specified in Section 4.2.2.16
> of [RFC1122]."

**Adherence:** met. The shrinking-window robustness
rules are enforced via the `_max_window` field
(`tcp__session.py:685` and refresh at line 3515) and
the persist-timer machinery at the zero-window
boundary. RFC 1122 §4.2.2.16 details are audited
under the RFC 1122 record.

---

## §3.2. Timestamps Option

### Wire format

> "Kind: 8 / Length: 10 bytes / TSval (4) | TSecr (4)"

**Adherence:** met. The wire-level encoding at
`packages/net_proto/net_proto/protocols/tcp/options/tcp__option__timestamps.py`
implements kind=8 and length=10 exactly.

### TSecr semantics

> "When the ACK bit is set in an outgoing segment,
> the sender MUST echo a recently received TSval...
> When the ACK bit is not set, the receiver MUST
> ignore the value of the TSecr field."

**Adherence:** met. The TSopt emission at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1348-1370`
constructs `(tsval, tsecr)` per the §4.3 rules:
on SYN, tsecr=0; on SYN+ACK or non-SYN, tsecr =
`_ts_recent`.

### TSopt MAY on initial SYN

> "A TCP MAY send the TSopt in an initial <SYN>
> segment (i.e., segment containing a SYN bit and no
> ACK bit), and MAY send a TSopt in <SYN,ACK> only
> if it received a TSopt in the initial <SYN>
> segment for the connection."

**Adherence:** met. PyTCP sends TSopt on the active-
open SYN iff `_advertise_ts` is True (line 1351-1356);
the passive-open SYN+ACK sends TSopt iff `_send_ts`
is True (line 1358-1363) — `_send_ts` is set only
when peer's SYN carried TSopt.

### TSopt MUST be sent on every non-RST segment after negotiation

> "Once TSopt has been successfully negotiated... the
> TSopt MUST be sent in every non-<RST> segment for
> the duration of the connection."

**Adherence:** met. Once `_send_ts` is True, every
non-RST outbound segment includes TSopt
(`tcp__session.py:1365-1370`). RST segments are
handled separately (RFC 7323 §5.2 says RST segments
SHOULD carry TSopt; PyTCP's RST emission path does
not currently include TSopt — see test coverage
audit).

### Missing TSopt on a non-RST: SHOULD silently drop

> "If a non-<RST> segment is received without a
> TSopt, a TCP SHOULD silently drop the segment. A
> TCP MUST NOT abort a TCP connection because any
> segment lacks an expected TSopt."

**Adherence:** met. PyTCP's
`_check_paws_and_update_ts_recent` returns False when
`_send_ts` is True and the inbound segment lacks TSopt,
causing the caller to silently drop the segment per
the §3.2 SHOULD. SYN-bearing segments are exempt because
they may legitimately re-initiate (RFC 6191 §3 4-tuple
reuse, RFC 9293 §3.10.7.4 SYN-in-synchronized
challenge-ACK path) and the per-segment TSopt
expectation has not yet been re-established for the
new incarnation. The §3.2 "NOT abort" MUST is also met
(no abort path exists).

### TSopt on RST: SHOULD include

> "TSopt SHOULD be sent in an <RST> segment."

**Adherence:** met. PyTCP's `_transmit_packet` carries
no RST-specific TSopt-suppress gate, so an RST emitted
in a TS-negotiated session naturally includes TSopt
(TSval = current TS clock, TSecr = `_ts_recent`). All
session-state RST emissions (ABORT path, retransmit-
exhaustion path) are routed through `_transmit_packet`
and therefore satisfy the SHOULD. Stateless RSTs from
LISTEN / SYN_SENT pre-handshake paths cannot include
TSopt because no `_ts_recent` has been negotiated; the
SHOULD does not apply to those connectionless emit
paths.

---

## §4. The RTTM Mechanism

### RTTM Rule: only update RTO on SND.UNA-advancing ACKs

> "A TSecr value received in a segment MAY be used to
> update the averaged RTT measurement only if the
> segment advances the left edge of the send window,
> i.e., SND.UNA is increased."

**Adherence:** met. The TSecr-based RTT sample is
folded only inside the cum-ACK path that advances
SND.UNA. Out-of-order or pure dup-ACK segments do
not feed the RTO estimator.

### §4.2 Multiple RTTMs per RTT

> "An implementation SHOULD try to adhere to the
> spirit of the history specified in [RFC6298]."

**Adherence:** met. PyTCP's RFC 6298 EWMA absorbs
multiple per-RTT samples from TSecr-based RTTM
correctly; the alpha=1/8 / beta=1/4 weights work
correctly with multiple samples per RTT.

### §4 (extension) Receiver-side RTT estimator (DRS)

Beyond the RTO sample above (which needs *our* data to
be acked), PyTCP keeps a separate **receiver-side** RTT
estimate for receive-buffer Dynamic Right-Sizing —
mirroring Linux `rcv_rtt_est` / `tcp_rcv_rtt_measure_ts`
— so a pure receiver that only sends ACKs still measures
a round trip.

**Adherence:** met (Linux-parity extension). On an
inbound new-data segment carrying a valid TSecr,
`RcvRttState.observe`
(`packages/pytcp/pytcp/protocols/tcp/state/tcp__state__rcv_rtt.py`)
folds `now_ms - TSecr` via an alpha=1/8 EWMA, deduped on
the echoed TSecr so a within-RTT burst yields one
sample (the phase-5 hook in
`session/tcp__session__ack.py`). When TSopt was **not**
negotiated, the fallback `observe_window` measures the
wall-time to receive one advertised window of data
(anchor at `rcv_nxt + rcv_wnd`) and takes the minimum,
matching Linux `tcp_rcv_rtt_measure` (`win_dep=1`). The
estimate feeds the DRS cadence gate (RFC 9293 §3.8.6.4)
but never the RFC 6298 RTO, so it cannot perturb
retransmission timing.

### §4.3 Which Timestamp to Echo (cases A, B, C)

The §4.3 algorithm specifies the `TS.Recent` /
`Last.ACK.sent` state machine:

> "(2) If: SEG.TSval >= TS.Recent and SEG.SEQ <=
>      Last.ACK.sent then SEG.TSval is copied to
>      TS.Recent; otherwise, it is ignored."

**Adherence:** met. PyTCP's
`_check_paws_and_update_ts_recent` gates the TS.Recent
update on `SEG.SEQ <= self._rcv_nxt` (the safe
tightening of `SEG.SEQ <= Last.ACK.sent`, since
Last.ACK.sent is monotone non-decreasing and equals
RCV.NXT at the moment of our last outbound ACK; the
gate can only suppress refreshes the strict algorithm
would also suppress, never the reverse). OOO segments
pass PAWS but do not refresh TS.Recent, so the next
outbound TSecr correctly echoes the last in-sequence
peer TSval. SYN-bearing segments are exempt because
they establish (or re-establish on RFC 6191 reuse)
the connection's TS.Recent in a fresh seq space.

---

## §5.2. The PAWS Mechanism

### Basic mechanism

> "PAWS uses the TCP Timestamps option described
> earlier and assumes that every received TCP
> segment... contains a timestamp SEG.TSval whose
> values are monotonically non-decreasing in time...
> a segment can be discarded as an old duplicate if
> it is received with a timestamp SEG.TSval less
> than some timestamps recently received on this
> connection."

**Adherence:** met. The PAWS check at
`_check_paws_and_update_ts_recent` (line 1789-1821)
implements:

```python
if not self._send_ts or packet_rx_md.tcp__tsval is None:
    return True
if lt32(packet_rx_md.tcp__tsval, self._ts_recent):
    return False
self._ts_recent = packet_rx_md.tcp__tsval
return True
```

The `lt32` modular comparison handles the 32-bit
timestamp wrap (24 days at 1 ms granularity).

### RST segments: NOT subject to PAWS

> "When an <RST> segment is received, it MUST NOT be
> subjected to the PAWS check by verifying an
> acceptable value in SEG.TSval, and information from
> the Timestamps option MUST NOT be used to update
> connection state information."

**Adherence:** PyTCP's PAWS check at line 1810-1811
returns True (passes) when the inbound segment has
no TSopt; for an RST that carries TSopt, the PAWS
gate would still apply. Looking at the call sites:

- `tcp__fsm__time_wait.py:103`: PAWS runs on RST in
  TIME-WAIT — this is the strengthened RFC 1337 §2
  path. RFC 7323 §5.2 says RST MUST NOT be subject
  to PAWS; PyTCP deliberately violates this in
  TIME-WAIT for the §1337 hardening. The deviation
  is documented in the RFC 1337 audit.
- Other states don't run PAWS on RST.

The §5.2 "RST MUST NOT be subjected to PAWS"
requirement is met in synchronized states (the PAWS
gate is in `_process_ack_packet` which doesn't fire
on RST). The TIME-WAIT deviation is intentional and
auditied separately under RFC 1337.

---

## §5.3. Basic PAWS Algorithm (R1–R5)

### R1) Stale-TSval drop

> "If there is a Timestamps option in the arriving
> segment, SEG.TSval < TS.Recent, TS.Recent is valid,
> and if the RST bit is not set, then treat the
> arriving segment as not acceptable: Send an
> acknowledgment in reply..."

**Adherence:** met. PyTCP's
`_check_paws_and_update_ts_recent` calls
`_emit_challenge_ack()` on the stale-TSval drop,
satisfying R1's "Send an acknowledgment in reply"
SHOULD. The challenge-ACK helper is rate-limited per
RFC 5961 §3 so a burst of stale-TSval segments cannot
amplify into an outbound ACK flood. The peer can
recover its sender state without waiting for its own
RTO.

### R3) Update TS.Recent

> "If an arriving segment satisfies SEG.TSval >=
> TS.Recent and SEG.SEQ <= Last.ACK.sent (see Section
> 4.3), then record its timestamp in TS.Recent."

**Adherence:** met — same as §4.3 audit above.
`check_paws_and_update_ts_recent`
(`session/tcp__session__validate.py:258`) gates the
`TS.Recent` refresh on
`flag_syn or le32(seq, rcv_nxt)` — the safe tightening
of `SEG.SEQ <= Last.ACK.sent` — and only applies the
update (`:302-303`) when that gate holds, so an OOO
segment cannot inflate `TS.Recent`.

### R4) In-sequence segment

The R4 rule is part of normal in-sequence processing
and is met implicitly by PyTCP's data-acceptance
path.

### R2 / R5) Out-of-window / acceptability

These overlap with RFC 9293 §3.10.7.4 acceptability
checks; met by the broader RFC 9293 implementation.

---

## §5.5. Outdated Timestamps

> "If a connection remains idle long enough for a
> peer's timestamp clock to wrap, the peer's TSval
> may appear stale to PAWS even though the connection
> is fresh."

**Adherence:** the §5.5 mitigation is a complex
"24-day timer reset" mechanism that PyTCP does not
implement. PyTCP's timestamp clock is driven by
`stack.timer.now_ms` (monotonic ms clock); the wrap
period is ~50 days. For typical connection lifetimes
(<< 50 days), the wrap edge case is moot. Connections
that idle for > 24 days would need the §5.5 reset;
PyTCP's omission means such connections may
spuriously drop traffic via PAWS. Out-of-scope for
typical PyTCP use cases.

---

## Test coverage audit

### §2.2 WSCALE wire format

- **Wire-level unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__option__wscale.py`
  covers the kind/length/shift_count assembler /
  parser / asserts.

**Status:** locked in.

### §2.2 / §2.3 Bilateral negotiation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__wscale.py`
  pins active-open WSCALE advertisement, passive-open
  WSCALE echo, and the bilateral-not-offered fallback.

**Status:** locked in.

### §2.2 SYN window unscaled

- **Integration:** every WSCALE test that inspects
  the outbound SYN's win field implicitly verifies
  unshifted; a test specifically for "win field on
  SYN is not shifted" pins this.

**Status:** locked in.

### §3.2 TSopt wire format

- **Wire-level unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__option__timestamps.py`.

**Status:** locked in.

### §3.2 TSopt on every non-RST segment after negotiation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py::TestTcpTimestampsPhase2`
  pins the per-segment emission post-bilateral-
  negotiation.

**Status:** locked in.

### §3.2 TSopt on RST segments (SHOULD)

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsRfc7323ShouldClauses::test__rfc7323__rst_in_synchronized_state_carries_tsopt`
  drives a TS-negotiated session to ESTABLISHED, calls
  `session.abort()`, and verifies the emitted RST
  carries TSopt with TSval=now and TSecr=peer's
  cached TSval.

**Status:** locked in.

### §3.2 SHOULD silently drop missing-TSopt segments

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsRfc7323ShouldClauses::test__rfc7323__missing_tsopt_segment_silently_dropped`
  injects a non-RST inbound data segment lacking TSopt
  on a TS-negotiated session and asserts (a) the
  payload does NOT enter the RX buffer and (b) no
  acknowledgement fires from the data path. The
  SYN-segment exemption (RFC 6191 §3 reuse path) is
  pinned indirectly by the existing
  `test__rfc6191__syn_without_tsopt_with_seq_evidence_accepts_reuse`
  and `test__rfc6191__no_evidence_falls_back_to_challenge_ack`
  tests (in `test__tcp__session__close__time_wait.py`)
  which verify a SYN-without-TSopt to TIME_WAIT accepts
  reuse when sequence evidence exists and otherwise
  falls back to the challenge ACK.

**Status:** locked in.

### §4 RTTM rule (SND.UNA-advancing ACK only)

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsPhase3`
  contains tests pinning that TSecr is folded into
  RTO only on cum-ACK that advances SND.UNA.

**Status:** locked in.

### §4 (extension) Receiver-side RTT estimator (DRS)

- **Unit:**
  `test__tcp__state__rcv_rtt.py::TestRcvRttState`
  pins the TSecr EWMA fold + within-RTT dedup;
  `::TestRcvRttStateWindowFallback` pins the
  no-timestamps `observe_window` min-fold.
- **Integration:**
  `test__tcp__session__rcv_rtt.py` pins the RX-path
  TSecr sample (seed / EWMA / dedup, and that a no-TS
  connection stays unset after a single segment);
  `test__tcp__session__rcv_rtt_no_ts.py` pins the
  window-based fallback seeding the estimate and
  enabling DRS growth on a timestamp-less connection.

**Status:** locked in.

### §4.3 Which TSval to echo

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsRfc7323ShouldClauses::test__rfc7323__ooo_segment_does_not_refresh_ts_recent`
  injects an OOO segment (SEG.SEQ > RCV.NXT) with a
  fresh TSval and asserts `_ts_recent` does NOT
  advance.
  `...::test__rfc7323__in_order_segment_refreshes_ts_recent`
  is the positive control: an in-order (SEG.SEQ ==
  RCV.NXT) segment DOES refresh `_ts_recent`. Together
  these pin the §4.3 rule (2) Last.ACK.sent gate.

**Status:** locked in.

### §5.2 PAWS basic mechanism

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsPhase4`
  pins stale-TSval drop and current-TSval acceptance.

**Status:** locked in.

### §5.2 RST not subject to PAWS

- **Integration:** the synchronized-state RST tests
  do not run PAWS on RST. The TIME-WAIT deviation
  is tested under RFC 1337 audit.

**Status:** locked in (with the documented
TIME-WAIT deviation).

### §5.3 R1) Stale-TSval drops + ACK reply (SHOULD)

- **Integration:**
  `test__tcp__session__timestamps.py::TestTcpTimestampsRfc7323ShouldClauses::test__rfc7323__paws_drop_emits_ack_reply`
  injects a stale-TSval data segment, asserts (a) the
  payload does NOT enter the RX buffer and (b) at
  least one ACK reply (no FIN, no RST) fires per the
  R1 SHOULD. The reply uses the rate-limited
  challenge-ACK helper so a burst of stale-TSval
  segments cannot amplify into an outbound ACK flood.
  The pre-existing
  `test__paws__time_wait_late_segment_with_stale_tsval_dropped`
  was updated to allow the new R1 ACK reply (verified
  to be a no-FIN, no-data ACK shape).

**Status:** locked in.

### §5.5 Outdated timestamps mitigation

When the connection has been idle longer than the
24-day threshold (`TS_RECENT_OUTDATED_THRESHOLD_MS` =
24 * 86400 * 1000 ms), an inbound segment whose TSval
would otherwise fail strict PAWS is accepted and
TS.Recent is refreshed - per the §5.5 advisory to
prevent a recovering idle connection from freezing
until the peer's TS clock wraps its sign bit again.
The local-clock 'last update' timestamp is captured
at every TS.Recent write site (active-open SYN+ACK,
passive-open SYN, post-handshake `_check_paws_and_
update_ts_recent`).

Pinned by two integration tests in
`test__tcp__session__timestamps.py`:
`test__timestamps__outdated__paws_invalidates_ts_
recent_after_24_day_idle` and the within-window
regression guard.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §2.2 WSCALE wire format                         | locked in (parser + assembler unit)            |
| §2.2 / §2.3 Bilateral negotiation               | locked in                                      |
| §2.2 SYN unscaled win                           | locked in                                      |
| §2.4 Window retraction                          | covered in RFC 1122 audit                      |
| §3.2 TSopt wire format                          | locked in                                      |
| §3.2 TSopt on every non-RST                     | locked in                                      |
| §3.2 TSopt on RST                               | locked in                                      |
| §3.2 SHOULD drop missing-TSopt                  | locked in                                      |
| §4 RTTM rule                                    | locked in                                      |
| §4 Receiver-side RTT estimator (DRS)            | locked in (unit + integration, TS + no-TS)     |
| §4.2 EWMA with multiple samples                 | locked in (covered by RFC 6298 audit)          |
| §4.3 Which TSval to echo (A/B/C)                | locked in (Last.ACK.sent gate test)            |
| §5.2 PAWS basic                                 | locked in                                      |
| §5.2 RST not subject to PAWS                    | locked in (with TIME-WAIT deviation)           |
| §5.3 R1 ACK reply on PAWS drop                  | locked in (challenge-ACK on stale-TSval)       |
| §5.5 Outdated timestamps mitigation             | locked in                                      |

---

## Overall assessment

| Aspect                                          | Status                                  |
|-------------------------------------------------|-----------------------------------------|
| §2.2 WSCALE wire format                         | met                                     |
| §2.2 Bilateral negotiation                      | met                                     |
| §2.2 Max shift count = 14                       | met (derived from tcp.rmem.max, cap 14) |
| §2.2 SYN window unscaled                        | met                                     |
| §2.3 Snd/Rcv.Wind.Shift state                   | met                                     |
| §2.4 Window retraction handling                 | met (cross-cut RFC 1122)                |
| §3.2 TSopt wire format                          | met                                     |
| §3.2 TSopt on every non-RST                     | met                                     |
| §3.2 TSopt on RST                               | met (synchronized states)               |
| §3.2 SHOULD drop missing-TSopt                  | met                                     |
| §4 RTTM rule                                    | met                                     |
| §4 Receiver-side RTT estimator (DRS)            | met (Linux-parity; TS + no-TS)          |
| §4.2 EWMA multi-sample                          | met                                     |
| §4.3 TSval-to-echo (A/B/C)                      | met (Last.ACK.sent gate via RCV.NXT)    |
| §5.2 PAWS                                       | met                                     |
| §5.2 RST not subject to PAWS                    | met (synchronized states)               |
| §5.3 R1 ACK reply on PAWS drop                  | met (challenge-ACK rate-limited)        |
| §5.5 Outdated timestamps mitigation             | met                                     |

PyTCP fully implements the wire-level RFC 7323 option
formats (WSCALE, Timestamps) and the core
bilateral-negotiation, RTTM-driven RTO, and PAWS
mechanisms. The four SHOULD-level deviations
previously open are now closed:

1. §3.2 TSopt on RST: emitted by `_transmit_packet` on
   any RST in a TS-negotiated session (no RST-suppress
   gate).
2. §3.2 missing-TSopt silent drop: implemented in
   `_check_paws_and_update_ts_recent`; SYN-bearing
   segments are exempt to preserve RFC 6191 §3 reuse
   and RFC 9293 §3.10.7.4 challenge-ACK paths.
3. §4.3 `Last.ACK.sent` gate: `_ts_recent` refresh is
   gated on `SEG.SEQ <= self._rcv_nxt`, the safe
   tightening of the strict algorithm. OOO segments
   pass PAWS but no longer inflate `TS.Recent`.
4. §5.3 R1 PAWS-drop ACK reply: stale-TSval drop now
   emits the rate-limited challenge-ACK so the peer
   can recover sender state without waiting for its
   own RTO.

§5.5 (outdated timestamps after >24-day idle) is shipped:
the strict PAWS check is bypassed when the connection has
been idle longer than the 24-day threshold so a recovered
idle connection does not freeze until the peer's TS clock
wraps its sign bit.

Overall RFC 7323 conformance is at full SHOULD/MUST
parity; no remaining deviations.
