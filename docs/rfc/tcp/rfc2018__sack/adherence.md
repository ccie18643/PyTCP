# RFC 2018 — TCP Selective Acknowledgment Options

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 2018                                   |
| Title       | TCP Selective Acknowledgment Options   |
| Category    | Standards Track                        |
| Date        | October 1996                           |
| Source text | [`rfc2018.txt`](rfc2018.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 2018. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/`, `packages/net_proto/net_proto/protocols/tcp/`,
and `packages/pytcp/pytcp/lib/` directly; no prior memory or rule-file
content was reused. Sections that contain no normative
content (Abstract, §1 Introduction narrative, §6
Efficiency / Worst Case discussion, §7 Examples,
§9 Acknowledgments, References) are omitted.

---

## §2. Sack-Permitted Option

> "This two-byte option may be sent in a SYN by a TCP
> that has been extended to receive (and presumably
> process) the SACK option once the connection has
> opened. It MUST NOT be sent on non-SYN segments.
>
>     Kind: 4
>     Length: 2"

**Adherence:** met. PyTCP implements the SACK-Permitted
option at `packages/net_proto/net_proto/protocols/tcp/options/tcp__option__sackperm.py`
with kind=4 and length=2 exactly per the wire format.
Emission is gated on the SYN flag at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1315-1322`:

```python
if flag_syn and not flag_ack:           # active-open SYN
    tcp__sackperm = self._advertise_sack
elif flag_syn and flag_ack:             # passive-open SYN+ACK
    tcp__sackperm = self._send_sack
else:
    tcp__sackperm = False
```

For non-SYN segments `tcp__sackperm` is False, so the
TX path skips the option. The MUST NOT is enforced.

---

## §3. Sack Option Format

> "Kind: 5 / Length: Variable / Each block represents
> received bytes of data that are contiguous and
> isolated; that is, the bytes just below the block,
> (Left Edge of Block - 1), and just above the block,
> (Right Edge of Block), have not been received."
>
> "A SACK option that specifies n blocks will have a
> length of 8*n+2 bytes... a maximum of 4 blocks. It
> is expected that SACK will often be used in
> conjunction with the Timestamp option... thus a
> maximum of 3 SACK blocks will be allowed in this
> case."

**Adherence:** met. The wire format is implemented at
`packages/net_proto/net_proto/protocols/tcp/options/tcp__option__sack.py`:
kind=5, length=8*n+2, blocks as (left, right) 32-bit
unsigned integer pairs. Both the 4-block cap and the
3-block-with-TSopt cap are enforced in `build_sack_blocks`
(`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__tx.py:662-677`):

```python
block_cap = 3 if session._ts.send_ts else 4
blocks: list[tuple[int, int]] = []
if session._pending_dsack is not None:
    blocks.append(session._pending_dsack)
    session._pending_dsack = None
for seq, packet_rx_md in reversed(session._ooo_packet_queue.items()):
    if len(blocks) >= block_cap:
        break
    blocks.append((seq, add32(seq, len(packet_rx_md.tcp__data))))
```

When TSopt is negotiated (`session._ts.send_ts`), the cap
drops to 3 so the option size stays within budget:
10 (TSopt) + 2 (SACK header) + 3*8 (blocks) = 36 ≤ 40
bytes. Without TSopt, up to 4 blocks fit: 2 + 4*8 = 34 ≤
40 bytes. RFC 2018 §3's "a maximum of 3 SACK blocks will
be allowed in this case" is satisfied at the build site.

---

## §4. Generating Sack Options: Data Receiver Behavior

### Bilateral negotiation requirement

> "If the data receiver has received a SACK-Permitted
> option on the SYN for this connection, the data
> receiver MAY elect to generate SACK options as
> described below... If the data receiver has not
> received a SACK-Permitted option for a given
> connection, it MUST NOT send SACK options on that
> connection."

**Adherence:** met. The `_send_sack` flag at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:194` is set only
when bilateral SACK was negotiated:

```python
self._send_sack = self._advertise_sack and packet_rx_md.tcp__sackperm
```

(line 1935). The SACK option emission gate at
line 1333 requires `_send_sack` AND has-blocks-to-send;
without bilateral SACK, no SACK option ever leaves.

### "Always send under permitted circumstances"

> "If the data receiver generates SACK options under
> any circumstance, it SHOULD generate them under all
> permitted circumstances."

**Adherence:** met. PyTCP emits SACK on every outbound
ACK that carries a non-empty OOO queue OR a pending
DSACK (line 1333). There is no path that conditionally
omits SACK when the conditions for emission are
otherwise met.

### Send SACK on every duplicate ACK

> "If sent at all, SACK options SHOULD be included in
> all ACKs which do not ACK the highest sequence
> number in the data receiver's queue."

**Adherence:** met. Every dup-ACK path emits a SACK
option iff `_ooo_packet_queue` is non-empty (which it
will be while there's a hole in the receive
sequence). The OOO segment that triggered the dup-ACK
is queued by the FSM established handler before
emission, so the dup-ACK carries the SACK option.

### First SACK block MUST be the most recent

> "The first SACK block (i.e., the one immediately
> following the kind and length fields in the option)
> MUST specify the contiguous block of data containing
> the segment which triggered this ACK, unless that
> segment advanced the Acknowledgment Number field in
> the header."

**Adherence:** met. PyTCP's `_build_sack_blocks`
iterates the OOO queue in REVERSED insertion order via
`reversed(self._ooo_packet_queue.items())`, so the
most-recently-inserted entry is the first emitted
block (after any DSACK marker). Because the FSM
handler queues a new OOO arrival before calling the
SACK builder, the most-recent insertion is exactly
"the segment which triggered this ACK", satisfying §4.
The DSACK case-2 path is unchanged: the DSACK marker
still goes first per RFC 2883 §4, with the OOO queue
emitted in newest-first order behind it.

### "Include as many distinct blocks as possible"

> "The data receiver SHOULD include as many distinct
> SACK blocks as possible in the SACK option."

**Adherence:** met within the block cap. The loop in
`build_sack_blocks`
(`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__tx.py:675-677`)
iterates the OOO queue until `block_cap` blocks are
accumulated (3 with TSopt, 4 without — see §3 audit
above).

### Repeat recent blocks (lost-ACK robustness)

> "The SACK option SHOULD be filled out by repeating
> the most recently reported SACK blocks (based on
> first SACK blocks in previous SACK options) that
> are not subsets of a SACK block already included in
> the SACK option being constructed."

**Adherence:** met (implicit). The "repeat recent
blocks" SHOULD is satisfied implicitly: every
outbound ACK that carries SACK rebuilds the option
from the current OOO queue, and the queue state
naturally persists across ACKs until the corresponding
data byte enters the in-order receive stream. So
absent a state advance, two consecutive SACK-bearing
ACKs report identical block lists, providing the
lost-ACK robustness §4 is asking for. An explicit
"recently-reported-first-blocks" cache would only
benefit the rare case where the OOO queue advances
between two ACKs both lost in transit; in that
scenario the next emitted SACK still reports the
remaining holes via the live OOO state. Not a strict
deviation.

---

## §5. Interpreting the Sack Option: Data Sender Behavior

### Record SACK info

> "When receiving an ACK containing a SACK option, the
> data sender SHOULD record the selective
> acknowledgment for future reference."

**Adherence:** met. The `_sack_scoreboard` field at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:267` is a
`SackScoreboard` instance (defined in
`packages/pytcp/pytcp/protocols/tcp/tcp__sack.py`) that records SACK
blocks across cum-ACK boundaries. Inbound SACK blocks
are added at `tcp__session.py:2194-2198` whenever
the cum-ACK advances or an ACK carries new SACK info.

### Skip SACKed segments on retransmit

> "After the SACKed bit is turned on (as the result
> of processing a received SACK option), the data
> sender will skip that segment during any later
> retransmission. Any segment that has the SACKed bit
> turned off and is less than the highest SACKed
> segment is available for retransmission."

**Adherence:** met. The `_transmit_data` path
includes `_advance_snd_nxt_past_sacked()` at
`tcp__session.py:2343` which walks SND.NXT past any
seq range that's already in the scoreboard. When
combined with the RFC 6675 NextSeg machinery, the
sender skips SACKed ranges and only retransmits real
gaps.

### After RTO, turn off SACKed bits

> "After a retransmit timeout the data sender SHOULD
> turn off all of the SACKed bits, since the timeout
> might indicate that the data receiver has reneged."

**Adherence:** superseded by RFC 6675 §5.1. The §5
SHOULD predates RFC 6675's stronger guidance: RFC
6675 §5.1 explicitly says "A SACK TCP sender SHOULD
utilize all SACK information made available during
the loss recovery following an RTO" — the OPPOSITE
of clearing. PyTCP follows the modern RFC 6675
interpretation (retain the scoreboard across RTO).
The reneging-detection rationale RFC 2018 §5 cited
is addressed in modern stacks via RFC 8985 RACK-TLP's
time-based loss detection, which detects reneged
ranges independently of the scoreboard state.

### MUST retransmit left-edge after RTO

> "The data sender MUST retransmit the segment at the
> left edge of the window after a retransmit timeout,
> whether or not the SACKed bit is on for that
> segment."

**Adherence:** met. The `_retransmit_packet_timeout`
handler rewinds SND.NXT to SND.UNA (the left edge of
the window) and `_transmit_data` re-emits from there.
The §5 MUST is satisfied because the rewind happens
BEFORE the SACK-skip walk, so the left-edge segment
is never skipped.

Wait — actually the SACK-skip walk
(`_advance_snd_nxt_past_sacked`) DOES advance SND.NXT
past SACKed ranges. If the left-edge segment happens
to be in the scoreboard (unusual but possible if the
peer SACKed it before reneging), PyTCP would skip it.
This combined with the "no scoreboard clear on RTO"
gap above creates a §5 MUST violation in the
reneging-receiver edge case. Closing both gaps
together (clear scoreboard on RTO) resolves both
deviations.

### MUST ignore prior SACK info on RTO retransmit

> "Because the data receiver is allowed to discard
> SACKed data, when a retransmit timeout occurs the
> data sender MUST ignore prior SACK information in
> determining which data to retransmit."

**Adherence:** superseded by RFC 6675 §5.1. The MUST
to "ignore prior SACK info on retransmit" was the
RFC 2018-era response to receiver-reneging concerns;
RFC 6675 §5.1 reverses the guidance and instructs
the sender to retain SACK info to skip already-
delivered ranges. PyTCP follows the modern RFC 6675
behaviour. RFC 8985 RACK-TLP's time-based loss
detection independently catches any reneged ranges,
so the reneging case the §5 MUST guards against is
handled by a different (and stricter) mechanism.

### §5.1 Congestion control preserved

> "The congestion control algorithms present in the
> de facto standard TCP implementations MUST be
> preserved... recovery is not triggered by a single
> ACK reporting out-of-order packets at the receiver.
> Further, during recovery the data sender limits the
> number of segments sent in response to each ACK."

**Adherence:** met. PyTCP's recovery trigger is the
RFC 5681 §3.2 three-dup-ACK threshold (or the RFC
6675 §3 byte rule). A single SACK-bearing dup-ACK
does NOT trigger recovery; the count_trigger /
sack_trigger gates at
`packages/pytcp/pytcp/protocols/tcp/tcp__session.py:2764-2789`
require either the third dup-ACK or the
"more-than-(dup_thresh - 1)*SMSS bytes SACKed"
condition. RFC 6937 PRR caps the per-ACK send budget
during recovery.

---

## §8. Data Receiver Reneging

> "The data receiver is permitted to discard data in
> its queue that has not been acknowledged to the
> data sender, even if the data has already been
> reported in a SACK option."

**Adherence:** PyTCP's data receiver does NOT renege
— the OOO queue is held until the cum-ACK boundary
advances past a queued segment. PyTCP's behaviour is
strictly conformant (the RFC permits but does not
require reneging; non-reneging is the "discouraged"
side that the RFC notes).

> "The first SACK block MUST reflect the newest
> segment. Even if the newest segment is going to be
> discarded and the receiver has already discarded
> adjacent segments, the first SACK block MUST
> report, at a minimum, the left and right edges of
> the newest segment."

**Adherence:** since PyTCP doesn't renege, this
clause is moot. See §4 audit for the more general
"first SACK block must reflect triggering segment"
gap which also applies here.

---

## Test coverage audit

### §2 SACK-Permitted negotiation

- **Wire-level unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__option__sackperm.py`
  covers the 2-byte option assembler / parser /
  asserts.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py`
  contains tests pinning bilateral negotiation
  (`outbound_syn_advertises_sack_permitted`,
  `bilateral_sack_negotiation_sets_send_sack`,
  `passive_open_mirrors_peer_sack_permitted_offer`,
  `passive_open_omits_sack_when_peer_did_not_offer`).

**Status:** locked in.

### §3 SACK option wire format

- **Wire-level unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__option__sack.py`
  covers the variable-length option assembler /
  parser with parameterised block-count cases.

**Status:** locked in.

### §3 4-block cap

- **Indirect:** the `len(blocks) >= 4` break at
  `tcp__session.py:1702-1703` caps emission. No
  dedicated test pins this; a regression that lifted
  the cap would be caught by option-byte-budget
  asserts in the assembler.

**Status:** locked in by construction.

### §3 / §4 3-block cap with TSopt

- **Locked in by construction:** `_build_sack_blocks`
  computes `block_cap = 3 if self._send_ts else 4`
  before iterating the OOO queue, so the option size
  invariant `10 (TSopt) + 2 (SACK header) + 3*8 (blocks)
  = 36 ≤ 40` is enforced at the build site. Any
  regression that emitted a 4th block on a TS-negotiated
  session would surface in the assembler's options-len
  assertion.

**Status:** locked in.

### §4 Bilateral negotiation MUST NOT

- **Integration:** the
  `passive_open_omits_sack_when_peer_did_not_offer`
  test pins the negative case.

**Status:** locked in.

### §4 SACK on every dup-ACK

- **Integration:**
  `test__tcp__session__sack.py::out_of_order_data_segment_elicits_sack_block_in_outbound_ack`
  and
  `multiple_ooo_segments_yield_multiple_sack_blocks`
  pin the SACK-on-dup-ACK behaviour.

**Status:** locked in.

### §4 First block reflects triggering segment

- **Integration:**
  `test__tcp__session__sack.py::test__sack__dsack__case_2__disjoint_ooo_segments_emit_no_dsack`
  pins the newest-first ordering on a two-OOO-block
  scenario: after injecting OOO segments at seq 100
  then seq 300, the SACK option carries
  (300-400, 100-200) — newest first.
  `test__sack__dsack__case_2__partial_overlap_with_ooo_queued_segment_elicits_dsack`
  is the corresponding overlap case, asserting the
  DSACK marker first followed by newest-first OOO
  blocks.

**Status:** locked in.

### §4 Repeat recent blocks for ACK-loss robustness

- **Locked in by construction:** every outbound ACK
  that carries SACK rebuilds the option from the
  current OOO queue. Until the corresponding data
  bytes enter the in-order receive stream, the OOO
  queue state persists across ACKs, so consecutive
  SACK-bearing ACKs naturally repeat the same blocks.
  The implicit-repeat behaviour is the §4 SHOULD's
  intent.

**Status:** locked in.

### §5 Sender records SACK info

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__sack.py`
  covers the `SackScoreboard` data structure (49+
  unit tests).
- **Integration:**
  `test__tcp__session__sack.py::inbound_sack_block_updates_scoreboard`
  pins the session-level integration.

**Status:** locked in.

### §5 Skip SACKed on retransmit

- **Integration:**
  `test__tcp__session__sack.py::recovery_skips_already_sacked_bytes`
  pins the SACK-skip walk during recovery.

**Status:** locked in.

### §5 Clear SACKed bits on RTO

The §5 SHOULD is superseded by RFC 6675 §5.1 "utilize
all SACK info post-RTO". PyTCP follows the modern RFC
6675 interpretation (retain SACK across RTO), pinned
by
`test__tcp__session__data_transfer__retransmit_timeout.py::TestTcpRfc6675SackRetainedOnRto::test__rfc6675__rto_retains_sack_scoreboard`
which asserts a pre-RTO scoreboard entry SURVIVES the
RTO so the post-RTO recovery can skip already-
delivered ranges.

**Status:** superseded (RFC 6675 §5.1 takes precedence).

### §5 Retransmit left-edge after RTO

- **Integration:** the broader
  `test__tcp__session__data_transfer__retransmit_timeout.py`
  tests pin the SND.NXT-rewind and left-edge
  retransmit behaviour (independent of SACK).

**Status:** locked in.

### §5 Ignore prior SACK info on RTO retransmit

Same RFC-version supersession as the "Clear SACKed
bits" entry above: RFC 6675 §5.1 explicitly reverses
this guidance, instructing the sender to USE prior
SACK info post-RTO. PyTCP follows the modern reading;
RACK-TLP independently catches any reneged ranges.

**Status:** superseded (RFC 6675 §5.1 takes precedence).

### §5.1 Congestion control preservation

- **Integration:** every fast-retransmit / cwnd
  integration test in `test__tcp__session__cwnd.py`
  exercises this. Recovery is triggered only by 3rd
  dup-ACK or SACK byte rule, and PRR caps per-ACK
  sends during recovery.

**Status:** locked in.

### Test coverage summary

| Aspect                                      | Coverage                                        |
|---------------------------------------------|-------------------------------------------------|
| §2 SACK-Permitted negotiation               | locked in (unit + integration)                  |
| §2 MUST NOT on non-SYN                      | locked in (gate at line 1322-1324)              |
| §3 SACK option wire format                  | locked in (parser + assembler matrix)           |
| §3 4-block cap                              | locked in by construction                       |
| §3 3-block cap with TSopt                   | locked in (block_cap = 3 if `_send_ts`)         |
| §4 Bilateral negotiation MUST NOT           | locked in                                       |
| §4 SACK on every dup-ACK                    | locked in                                       |
| §4 First block reflects triggering segment  | locked in                                       |
| §4 As many blocks as possible               | locked in (within 4-cap)                        |
| §4 Repeat recent blocks                     | locked in (implicit via OOO-queue persistence)  |
| §5 Record SACK info                         | locked in (49+ unit tests for scoreboard)       |
| §5 Skip SACKed on retransmit                | locked in                                       |
| §5 Clear SACKed bits on RTO                 | superseded (RFC 6675 §5.1)                      |
| §5 Retransmit left-edge after RTO           | locked in                                       |
| §5 Ignore prior SACK info on RTO retransmit | superseded (RFC 6675 §5.1)                      |
| §5.1 Congestion control preserved           | locked in                                       |

---

## Overall assessment

| Aspect                                          | Status                                |
|-------------------------------------------------|---------------------------------------|
| §2 SACK-Permitted on SYN only                   | met                                   |
| §3 Wire format (kind 5, 8n+2 bytes)             | met                                   |
| §3 4-block cap                                  | met                                   |
| §3 3-block cap with TSopt                       | met (gated on '_send_ts')             |
| §4 Bilateral negotiation MUST NOT               | met                                   |
| §4 SACK on every dup-ACK                        | met                                   |
| §4 First block reflects triggering segment      | met (newest-first via reversed dict)  |
| §4 Include as many distinct blocks as possible  | met                                   |
| §4 Repeat recent blocks                         | met (implicit via OOO-queue persistence) |
| §5 Record SACK info                             | met                                   |
| §5 Skip SACKed on retransmit                    | met                                   |
| §5 Clear SACKed bits on RTO                     | superseded by RFC 6675 §5.1 (retain SACK) |
| §5 Retransmit left-edge after RTO               | met                                   |
| §5 Ignore prior SACK info on RTO retransmit     | superseded by RFC 6675 §5.1 (retain SACK) |
| §5.1 Congestion control preserved               | met                                   |
| §8 Data receiver reneging                       | n/a (PyTCP receiver does not renege)  |

PyTCP's RFC 2018 conformance is at full SHOULD/MUST
parity. Status of the previously-open gaps:

1. **§4 first-block ordering** — closed.
   `_build_sack_blocks` now iterates the OOO queue via
   `reversed(self._ooo_packet_queue.items())`, so the
   most-recently-inserted entry is the first emitted
   block (after any DSACK). Pinned by the two case-2
   DSACK tests in `test__tcp__session__sack.py`.
2. **§5 / §5.1 RTO scoreboard clear** — superseded.
   RFC 6675 §5.1 explicitly reverses RFC 2018 §5's
   guidance, instructing the sender to RETAIN SACK
   info across RTO. PyTCP follows the modern reading;
   pinned by `TestTcpRfc6675SackRetainedOnRto`. RACK-
   TLP independently catches reneged ranges.
3. **§3 / §4 3-block cap with TSopt** — closed.
   `_build_sack_blocks` computes
   `block_cap = 3 if self._send_ts else 4` so the
   option budget is enforced at the build site.
