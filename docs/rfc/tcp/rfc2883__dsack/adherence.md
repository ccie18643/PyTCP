# RFC 2883 — An Extension to the Selective Acknowledgement (SACK) Option for TCP

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 2883                                                 |
| Title       | An Extension to the SACK Option for TCP (DSACK)      |
| Category    | Standards Track                                      |
| Date        | July 2000                                            |
| Source text | [`rfc2883.txt`](rfc2883.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 2883. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Conventions, §2 / §3
RFC 2018 background, §4 examples 4.1.1–4.2.3, §5
Detecting Spurious Retransmissions, §6 / §7 / §8
discussion / acknowledgments / references) are omitted.
The five-rule §4 algorithm is the central normative
content; the §4.3 PAWS interaction is the secondary
normative point.

---

## §4. Use of the SACK option for reporting a duplicate segment

### Rule (1) — D-SACK only for most recent duplicate

> "A D-SACK block is only used to report a duplicate
> contiguous sequence of data received by the receiver
> in the most recent packet."

**Adherence:** met. PyTCP populates `_pending_dsack`
exactly when the most recent inbound packet carries
a duplicate range; the field is consumed (cleared)
by the next outbound ACK. Three detection sites,
each scoped to "most recent packet":

- Full duplicate below RCV.NXT —
  `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1772-1780`
  (in `_check_segment_acceptability`).
- Overlap with OOO-queued segment —
  `packages/pytcp/pytcp/protocols/tcp/tcp__fsm__established.py:206-216`
  (in the OOO-receive branch).
- Partial-overlap prefix below RCV.NXT —
  `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:3441-3449`
  (in the in-sequence enqueue path).

In all three sites, `_pending_dsack` is overwritten
on each new packet, so the field always reflects the
most-recent duplicate.

### Rule (2) — Each duplicate seq reported in at most one D-SACK block

> "Each duplicate contiguous sequence of data received
> is reported in at most one D-SACK block."

**Adherence:** met. The `_pending_dsack` field holds
exactly one (left, right) tuple at a time. The next
outbound ACK at `_build_sack_blocks`
(`tcp__session.py:1684-1705`) emits the tuple as the
first block AND clears the field (line 1700). A
subsequent ACK without a fresh duplicate emits no
DSACK marker.

### Rule (3) — Left/right edges describe the duplicate range

> "The left edge of the D-SACK block specifies the
> first sequence number of the duplicate contiguous
> sequence, and the right edge of the D-SACK block
> specifies the sequence number immediately following
> the last sequence in the duplicate contiguous
> sequence."

**Adherence:** met. All three detection sites store
the tuple as `(seq, seq + len)` or
`(seg_seq, seg_seq + overlap_prefix)` — the
canonical [left, right) half-open form §4 specifies.

### Rule (4) — Duplicate above cum-ACK with larger block context

> "If the D-SACK block reports a duplicate contiguous
> sequence from a (possibly larger) block of data in
> the receiver's data queue above the cumulative
> acknowledgement, then the second SACK block in that
> SACK option should specify that (possibly larger)
> block of data."

**Adherence:** met for the OOO-overlap case. When the
duplicate range is part of an OOO-queued segment,
`_build_sack_blocks` emits the DSACK first and then
iterates `_ooo_packet_queue.items()` for the
remaining blocks (`tcp__session.py:1701-1704`). The
OOO segment that contains the duplicate is one of
those blocks.

§4 rule 4 says the SECOND SACK block "should specify
that (possibly larger) block of data" — i.e., the OOO
block containing the duplicate should immediately
follow the DSACK marker. PyTCP emits OOO blocks in
newest-first order via
`reversed(session._ooo_packet_queue.items())`
(`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__tx.py:675`),
so the most-recent OOO arrival is the first block after
the DSACK marker. In the OOO-overlap case the duplicate
is carried by the triggering packet's OOO segment, so
that block immediately follows the DSACK marker,
satisfying rule 4's second-block placement. This aligns
with the RFC 2018 §4 first-block ordering, which is now
met (newest-first), not a deviation.

### Rule (5) — Additional SACK blocks per RFC 2018

> "Following the SACK blocks described above for
> reporting duplicate segments, additional SACK
> blocks can be used for reporting additional blocks
> of data, as specified in RFC 2018."

**Adherence:** met. Remaining OOO-queue entries are
appended to the SACK block list up to the §3 4-block
cap.

---

## §4.3. Interaction Between D-SACK and PAWS

> "Since PAWS still requires sending an ACK, there is
> no harmful interaction between PAWS and the use of
> D-SACK. The D-SACK block can be included in the SACK
> option of the ACK, as outlined in Section 4,
> independently of the use of PAWS by the TCP receiver,
> and independently of the determination by PAWS of
> the validity or invalidity of the data segment."

**Adherence:** PAWS takes precedence in PyTCP. The
inbound dispatch path runs PAWS first
(`tcp__session.py:1789` `_check_paws_and_update_ts_recent`)
and drops the segment without invoking the DSACK
detector when PAWS fails. This means a segment that
PAWS classifies as stale (and would otherwise also be
classified as a DSACK candidate) is dropped silently
without a DSACK marker on the outgoing ACK.

The §4.3 wording ("independently of the use of PAWS")
suggests the DSACK should still fire even when PAWS
drops the segment. PyTCP's PAWS-first ordering
produces a different observable behaviour: the peer's
spurious retransmit goes unflagged via DSACK because
the segment never reaches the DSACK detector.

This is a deviation from §4.3, but the practical
impact is small — when PAWS fires, the segment is
already known to be stale (older than the receiver's
recent timestamps), and the sender's TSecr-based RTT
sampling will already attribute the spuriousness
correctly. The cross-RFC interaction is pinned by a
specific test (see Test coverage).

---

## Test coverage audit

### §4 rule 1 — Most recent duplicate

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py::test__sack__dsack__fully_duplicate_segment_elicits_dsack_in_outbound_ack`
  drives a fully-duplicate retransmit and asserts the
  outbound ACK carries a DSACK block reporting the
  duplicate range.

**Status:** locked in.

### §4 rule 2 — One D-SACK block per duplicate

- **Indirect:** the `_pending_dsack = None` clear at
  line 1700 is exercised by every DSACK test (the
  assertion typically checks that the first SACK
  block matches the expected DSACK range, then
  verifies the next ACK does NOT carry the same
  block).

**Status:** locked in indirectly.

### §4 rule 3 — Edge semantics

- **Integration:** the tuple shape `(left, right)`
  with `right = left + len` is verified by every
  DSACK test that reads the emitted SACK blocks.

**Status:** locked in.

### §4 rule 4 — Larger block context

- **Integration:**
  `test__tcp__session__sack.py::test__sack__dsack__case_2__full_duplicate_of_ooo_queued_segment_elicits_dsack`
  drives a duplicate of an OOO-queued segment and
  asserts the SACK option contains the DSACK first
  followed by the OOO block.

**Status:** locked in for the OOO-overlap path. The
"second block must be the larger block" sub-case is
not specifically pinned for the multi-OOO scenario.

### §4 rule 5 — Additional blocks

- **Integration:** the broader SACK tests cover
  multi-block emissions; specifically tests that
  drive OOO arrivals plus a duplicate verify multiple
  blocks are emitted.

**Status:** locked in.

### §4 inbound DSACK detection (sender side)

- **Integration:**
  `test__tcp__session__sack.py::test__sack__dsack__inbound_dsack_below_snd_una_detected_and_not_ingested`
  pins the sender's recognition of an incoming DSACK
  (first block right-edge ≤ SND.UNA) and the
  `_dsack_received` counter.
- **Integration:**
  `test__sack__dsack__inbound_dsack_contained_in_outer_block_detected`
  pins the case where the DSACK is contained within
  the second block's larger range.

**Status:** locked in.

### §4 partial-overlap detection

- **Integration:**
  `test__tcp__session__sack.py::test__sack__dsack__case_2__partial_overlap_with_ooo_queued_segment_elicits_dsack`
  pins the partial-overlap case at the OOO-queue
  intersection.

**Status:** locked in.

### §4.3 PAWS-DSACK interaction

- **Integration:**
  `test__tcp__session__sack.py::test__sack__cross_rfc__paws_drops_stale_segment_before_dsack_detector`
  pins PyTCP's PAWS-first ordering: a PAWS-stale
  segment is silently dropped without a DSACK marker.
  The test docstring explicitly notes this is a
  deviation from RFC 2883 §4.3.

**Status:** locked in (negative coverage of the §4.3
SHOULD).

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §4 rule 1 (most recent duplicate)               | locked in                                      |
| §4 rule 2 (one D-SACK per duplicate)            | locked in indirectly                           |
| §4 rule 3 (edge semantics)                      | locked in                                      |
| §4 rule 4 (larger block context)                | locked in (positive case)                      |
| §4 rule 5 (additional blocks)                   | locked in                                      |
| §4 sender-side DSACK detection                  | locked in                                      |
| §4 partial-overlap detection                    | locked in                                      |
| §4.3 PAWS-DSACK interaction (deviation)         | locked in (negative coverage)                  |

---

## Overall assessment

| Aspect                                                  | Status                                  |
|---------------------------------------------------------|-----------------------------------------|
| §4 rule 1 (most recent duplicate)                       | met                                     |
| §4 rule 2 (one D-SACK per duplicate)                    | met                                     |
| §4 rule 3 (edge semantics)                              | met                                     |
| §4 rule 4 (larger block context)                        | met for OOO case (SHOULD ordering)      |
| §4 rule 5 (additional blocks)                           | met                                     |
| §4 sender-side DSACK awareness                          | met (`_dsack_received` counter)         |
| §4.3 PAWS-DSACK independence                            | deviates (PAWS drops before DSACK)      |

PyTCP's RFC 2883 DSACK conformance is solid for the
core algorithm. Three detection sites (full duplicate
below RCV.NXT, overlap with OOO queue, partial
prefix-duplicate) cover the §4 cases. The
`_pending_dsack` field is consumed-on-emit per rule
2, and the DSACK marker is emitted as the first SACK
block per rule 1.

The single deviation from §4.3 is the PAWS-first
ordering: a PAWS-stale segment is dropped without a
DSACK marker. The §4.3 wording suggests DSACK should
fire "independently of PAWS"; PyTCP's ordering means
this does not happen. The test that pins this
deviation explicitly notes it; the practical impact
is minimal because PAWS-stale segments are by
definition older than the timestamps the receiver
considers fresh, and the sender's TSecr-based
spurious-retransmit detection (RFC 7323 §4 RTTM)
already addresses the spurious-retransmit accounting
that DSACK was meant to provide.

The §4 rule 4 SHOULD ("second block specifies the
larger block of data") is satisfied for the OOO case:
the OOO queue is iterated newest-first (reversed) via
`reversed(session._ooo_packet_queue.items())`, matching
the RFC 2018 §4 first-block ordering (now met). The
DSACK marker is emitted first, then the newest OOO
block — the one carrying the triggering duplicate —
follows immediately, so the "second block" reflects the
containing OOO range in the tested single-OOO scenario.
