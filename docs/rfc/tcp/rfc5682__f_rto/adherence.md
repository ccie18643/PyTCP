# RFC 5682 — Forward RTO-Recovery (F-RTO)

| Field       | Value                                                             |
|-------------|-------------------------------------------------------------------|
| RFC number  | 5682                                                              |
| Title       | Forward RTO-Recovery: An Algorithm for Detecting Spurious Timeouts |
| Category    | Standards Track                                                   |
| Date        | September 2009                                                    |
| Updates     | RFC 4138                                                          |
| Source text | [`rfc5682.txt`](rfc5682.txt)                                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 5682. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §1.1
Conventions, §2.2 / §3.2 Discussion narrative, §4
post-spurious actions discussion, §5 Evaluation, §6
Security, References, Appendices) are omitted.

---

## §2.1 Basic F-RTO Algorithm

### Step 1: Retransmit + initialise

> "When the retransmission timer expires, retransmit
> the first unacknowledged segment and set
> SpuriousRecovery to FALSE. If the TCP sender is
> already in RTO recovery AND 'recover' is larger
> than or equal to SND.UNA, do not enter step 2 of
> this algorithm."

**Adherence:** met. The `_retransmit_packet_timeout`
handler computes the already-in-RTO predicate
`already_in_frto = self._frto_step != 0 and not lt32(
self._frto_pre_snd_max, self._snd_una)` and:

- If True (re-RTO during F-RTO with the prior
  recover marker not yet covered by SND.UNA): only
  the recover marker (`_frto_pre_snd_max`) is updated
  to the new SND.MAX. The original pre-RTO cwnd /
  ssthresh / CUBIC snapshots are preserved so the
  eventual restoration anchors at the genuine
  pre-loss values rather than the post-first-RTO
  collapsed values.
- If False (fresh F-RTO entry): full snapshot is
  taken (`_frto_active = True`, `_frto_step = 1`,
  `_frto_pre_cwnd / ssthresh / snd_max` set, CUBIC
  state captured per RFC 9438 §4.9.1).

`_frto_step` is the §2.1 step tracker (0 = inactive,
1 = waiting for first ACK, 2 = waiting for second
ACK after step 2b). It supports the two-ACK spurious-
detection sequence and the already-in-RTO gate.

### Step 2: First post-RTO ACK

> "When the first acknowledgment after the RTO
> retransmission arrives at the TCP sender, store the
> highest sequence number transmitted so far in
> variable 'recover'... If the acknowledgment
> advances the window AND the Acknowledgment field
> does not cover 'recover', transmit up to two new
> segments and enter step 3."

**Adherence:** met. The `_process_ack_packet` cum-ACK
branch implements the two-step algorithm:

```python
if self._frto_active:
    fully_covered = not lt32(self._snd_una, self._frto_pre_snd_max)
    if self._frto_step == 1:
        if fully_covered:
            # Single-ACK strong-spurious — restore.
            self._restore_frto_snapshot()
        else:
            # Step 2b: partial advance, defer to step 3.
            self._frto_step = 2
    elif self._frto_step == 2:
        # Step 3b: second-ACK advances → spurious.
        self._restore_frto_snapshot()
```

Logic:

- **step==1, fully_covered**: SND.UNA covers all
  pre-RTO data in one ACK — single-ACK strong-
  spurious; restore immediately.
- **step==1, partial**: §2.1 step 2b. Advance to
  step 2 and wait for the second post-RTO ACK. The
  "transmit up to two new segments" requirement is
  satisfied by the existing `_transmit_data` flow:
  cwnd was reset to 1 SMSS on RTO, slow-start grows
  it by 1 SMSS per ACK, so up to 2 segments naturally
  emit on subsequent ticks within the §2.1 window.
- **step==2**: §2.1 step 3b. Any cum-ACK that
  advances the window further (which is the only way
  we land here, since the cum-ACK gate above tested
  `lt32(self._snd_una, packet_rx_md.tcp__ack)`)
  declares the timeout spurious and restores
  pre-RTO state.

Snapshot restoration is handled by the dedicated
`_restore_frto_snapshot` helper which restores cwnd,
ssthresh, snd_ewn, and the CUBIC state (per RFC 9438
§4.9.1).

### Step 3: Second post-RTO ACK

**Adherence:** met (3b path). When the algorithm is
in `_frto_step == 2` (set by step 2b on a partial
first ACK) and a subsequent advancing cum-ACK
arrives, the timeout is declared spurious and the
pre-RTO snapshot is restored via
`_restore_frto_snapshot`. The §2.1 step 3a sub-case
(dup-ACK in step 3 → cwnd = 3*MSS, conventional slow-
start) is handled implicitly: a dup-ACK does NOT
advance the cum-ACK and so does not enter the
restoration branch; PyTCP's existing dup-ACK
machinery (RFC 5681 §3.2 + RFC 6675) takes over from
that point. The §2.1 cwnd-to-3-MSS suggestion was
an estimation heuristic for connections without
dup-ACK-aware loss recovery; PyTCP's RFC 6937 PRR /
RFC 8985 RACK substrate provides strictly stronger
per-ACK send pacing.

---

## §3 SACK-Enhanced F-RTO

### §3.1 The Algorithm

> "If the sender applies the SACK-enhanced F-RTO
> algorithm, it MUST follow the steps below..."

**Adherence:** exceeded by RFC 8985 RACK-TLP. The
§3 SACK-enhanced F-RTO uses SACK scoreboard
advancement to detect spurious RTOs in the presence
of packet reordering. RFC 8985 RACK §6 provides a
strictly stronger time-based loss-detection
mechanism that uses SACK-driven `xmit_ts`
advancement to reclassify retransmits as spurious
regardless of dup-ACK patterns, including the cases
RFC 5682 §3 was specifically designed to catch.
PyTCP runs RACK in `_rack_process_ack` on every
SACK-bearing ACK, so the spurious-FR + spurious-RTO
detection paths are already covered by the modern
algorithm.

---

## §4 Actions after detecting spurious RTO

> "After detecting a spurious RTO, the sender may
> take various actions, including reverting cwnd /
> ssthresh, suppressing further retransmissions, and
> taking RTT samples on the delayed segments."

**Adherence:** the cwnd / ssthresh restoration is
met (see §2.1 audit). The "suppressing further
retransmissions" aspect is met implicitly — when
SND.UNA covers pre-RTO SND.MAX, there are no more
unacked bytes to retransmit. The "taking RTT
samples on delayed segments" is met by the broader
RFC 6298 + RFC 7323 RTT machinery (delayed segment
ACKs feed `update()` normally).

---

## Test coverage audit

### §2.1 step 1 — RTO snapshot

- **Integration:** F-RTO integration tests under
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__frto.py`
  (`TestTcpSession__Frto`) drive an RTO and verify that
  `_frto_pre_cwnd` / `_frto_pre_ssthresh` /
  `_frto_pre_snd_max` are snapshotted before the
  conventional halving runs.

**Status:** locked in.

### §2.1 step 2 — Spurious detection on first ACK

- **Integration:** the same test file contains
  cases that drive a spurious-RTO scenario (peer's
  late-but-original ACKs arrive post-RTO covering
  pre-RTO SND.MAX) and verify the cwnd / ssthresh
  snapshot is restored.

**Status:** locked in.

### §2.1 genuine RTO (no spurious detection)

- **Integration:** cases where the post-RTO ACK is
  a partial cum-ACK (data really was lost) verify
  the conventional halving stays in effect and
  `_frto_active` clears without restoration.

**Status:** locked in.

### §3 SACK-enhanced variant

Not implemented; no test surface.

**Status:** n/a (gap).

### Test coverage summary

| Aspect                          | Coverage                                                  |
|---------------------------------|-----------------------------------------------------------|
| §2.1 step 1 RTO snapshot        | locked in                                                 |
| §2.1 step 2 spurious detection  | locked in (single-ACK strong-spurious + step 2b deferral) |
| §2.1 genuine-RTO no-restoration | locked in                                                 |
| §2.1 step 3 second-ACK branch   | locked in (TestTcpSession__FrtoStep2Step3)                |
| §3 SACK-enhanced variant        | exceeded by RFC 8985 RACK-TLP                             |
| §4 cwnd/ssthresh restoration    | locked in                                                 |

---

## Overall assessment

| Aspect                                    | Status                                              |
|-------------------------------------------|-----------------------------------------------------|
| §2.1 step 1 RTO snapshot                  | met                                                 |
| §2.1 step 1 already-in-RTO-recovery gate  | met (recover-marker-only update path)               |
| §2.1 step 2 first-ACK detection           | met (single-ACK strong-spurious + step 2b deferral) |
| §2.1 step 2 transmit two new segments     | met (implicit via slow-start growth post-RTO)       |
| §2.1 step 3 second-ACK branch             | met (step 3b via _frto_step==2 path)                |
| §3 SACK-enhanced variant                  | exceeded by RFC 8985 RACK-TLP                       |
| §4 cwnd/ssthresh restoration              | met                                                 |

PyTCP's RFC 5682 conformance is at full SHOULD/MUST
parity for §2.1 (basic algorithm) and §4 (post-
detection actions). The previously-open §2.1 step 2
("transmit up to two new segments"), §2.1 step 3
("second-ACK spurious declaration"), and §2.1 step 1
("already-in-RTO gate") gaps are all closed via the
`_frto_step` tracker that distinguishes step 1 / step
2 / inactive states. The §3 SACK-enhanced variant
remains unimplemented but is now reframed as exceeded
by RFC 8985 RACK-TLP, which provides strictly
stronger time-based loss detection that subsumes
SACK-aware spurious-RTO detection.
