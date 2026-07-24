# RFC 4015 — The Eifel Response Algorithm for TCP

| Field       | Value                                            |
|-------------|--------------------------------------------------|
| RFC number  | 4015                                             |
| Title       | The Eifel Response Algorithm for TCP             |
| Category    | Standards Track                                  |
| Date        | February 2005                                    |
| Source text | [`rfc4015.txt`](rfc4015.txt)                     |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 4015. Sections without normative
content (Abstract, §1 Introduction, §1.1 Terminology,
§4 Discussion, §5 Acknowledgements, §6 Security, §7
IANA, References) are omitted.

---

## §2 Appropriate Detection Algorithms

> "If the Eifel response algorithm is implemented at
> the TCP sender, it MUST be implemented together with
> a detection algorithm that is specified in a
> standards track or experimental RFC."

**Adherence:** Eifel response is not implemented in
PyTCP. The simplified F-RTO (RFC 5682) variant is the
spurious-RTO detector, but it does not feed an Eifel
response algorithm.

---

## §3.1 The Algorithm

### Step 0: snapshot pipe_prev / SRTT_prev / RTTVAR_prev

> "Before the variables cwnd and ssthresh get updated
> when loss recovery is initiated, set
> pipe_prev = max(FlightSize, ssthresh);
> SRTT_prev = SRTT + 2*G;
> RTTVAR_prev = RTTVAR."

**Adherence:** partial. PyTCP's F-RTO snapshot at
`packages/pytcp/pytcp/protocols/tcp/state/tcp__state__cc.py:158-173`
(`save_frto_snapshot`, called from
`session/tcp__session__retransmit.py:280`) captures
`_cc.frto_pre_cwnd`, `_cc.frto_pre_ssthresh`, and
`_cc.frto_pre_snd_max` — analogous to pipe_prev. It
does NOT snapshot SRTT_prev / RTTVAR_prev.

### Step 7: SPUR_TO branching

**Adherence:** not implemented (PyTCP doesn't track
the SpuriousRecovery state variable).

### Step 8: resume with previously-unsent data

> "If SpuriousRecovery == SPUR_TO, resume the
> transmission with previously unsent data."

**Adherence:** not implemented as such. Once F-RTO
detects spurious-RTO and restores cwnd, normal
`_transmit_data` resumes — but it does NOT prefer
new data over retransmits. The §3.1 step 8
optimization (avoiding go-back-N retransmits) is not
in PyTCP.

### Step 9: LATE_SPUR_TO branching

> "If SpuriousRecovery == LATE_SPUR_TO, take pipe_prev
> as cwnd, set ssthresh accordingly."

**Adherence:** not implemented.

### Step DONE: cwnd/ssthresh/RTO restoration

**Adherence:** partial. PyTCP's F-RTO restores cwnd
and ssthresh from the snapshot but does NOT restore
SRTT/RTTVAR/RTO. The snapshot-and-restore is also
unconditional on SpuriousRecovery being SPUR_TO —
it fires whenever SND.UNA covers pre-RTO SND.MAX,
which is roughly equivalent to the SPUR_TO
classification but reached via a different signal.

---

## Test coverage audit

No Eifel response tests exist. The cwnd / ssthresh
restoration via F-RTO is tested at
`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_timeout.py`.

### Test coverage summary

| Aspect                                  | Coverage                          |
|-----------------------------------------|-----------------------------------|
| §3.1 step 0 pipe_prev snapshot          | partial (F-RTO captures cwnd)     |
| §3.1 step 0 SRTT_prev / RTTVAR_prev     | n/a (gap)                         |
| §3.1 step 7 SpuriousRecovery branching  | n/a (gap)                         |
| §3.1 step 8 resume with unsent data     | n/a (gap)                         |
| §3.1 step 9 LATE_SPUR_TO handling       | n/a (gap)                         |
| §3.1 cwnd/ssthresh restoration          | met (F-RTO simplified)            |
| §3.1 RTO restoration                    | n/a (gap)                         |

---

## Overall assessment

| Aspect                                | Status                        |
|---------------------------------------|-------------------------------|
| §2 paired with detection algorithm    | not implemented               |
| §3.1 step 0 pipe_prev                 | met (via F-RTO snapshot)      |
| §3.1 step 0 SRTT/RTTVAR snapshot      | not implemented               |
| §3.1 step 7 SpuriousRecovery dispatch | not implemented               |
| §3.1 step 8 resume w/ unsent data     | not implemented               |
| §3.1 step 9 LATE_SPUR_TO              | not implemented               |
| §3.1 cwnd/ssthresh restoration        | met (via F-RTO simplified)    |
| §3.1 RTO doubling-on-spurious         | not implemented               |

PyTCP does not implement the Eifel response algorithm.
The cwnd/ssthresh restoration in PyTCP's F-RTO
implementation (RFC 5682, simplified one-step variant)
overlaps with what Eifel response §3.1 step DONE does,
but the steps that distinguish Eifel from F-RTO —
suppressing go-back-N retransmits in step 8, RTT
adaptation, and RTO-recalibration — are not present.

Implementing Eifel response on top of the existing
F-RTO substrate would require:
- Adding SRTT_prev / RTTVAR_prev snapshot fields.
- A `SpuriousRecovery` state variable (boolean is
  insufficient — three-valued: FALSE / SPUR_TO /
  LATE_SPUR_TO).
- A "prefer-unsent-data" branch in the post-spurious
  retransmit path.
- RTO recalibration on spurious-RTO detection.

Estimated effort: ~5-6 commits.
