# RFC 5827 — Early Retransmit for TCP and SCTP

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 5827                                                 |
| Title       | Early Retransmit for TCP and Stream Control Transmission Protocol (SCTP) |
| Category    | Experimental                                         |
| Date        | April 2010                                           |
| Source text | [`rfc5827.txt`](rfc5827.txt)                         |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 5827. The audit was performed by
reading the RFC text fresh and inspecting the
codebase under `packages/pytcp/pytcp/protocols/tcp/` directly; no
prior memory or rule-file content was reused.
Sections without normative content (Abstract, §1
Introduction, §2 Terminology, §4 Discussion, §5
Related Work, §6 Security, References) are omitted.

---

## §3.1 Byte-Based Early Retransmit

### Trigger conditions

> "Upon the arrival of an ACK, a sender employing
> byte-based Early Retransmit MUST use the following
> two conditions to determine when an Early Retransmit
> is sent:
>
> (2.a) The amount of outstanding data (ownd) is less
>       than 4*SMSS bytes.
>
> (2.b) There is either no unsent data ready for
>       transmission at the sender, or the advertised
>       receive window does not permit new segments to
>       be transmitted."

**Adherence:** not implemented. PyTCP's fast-
retransmit trigger requires the canonical 3rd
duplicate ACK (RFC 5681 §3.2 path) or the SACK byte
rule (RFC 6675 §3 path) per the existing
`_retransmit_packet_request` machinery. There is no
short-flight gating that lowers the dup-ACK threshold
when `flight_size < 4*SMSS`.

### Lowered dup-ACK threshold

> "ER_thresh = ceiling (ownd/SMSS) - 1"

**Adherence:** not implemented.

### SACK-aware variant

> "When conditions (2.a) and (2.b) hold and a TCP
> connection does support SACK, Early Retransmit MUST
> be used only when 'ownd - SMSS' bytes have been
> SACKed."

**Adherence:** not implemented. PyTCP's SACK byte-
rule trigger fires when `IsLost(SND.UNA) == True` per
RFC 6675 §3, which uses fixed thresholds rather than
the Early Retransmit short-flight relaxation.

---

## §3.2 Segment-Based Early Retransmit

> "A TCP or SCTP sender MAY use segment-based Early
> Retransmit."

**Adherence:** not implemented.

---

## §6.1 Limited Transmit interaction

> "Limited Transmit (RFC 3042 / RFC 5681) sends
> previously unsent data on the first two duplicate
> ACKs to induce additional duplicate ACKs."

**Adherence:** met (Limited Transmit itself). Limited
Transmit IS implemented in PyTCP at
`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__retransmit.py:465-482`:
the first two duplicate ACKs each emit one previously-
unsent segment (bounded by `cwnd + count * SMSS` and
the peer's advertised window). See the RFC 3042
adherence record, which marks Limited Transmit met.
Only Early Retransmit's own use of Limited Transmit as
a companion trigger is absent, because ER itself is
not implemented.

---

## Test coverage audit

No Early Retransmit tests exist; the fast-retransmit
path is tested via the canonical 3rd-dup-ACK trigger
in
`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py`.

### Test coverage summary

| Aspect                                 | Coverage   |
|----------------------------------------|------------|
| §3.1 byte-based ER trigger             | n/a (gap)  |
| §3.1 ER_thresh formula                 | n/a (gap)  |
| §3.1 SACK-aware ER variant             | n/a (gap)  |
| §3.2 segment-based ER variant          | n/a (gap)  |
| §6.1 Limited Transmit interaction      | n/a (gap)  |

---

## Overall assessment

| Aspect                                | Status          |
|---------------------------------------|-----------------|
| §3.1 byte-based Early Retransmit      | not implemented |
| §3.1 SACK-aware ER                    | not implemented |
| §3.2 segment-based Early Retransmit   | not implemented |
| §6.1 Limited Transmit                 | met (RFC 3042)  |

PyTCP does not implement Early Retransmit. This
matters most for short-flight workloads (final few
segments of a transfer, application-limited flows,
small-cwnd connections) where standard fast retransmit
cannot fire because there are too few outstanding
segments to generate three duplicate ACKs. Limited
Transmit (RFC 3042) is implemented and helps when the
sender has fresh data to send on the 1st / 2nd dup-ACK;
but when there is no unsent data (the application-
limited tail case ER specifically targets), the loss
still falls through to the RTO timer, adding ≥1 second
of stalled time.

PyTCP's RACK-TLP implementation (RFC 8985) provides
a related mitigation: TLP probes elicit dup-ACKs
that can drive RACK loss detection, sidestepping the
need for the 3-dup-ACK threshold in tail-loss cases.
This partially closes the same operational gap that
RFC 5827 addresses, though it does not replace it.

Implementing Early Retransmit alongside the existing
fast-retransmit / SACK / RACK paths would require:
- A short-flight gate at the dup-ACK arrival path.
- Computation of ER_thresh from FlightSize.
- A separate "ER recovery point" marker so the
  one-shot guard does not conflict with §3.2 fast-
  recovery entry.

Estimated effort: ~3-4 commits.
