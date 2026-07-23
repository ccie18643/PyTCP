# RFC 8311 — Relaxing Restrictions on ECN Experimentation

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 8311                                                 |
| Title       | Relaxing Restrictions on ECN Experimentation         |
| Category    | Standards Track                                      |
| Date        | January 2018                                         |
| Updates     | RFC 3168, 4341, 4342, 5622, 6679                     |
| Source text | [`rfc8311.txt`](rfc8311.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8311. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §1.1
Terminology, §1.2 Requirements, §2 Overview, §3 ECN
Nonce closure, §5 / §6 RTP / DCCP cross-cuts, §7 IANA,
§8 Security, References) are omitted.

RFC 8311 is a meta-RFC that **relaxes** restrictions
in RFC 3168 to enable experimentation rather than
imposing new requirements. The §4 updates permit
behaviours that RFC 3168 previously forbade, but do
not require any implementation to adopt them.
PyTCP's adherence question is therefore "which §4
relaxations does PyTCP take advantage of?" rather
than "which mandates does PyTCP meet?"

---

## §4. Updates to RFC 3168

### §4.1 Congestion Response Differences

> "ECN deployments could use feedback indications
> based on a more accurate count of CE-marked
> packets to enable adjustments to TCP behavior to
> obtain better performance... Such adjustments are
> allowed when the new TCP behavior has been
> documented in an Experimental RFC."

**Adherence:** PyTCP takes advantage of this
relaxation via two mechanisms:

1. **RFC 8511 ABE (Alternative Backoff with ECN)**:
   the cwnd reduction on ECE event uses a 17/20
   multiplier instead of RFC 3168's strict 1/2.
   Implemented in `compute_ecn_event_ssthresh` at
   `packages/pytcp/pytcp/protocols/tcp/tcp__cwnd.py:145-175`. The
   inline citation explicitly references RFC 8511.

2. **RFC 9768 AccECN (Accurate ECN)**: PyTCP
   supports the AccECN feedback that conveys CE-mark
   counts beyond a single-bit ECE flag. Advertised
   via `AdvertiseState.accecn`
   (`tcp__state__advertise.py:73`) and the AE+CWR+ECE
   handshake encoding in
   `fsm/tcp__fsm__syn_sent.py:365-369`.

Both mechanisms are documented in their own RFCs
(8511, 9768), satisfying the §4.1 "documented in an
Experimental RFC" gating clause for the more
aggressive cwnd response behaviour.

### §4.2 Congestion Marking Differences

> "Marking based on a virtual queue can be used to
> implement a low-loss high-throughput service
> based on existing congestion control protocols
> (i.e., supporting connections from existing
> deployed senders)."

**Adherence:** PyTCP is a host stack, not a router.
Marking is router behaviour; this clause does not
apply to PyTCP's role as an ECN-capable sender.

> "Different ECT codepoints can be used to convey
> finer-granularity feedback... For example, the
> ECT(1) codepoint can be used to indicate
> finer-granularity feedback in the L4S
> architecture."

**Adherence:** not implemented. PyTCP uses ECT(0)
unconditionally on outbound segments
(`ip__ecn = 2` at line 1500). It does NOT use
ECT(1) for L4S-style finer feedback. RFC 8311 §4.2
permits this experimentation; PyTCP has not
adopted it.

### §4.3 TCP Control Packets and Retransmissions

> "RFC 3168 disallows the use of ECN with TCP
> control packets or with retransmitted segments,
> as the loss of these segments could affect the
> ability to abort or close down a TCP connection
> efficiently. This memo updates RFC 3168 to allow
> the use of ECN with TCP control packets and
> retransmitted segments."

**Adherence:** not leveraged. PyTCP does NOT take
advantage of the §4.3 relaxation — it keeps the
conservative RFC 3168 behaviour, marking both
control packets (SYN, FIN, RST, pure ACKs) and
retransmitted segments Not-ECT. The gate at
`packages/pytcp/pytcp/protocols/tcp/session/tcp__session__tx.py:244-245`:

```python
is_retransmit = bool(data) and lt32(seq, session._snd_seq.max)
ip__ecn = 2 if (session._ecn.enabled and data and not is_retransmit) else 0
```

emits ECT(0) only when `data` is non-empty **and**
the segment is not a retransmit. Control packets
have empty `data`, so they get Not-ECT; retransmits
are excluded by the explicit `not is_retransmit`
term, so they get Not-ECT too.

So:

- TCP control packets carry Not-ECT (PyTCP
  conformant with RFC 3168 conservative default).
- Retransmits carry Not-ECT (PyTCP keeps the RFC
  3168 §6.1.5 restriction; it does NOT adopt the
  §4.3 relaxation).

The "RFC 3168 §6.1.5 met" invariant noted in the RFC
3168 audit therefore holds — PyTCP does not relax it
under RFC 8311 §4.3.

---

## Test coverage audit

### §4.1 ABE / AccECN cwnd response

- **Integration:** ABE tests under
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py`
  pin the 17/20 ssthresh reduction.
- **Integration:** AccECN tests pin the more
  granular feedback codepoints.

**Status:** locked in (both tested via their
respective RFC adherence records).

### §4.2 Marking variants

PyTCP is host-side; router marking is out of scope.
No test surface.

**Status:** n/a.

### §4.3 ECT on retransmits / control packets

The "control packets carry Not-ECT" invariant is
implicitly verified by every ECN integration test
that checks `ip__ecn` on outbound non-data segments.
The "retransmits carry Not-ECT" behaviour is not
specifically tested but follows from the explicit
`not is_retransmit` term in the gate at
`session/tcp__session__tx.py:244-245`.

**Status:** locked in by construction (control
packets); locked in indirectly (retransmits also
Not-ECT).

### Test coverage summary

| Aspect                                       | Coverage                                       |
|----------------------------------------------|------------------------------------------------|
| §4.1 Alternative cwnd response (ABE/AccECN)  | locked in (cross-ref RFC 8511, RFC 9768)       |
| §4.2 Router marking variants                 | n/a (router-side)                              |
| §4.3 ECT on retransmits                      | locked in indirectly (Not-ECT, conservative)   |
| §4.3 ECT on control packets                  | locked in by construction (Not-ECT on control) |

---

## Overall assessment

| Aspect                                          | Status                                  |
|-------------------------------------------------|-----------------------------------------|
| §3 ECN nonce closure (ECT(1) freed)             | n/a (PyTCP doesn't use ECT(1))          |
| §4.1 Alternative cwnd response (ABE)            | leveraged                               |
| §4.1 AccECN feedback                            | leveraged                               |
| §4.2 Marking variants (router-side)             | n/a                                     |
| §4.2 ECT(1) for L4S                             | not implemented                         |
| §4.3 ECT on TCP retransmits                     | not leveraged (Not-ECT, conservative)   |
| §4.3 ECT on TCP control packets                 | not leveraged (Not-ECT, conservative)   |

PyTCP takes advantage of one RFC 8311 §4 relaxation:

1. The alternative cwnd response (§4.1) via RFC 8511
   ABE and RFC 9768 AccECN — both shipped per their
   respective audits.

PyTCP does NOT take advantage of:

- ECT(1) for L4S finer feedback (§4.2). This is
  active research; adopting it would require
  implementing the L4S sender-side response (RFC
  9330+) which is a substantial separate project.
- ECT on TCP retransmits (§4.3). The emission gate
  carries an explicit `not is_retransmit` term, so
  retransmits stay Not-ECT — PyTCP keeps the RFC
  3168 §6.1.5 restriction rather than adopting the
  relaxation.
- ECT on TCP control packets (§4.3). PyTCP keeps
  the conservative RFC 3168 default; adopting the
  relaxation is permissible but offers limited
  benefit.

RFC 8311 is a permissive update; PyTCP's partial
adoption (ABE + AccECN) leverages the §4.1 cwnd-response
relaxation while keeping the conservative RFC 3168
defaults for the §4.2 / §4.3 experimental extensions
PyTCP has not yet integrated.
