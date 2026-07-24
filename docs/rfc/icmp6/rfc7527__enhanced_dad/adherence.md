# RFC 7527 — Enhanced Duplicate Address Detection

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7527                                              |
| Title       | Enhanced Duplicate Address Detection              |
| Category    | Standards Track                                   |
| Date        | April 2015                                        |
| Source text | [`rfc7527.txt`](rfc7527.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 7527. The audit was performed by reading the RFC
text fresh and inspecting
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__{tx,rx}.py`
plus `packages/pytcp/pytcp/lib/dad_slot_registry.py` directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 7527 Enhanced DAD. The DAD-probe TX
path emits a Nonce option in each Neighbor Solicitation
probe; the DAD-probe RX path consults the per-candidate
Nonce in the DAD slot registry and drops inbound NS that
echo our own Nonce as loop-hairpin frames. The result:
PyTCP's DAD does not falsely conclude "duplicate" when a
misconfigured layer-2 device reflects the probe back.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §3      | Background — DAD loopback failure mode             | n/a (motivation)               |
| §4.1    | Nonce option emit on DAD NS                        | met                            |
| §4.2    | Nonce match on inbound NS = loop-hairpin drop      | met                            |
| §4.3    | Operator-tunable behaviour                         | met (sysctl `icmp6.enhanced_dad`) |

---

## §4.1 Nonce Option on Outbound DAD Probes

> "When transmitting a DAD Neighbor Solicitation message,
>  the host MUST include a Nonce option."

**Adherence:** met. `_send_icmp6_nd_dad_message` at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py:196-238`
accepts an `nonce: bytes | None` parameter; when supplied
(every Phase-1 caller passes a fresh random nonce), the
probe carries an `Icmp6NdOptionNonce(nonce=nonce)` in the
options list:

```python
options: list[Icmp6NdOption] = []
if nonce is not None:
    options.append(Icmp6NdOptionNonce(nonce=nonce))
```

The `Icmp6NdOptionNonce` codec lives in the ND options
package. Each per-candidate DAD attempt picks a fresh
nonce via `secrets.token_bytes`; the registry stores it
so the RX path can compare.

> "The Nonce option carries an opaque nonce value of at
>  least 6 octets in length."

**Adherence:** met. PyTCP uses 6-byte nonces by default
(generated via `secrets.token_bytes(6)`); the option
codec accepts arbitrary lengths so future longer nonces
land without re-spec.

---

## §4.2 Nonce Check on Inbound NS

> "When receiving an NS for a target address that this
>  node is currently probing, the receiver MUST compare
>  the Nonce option (if present) against the nonce values
>  it has emitted for that target. A match means this NS
>  is a loop-hairpin echo of the receiver's own probe and
>  SHOULD be silently discarded rather than treated as a
>  conflict."

**Adherence:** met. The NS RX dispatcher at
`packet_handler__icmp6__rx.py:960-978` calls
`DadSlotRegistry.try_signal_conflict` with the inbound
nonce; the registry compares against the locally-emitted
nonce for that candidate:

- **Nonce match → `DadSignalResult.LOOP_HAIRPIN`** —
  silent drop, bump the
  `icmp6__nd_neighbor_solicitation__loop_hairpin__drop`
  counter, return without flagging the DAD slot.
- **No match (or no Nonce option) → `SIGNALED`** —
  treat as a genuine DAD conflict, abort the local
  claim, bump the `dad_conflict` counter.

The compare runs inside the registry's atomic lock so
there is no race between the TX-emit-nonce-write and the
RX-receive-nonce-check.

---

## §4.3 Operator Control

> "Implementations SHOULD provide an operator-tunable
>  knob to enable / disable Enhanced DAD."

**Adherence:** met. The `icmp6.enhanced_dad` sysctl
(declared in
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py`, default 1)
controls whether the nonce is generated and emitted. With
the knob disabled, the DAD probe is the bare RFC 4862
form (no Nonce option) and the RX path's `LOOP_HAIRPIN`
case never fires.

---

## Test coverage audit

### §4.1 / §4.2 Loop-hairpin detection

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__enhanced_dad.py`
  — drives a self-echoed NS through the RX path, asserts
  the `loop_hairpin__drop` counter increments and the
  DAD slot is NOT signalled as a conflict (the local
  probe continues).

**Status:** locked in.

### §4.3 Operator knob

- **Integration / unit:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__enhanced_dad.py`
  exercises the on/off paths via
  `sysctl_module.override("icmp6.enhanced_dad", ...)`.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Nonce option on outbound DAD probes                 | locked in |
| Nonce-match → loop-hairpin silent drop              | locked in |
| Nonce-mismatch → genuine DAD conflict path          | locked in |
| Operator sysctl on/off                              | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §4.1 Nonce option emit on every DAD NS                | met    |
| §4.2 Inbound Nonce-match → loop-hairpin drop          | met    |
| §4.2 Inbound Nonce-mismatch → genuine conflict        | met    |
| §4.3 Operator-tunable enable / disable knob           | met (`icmp6.enhanced_dad`) |

PyTCP fully ships RFC 7527. The DadSlotRegistry's atomic
compare-and-signal makes the nonce check race-free between
the TX-emit and the RX-receive threads.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (SHOULD).
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC / DAD record.
- Source: `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py:196-238`
  (`_send_icmp6_nd_dad_message`),
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py:960-978`
  (NS RX Nonce-check), `packages/pytcp/pytcp/lib/dad_slot_registry.py`
  (atomic registry).
