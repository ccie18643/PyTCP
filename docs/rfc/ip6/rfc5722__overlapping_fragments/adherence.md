# RFC 5722 — Handling of Overlapping IPv6 Fragments

| Field       | Value                                                 |
|-------------|-------------------------------------------------------|
| RFC number  | 5722                                                  |
| Title       | Handling of Overlapping IPv6 Fragments                |
| Category    | Standards Track (Updates RFC 2460)                    |
| Date        | December 2009                                         |
| Source text | [`rfc5722.txt`](rfc5722.txt)                          |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 5722. The shared
`packages/pytcp/pytcp/lib/ip_frag_table.py::IpFragTable` (now relocated to
`packages/pytcp/pytcp/protocols/ip/ip_frag_table.py`) detects any overlap
between an arriving fragment and the per-flow store, marks
the entire flow as discarded, clears the stored fragment
payloads, and silently drops every subsequent fragment that
matches the discarded flow id. PyTCP picks the strict
reading of §4: an exact-duplicate fragment (same offset, same
length) is treated as overlapping, in line with RFC 1858 /
RFC 3128 fragmentation-attack mitigations.

The implementation lives in commit `604eebbf` and the
shared-table refactor it builds on (commit `6c1c8634`); the
overlap test surface is mirrored at both the `IpFragTable`
unit-test level (`packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip__ip_frag_table.py`)
and the v4 / v6 packet-handler unit-test level
(`packages/pytcp/pytcp/tests/unit/runtime/packet_handler/`).

PyTCP's TX path does not generate overlapping fragments —
the fragment-emission machinery in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__tx.py`
walks an IPv6 datagram in 8-octet chunks with monotonically-
increasing offsets, so the §4 producer-side MUST holds by
construction.

---

## §1 Introduction

> "[RFC2460] specifies that when reassembling a fragmented
> IPv6 packet, if one or more of the fragments is determined
> to be an overlapping fragment, the reassembly should
> proceed using the data from the most recently received
> fragment ... However, this behavior is not desirable from a
> security perspective."

**Adherence:** N/A (background). The "use latest fragment"
behaviour from RFC 2460 is replaced by RFC 5722 §4
silent-discard; PyTCP follows §4.

## §2 Overlapping Fragments

> "An overlapping fragment is one that overlaps the data in
> a previously received fragment."

**Adherence:** shipped. The overlap check in
`IpFragTable.add_fragment` walks the per-flow store and
returns OVERLAP when the new fragment's `[offset,
offset+len)` byte range overlaps any stored
`[stored_offset, stored_offset+stored_len)` range:

```python
new_end = offset + len(payload)
for stored_offset, stored_chunk in self._flows[flow_id].payload.items():
    stored_end = stored_offset + len(stored_chunk)
    if offset < stored_end and stored_offset < new_end:
        self._flows[flow_id].mark_discarded()
        return IpFragAddResult(outcome=IpFragAddOutcome.OVERLAP)
```

The check fires on:

- A non-trivial range overlap (e.g. offsets 0/16 + 8/8).
- An exact-duplicate fragment (same offset, same length) —
  PyTCP picks the strict reading of §4 over the lenient
  retransmit-tolerant interpretation. A benign retransmit
  destroys the in-progress reassembly, but the sender will
  retransmit the entire datagram; the stricter security
  posture is preferred.

## §3 The Attack

> "A malicious node ... bypassed the firewall's access
> control to initiate a connection request to a node
> protected by a firewall."

**Adherence:** N/A (motivation). The attack relies on a
receiver that uses the most-recent-fragment data for
overlapping bytes; PyTCP discards the entire datagram, so
the attack vector cannot complete.

## §4 Node Behavior — the security MUST

> "IPv6 nodes transmitting datagrams that need to be
> fragmented MUST NOT create overlapping fragments."

**Adherence:** shipped (TX side). PyTCP's IPv6 fragment-
emission path
(`packet_handler__ip6_frag__tx.py`) walks the source
datagram in 8-octet chunks at strictly-increasing offsets;
the producer cannot by construction emit overlapping
fragments.

> "When reassembling an IPv6 datagram, if one or more its
> constituent fragments is determined to be an overlapping
> fragment, the entire datagram (and any constituent
> fragments, including those not yet received) MUST be
> silently discarded."

**Adherence:** shipped (RX side). On overlap detection the
table calls `IpFragData.mark_discarded()` which:

1. Sets the per-flow `discarded: bool` flag.
2. Clears the `payload` dict (frees the buffered fragments).

The flow remains in the table (so the `discarded` flag is
discoverable by subsequent admissions for the same flow id)
but its payload store is empty. Any later fragment for the
discarded flow yields `IpFragAddOutcome.DISCARDED` from
`add_fragment`; the v4 and v6 handlers treat OVERLAP and
DISCARDED outcomes identically — silent drop, no upper-
layer dispatch, and a bump of the family-specific
`ip*__frag__overlap__drop` counter for observability.

The flow itself is reaped by the lazy expiry sweep at the
top of `add_fragment` once `time() - timestamp >=
IP*__FRAG_FLOW_TIMEOUT` (5 s by default).

> "Implementations should drop reassembly state when they
> drop the partial datagram."

**Adherence:** shipped (clear-on-discard). `mark_discarded()`
calls `self.payload.clear()`, so the per-fragment byte
buffers are released for GC at the moment overlap is
detected. Memory does not stay tied up while the flow waits
for the expiry sweep to reap the now-empty entry.

## §5 Security Considerations

> "Lifting the deprecation of the most-recent-fragment
> reassembly algorithm (or any similar functionality) ought
> not be done lightly..."

**Adherence:** N/A (PyTCP does not lift the deprecation).

---

## Test coverage audit

The §4 clauses above are pinned by:

| Clause | Test file / class |
|--------|-------------------|
| Overlap detection (range overlap) | `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip__ip_frag_table.py::TestIpFragTableOverlap::test__ip_frag_table__add_fragment__overlap_drops_flow` |
| Strict-reading exact duplicate | Same class :: `test__ip_frag_table__add_fragment__exact_duplicate_treated_as_overlap` |
| Discarded-flow gate (subsequent fragments dropped) | Same class :: `test__ip_frag_table__add_fragment__subsequent_after_discard_yields_discarded` |
| Three-fragment regression-pin (no false positive) | Same class :: `test__ip_frag_table__add_fragment__three_fragments_no_overlap_still_reassembles` |
| `mark_discarded()` flag flip | `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip__ip_frag.py::TestIpFragDataMarkDiscarded::test__ip_frag_data__mark_discarded__sets_flag` |
| `mark_discarded()` clears payload | Same class :: `test__ip_frag_data__mark_discarded__clears_payload` |
| v4 handler counter wiring | `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip4__rx.py::TestPacketHandlerIp4RxFragmentFlowState::test__stack__packet_handler__ip4__rx__overlapping_fragments_drop_flow` |
| v4 handler same-fragment-twice strict drop | Same class :: `test__stack__packet_handler__ip4__rx__same_fragment_twice_drops_flow` |
| v6 handler counter wiring | `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6_frag__rx.py::TestPacketHandlerIp6FragRx::test__stack__packet_handler__ip6_frag__rx__overlapping_fragments_drop_flow` |
| v6 handler same-fragment-twice strict drop | Same class :: `test__stack__packet_handler__ip6_frag__rx__same_fragment_twice_drops_flow` |
| Integration: replay-fragment in flow A drops only that flow | `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rx.py` (the "duplicate fragments in flow A drop flow A under RFC 5722 §3 strict reading" parametrized case) |
| Integration v6 analog | `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__reassembly.py` (same case) |

---

## Cross-references

- `docs/rfc/ip6/rfc8200__ipv6/adherence.md` §4.5 — Fragment Header parent record
- `docs/rfc/ip6/rfc6946__atomic_fragments/adherence.md` —
  RFC 6946 atomic-fragment isolation, the companion
  fragmentation-hardening spec
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.1 —
  RFC 8504's "MUST silently discard overlapping fragments"
  sub-clause
- Implementing commits: `604eebbf` (overlap detection),
  `6c1c8634` (shared-table refactor)
