# RFC 6946 — Processing of IPv6 "Atomic" Fragments

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 6946                                                 |
| Title       | Processing of IPv6 "Atomic" Fragments                |
| Category    | Standards Track (Updates RFC 2460, RFC 5722)         |
| Date        | May 2013                                             |
| Source text | [`rfc6946.txt`](rfc6946.txt)                         |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 6946 §4. An atomic
fragment (a Fragment Header with `Offset == 0` and `M == 0`,
constituting the entire datagram in a single fragment) is
processed in isolation from the reassembly buffer: the
shared `IpFragTable.add_fragment` detects the atomic case
at the head of the function — before any flow-table lookup,
discarded-flow gate, or overlap walk — and returns
`IpFragAddOutcome.COMPLETE` immediately with the input
header / payload bytes echoed back as the "reassembled"
datagram.

The implementation lives in commit `909c3e06`, layered on
top of the strict-overlap detection from RFC 5722 §3
(commit `604eebbf`) and the shared `IpFragTable` lift
(commit `6c1c8634`).

---

## §1 Introduction — motivation

> "Implementations may handle [atomic fragments] as part of
> the regular reassembly process. As a result, fragments
> resulting from independent original packets may be
> reassembled together, leading to interoperability
> problems and Denial-of-Service vulnerabilities."

**Adherence:** shipped — the failure mode RFC 6946 §1
describes is exactly what PyTCP avoided by carving out an
atomic fast-path. Before commit `909c3e06`, an atomic
fragment shared the flow-table machinery with non-atomic
reassemblies; under the RFC 5722 §3 strict-overlap policy
(commit `604eebbf`), this caused a malicious atomic
fragment with a colliding flow id to discard a legitimate
in-progress reassembly. The §4 isolation requirement made
the bug fix surface explicit.

## §2 Terminology

> "Atomic fragments: IPv6 packets that contain a Fragment
> Header with the Fragment Offset set to 0 and the M flag
> set to 0."

**Adherence:** shipped. `IpFragTable.add_fragment` detects
the atomic case via the boolean predicate
`offset == 0 and not flag_mf`.

## §3 Generation of IPv6 Atomic Fragments — TX side

**Adherence:** PyTCP **does not generate** atomic fragments.
The §3 motivation describes that an ICMPv6 "Packet Too Big"
with Next-Hop MTU < 1280 — typically from a translating
router — could trigger atomic-fragment generation. PyTCP's
TX path follows RFC 8021 (which the RFC 8504 §5.1 cross-
reference makes a MUST NOT): atomic fragments are simply not
created. The fragment-emission path
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__tx.py`
only produces multi-fragment datagrams, and PMTU < 1280 is
clamped to 1280 at the IPv6 minimum-MTU floor.

## §4 Updating RFC 2460 and RFC 5722 — the core normative MUSTs

> "A host that receives an IPv6 packet that includes a
> Fragment Header with the 'Fragment Offset' equal to 0 and
> the 'M' flag equal to 0 MUST process that packet in
> isolation from any other packets/fragments, even if such
> packets/fragments contain the same set {IPv6 Source
> Address, IPv6 Destination Address, Fragment
> Identification}."

**Adherence:** shipped. The atomic gate is the very first
branch of `IpFragTable.add_fragment`:

```python
# RFC 8200 §4.5 / RFC 6946 §4 atomic-fragment fast-path.
# An atomic fragment is the entire datagram; it must
# never touch the flow store and must process in
# isolation from any concurrent non-atomic reassembly
# that happens to share the same source/destination/ID.
if offset == 0 and not flag_mf:
    return IpFragAddResult(
        outcome=IpFragAddOutcome.COMPLETE,
        header=bytes(header),
        payload=bytes(payload),
    )
```

The atomic path runs *before* the lazy expiry sweep, the
discarded-flow gate, and the overlap walk — so an atomic
fragment cannot interact with the per-flow store at all.
Any concurrent non-atomic reassembly with the same flow id
remains intact.

> "A received atomic fragment should be 'reassembled' from
> the contents of that sole fragment.
>
> The Unfragmentable Part of the reassembled packet
> consists of all headers up to, but not including, the
> Fragment Header of the received atomic fragment.
>
> The Next Header field of the last header of the
> Unfragmentable Part of the reassembled packet is obtained
> from the Next Header field of the Fragment Header of the
> received atomic fragment.
>
> The Payload Length of the reassembled packet is obtained
> by subtracting the length of the Fragment Header (that
> is, 8) from the Payload Length of the received atomic
> fragment."

**Adherence:** shipped. The per-family v6 handler
(`__defragment_ip6_packet`) applies the same header-rewrite
pass it uses for non-atomic reassemblies once `add_fragment`
returns COMPLETE:

- The unfragmentable part = the IPv6 header bytes captured
  by the chain walker before the Fragment Header
  (`packet_rx.ip6.header_bytes`).
- The Next Header field at byte offset 6 is rewritten from
  `packet_rx.ip6_frag.next` (the upper-layer protocol that
  the Fragment Header pointed at).
- The Payload Length at bytes 4-5 is rewritten to
  `len(payload)` (the joined / passed-through payload),
  which for an atomic fragment is just the atomic
  fragment's own data — exactly equal to "original payload
  length minus 8 (Fragment Header)" as required by §4.

> "Additionally, if any fragments with the same set {IPv6
> Source Address, IPv6 Destination Address, Fragment
> Identification} are present in the fragment reassembly
> queue when the atomic fragment is received, such
> fragments MUST NOT be discarded upon receipt of the
> 'colliding' IPv6 atomic fragment, since IPv6 atomic
> fragments MUST NOT interfere with 'normal' fragmented
> traffic."

**Adherence:** shipped — pinned by the dedicated
"isolation" test
(`test__ip_frag_table__add_fragment__atomic_isolated_from_existing_flow`):
with an in-progress non-atomic flow already admitted, an
atomic fragment for the same `flow_id` returns COMPLETE
*and* the existing flow's `IpFragData.payload` dict remains
intact for continued reassembly.

The atomic gate's "no flow-store interaction" property is
what makes this isolation guarantee mechanical: the
function returns before any code that could mutate the
existing flow.

## §5 Security Considerations

> "This document formally updates [RFC2460] and [RFC5722],
> such that IPv6 atomic fragments are processed
> independently of any other fragments, thus completely
> eliminating the aforementioned attack vector."

**Adherence:** shipped. The colliding-flow-id attack from
the §3 motivation cannot complete on PyTCP — atomic
fragments take a code path that does not consult the flow
table.

---

## Test coverage audit

The §4 clauses above are pinned by:

| Clause | Test file / class |
|--------|-------------------|
| Atomic returns COMPLETE without flow-table allocation | `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip__ip_frag_table.py::TestIpFragTableAtomicFragment::test__ip_frag_table__add_fragment__atomic_returns_complete_without_admission` |
| Atomic isolated from existing flow id | Same class :: `test__ip_frag_table__add_fragment__atomic_isolated_from_existing_flow` |
| Handler dispatches + bumps `ip6_frag__atomic__defrag` | `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6_frag__rx.py::TestPacketHandlerIp6FragRx::test__stack__packet_handler__ip6_frag__rx__atomic_fragment_dispatches_without_flow_table` |
| Handler does not allocate flow-table entry | Same test (asserts `_ip6_frag_table.flows == {}`) |

The TX-side §3 MUST NOT (do-not-generate-atomic-fragments)
is regression-pinned implicitly: the v6 fragment-emission
path in `packet_handler__ip6_frag__tx.py` does not have a
code branch that would emit a single-fragment datagram.

---

## Cross-references

- `docs/rfc/ip6/rfc8200__ipv6/adherence.md` §4.5 — Fragment Header parent record
- `docs/rfc/ip6/rfc5722__overlapping_fragments/adherence.md` —
  the strict-overlap policy that motivated the atomic
  fast-path carve-out
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.1 —
  cross-references RFC 6946's atomic-fragment processing
  requirement
- Implementing commit: `909c3e06`
