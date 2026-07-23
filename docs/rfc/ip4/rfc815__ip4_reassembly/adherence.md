# RFC 815 — IP Datagram Reassembly Algorithms

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 815                                            |
| Title       | IP Datagram Reassembly Algorithms              |
| Category    | Informational                                  |
| Date        | July 1982                                      |
| Source text | [`rfc815.txt`](rfc815.txt)                     |

This document records the PyTCP codebase's adherence to RFC 815's
reassembly algorithm. RFC 815 is **informational** — it
describes one viable reassembly algorithm (the "hole descriptor
list") but does not impose a wire-protocol-level MUST. The
normative requirement is RFC 791's "reassemble fragments
identified by the (src, dst, proto, id) tuple". This audit
verifies that PyTCP's reassembly produces correct results for
every fragmentation pattern RFC 815 enumerates, including the
overlap and timer-expiry edges, while noting where the
implementation diverges from the specific 8-step hole-descriptor
algorithm.

The audit was performed by reading the RFC text fresh and
inspecting `packages/pytcp/pytcp/protocols/ip/ip_frag.py`, `ip_frag_table.py`,
and the RX-side hook in `packet_handler__ip4__rx.py` directly;
no prior memory or rule-file content was reused.

---

## Top-line adherence

PyTCP **shipped** the reassembly. The state machine differs from
the RFC 815 hole-descriptor approach (PyTCP uses a sorted-offset
dictionary plus a "last-fragment seen" boolean), but the
externally observable behaviour is the same: correct
reassembly for every covered fragmentation pattern, overlap
rejection, timeout-based purge, atomic-fragment fast-path.

| Section | Topic                                                       | Status |
|---------|-------------------------------------------------------------|--------|
| §2      | Algorithm shape (any algorithm that reassembles correctly)  | met    |
| §3      | Eight-step hole-descriptor algorithm                        | functionally equivalent (different state representation) |
| §4      | Hole-descriptor storage in the reassembly buffer            | not used (Python objects instead) |
| §5      | List-head pointer placement                                 | not used (Python dict) |
| §6      | Options handling (variable header size; first-fragment carries options) | met (atomic header rewrite on completion) |
| §7      | Flow keying by (src, dst, proto, id)                        | met    |
| §7      | Timer-based reaper                                          | met (lazy sweep on each admission) |

The audit also notes interactions with later RFCs:

- **RFC 5722 §3** — overlapping-fragment rejection (silent discard, mark flow). Met by `IpFragTable.add_fragment` overlap branch.
- **RFC 791 §3.2 / RFC 6864** — atomic-fragment fast-path. Met by the `offset == 0 and not flag_mf` early-return.
- **RFC 6864 §4.3** — DF=1 MUST NOT be fragmented. Enforced on the **send** side; this audit covers receive.

---

## §2 The Algorithm (shape)

> "When a new fragment of the datagram arrives, it will possibly
> fill in one or more of the existing holes. We will examine
> each of the entries in the hole descriptor list to see whether
> the hole in question is eliminated by this incoming fragment.
> ... Eventually, a fragment will arrive which eliminates every
> entry from the list. At this point, the datagram has been
> completely reassembled and can be passed to higher protocol
> levels for further processing."

**Adherence:** met (functionally). PyTCP implements the same
externally observable contract — fragment arrives, store admits
it, completion test runs, completed datagram is forwarded
upstream — but through a different state representation:

- Instead of an explicit "hole descriptor list", PyTCP stores
  the **arrived fragments** keyed by offset
  (`IpFragData.payload: dict[int, Buffer]` at
  `packages/pytcp/pytcp/protocols/ip/ip_frag.py`).
- Completion is tested by walking the sorted offsets and
  verifying a contiguous chain from 0 covers every byte up to
  the last fragment's end
  (`ip_frag_table.py:184-192`). The "hole list is empty" check
  becomes "every offset-to-next-offset span is closed and the
  last-fragment marker is set."
- The dual representation (track holes vs. track arrivals) is
  algebraically equivalent for the purposes of RFC 791
  reassembly. The hole-descriptor approach makes incremental
  hole-shrinking cheap; the arrival-set approach makes overlap
  detection cheap. PyTCP chose the latter so the RFC 5722
  hardening (see §3 below) folds in naturally.

## §3 Fragment Processing Algorithm — 8 steps

The eight-step algorithm in RFC 815 is one valid implementation;
RFC 815 itself notes "the algorithm can compare each hole to the
arriving fragment in only four tests" but does not require any
particular state shape. PyTCP's step-by-step equivalent:

| RFC 815 step | PyTCP equivalent | Location |
|--------------|------------------|----------|
| 1. Iterate hole-descriptor list | Iterate the `_flows[flow_id].payload` dict (overlap test only) | `ip_frag_table.py:165-170` |
| 2. `fragment.first > hole.last` → skip | Implicit — overlap test condition `offset < stored_end and stored_offset < new_end` | `ip_frag_table.py:169` |
| 3. `fragment.last < hole.first` → skip | Implicit (same condition) | `ip_frag_table.py:169` |
| 4. Delete current hole | n/a — no hole representation; arrival dict is updated instead | `ip_frag_table.py:175` |
| 5. Trailing hole creation | n/a — implicit via sorted-offset walk on completion test | — |
| 6. Leading hole creation (incl. MF test) | Last-fragment marker tracked separately on `IpFragData` | `ip_frag.py::IpFragData.received_last_frag` |
| 7. Loop back to step 1 | n/a — single overlap pass | — |
| 8. Empty hole list → complete | Sorted-offset contiguity walk + `last` boolean | `ip_frag_table.py:184-207` |

**Adherence:** functionally equivalent. PyTCP's representation
is closer to Linux's `inet_frags.c` (per-offset
`sk_buff_head` queue plus `last_in` bitmask) than to the
RFC 815 hole-descriptor list. RFC 815 §2 explicitly permits
this — the algorithm is offered as guidance, not as the only
legal shape.

## §4 Managing the Hole Descriptor List (storage trick)

> "Just put each hole descriptor in the first octets of the hole
> itself. ... by the definition of the reassembly algorithm,
> the minimum size of a hole is eight octets."

**Adherence:** not applicable. The RFC 815 storage trick (embed
hole descriptors in the hole bytes themselves) made sense in
1982 when buffer allocation was expensive and stacks ran on
hardware with kilobyte-scale RAM. PyTCP runs on a Python
interpreter — `dict[int, Buffer]` allocation is cheap and the
storage trick would obscure the algorithm without speeding it
up. The RFC explicitly permits any reassembly-buffer storage
strategy that produces the same external behaviour.

## §5 Loose Ends (list-head pointer placement)

> "An obvious location is the checksum field [for the list-head
> pointer]."

**Adherence:** not applicable. Same reasoning as §4 — PyTCP
holds the list head as a normal Python attribute
(`IpFragData.payload`); no in-band cleverness needed.

> "When the final fragment of the datagram arrives, the packet
> length field in the internet header should be filled in."

**Adherence:** met. On completion the RX handler rewrites the
reassembled header explicitly, preserving the first fragment's
IHL and options (`packet_handler__ip4__rx.py:409-413`):

```
header = bytearray(header_bytes)                                    # full first-fragment header incl. options
header[1] = (header[1] & 0xFC) | (result.ecn & 0x03)               # aggregated ECN (DSCP preserved)
struct.pack_into("!H", header, 2, len(header) + len(payload))      # Total Length
header[6] = header[7] = header[10] = header[11] = 0                 # Flags+Offset, cksum
struct.pack_into("!H", header, 10, inet_cksum(memoryview(header))) # recompute cksum
```

The Total Length field is updated to the joined header+payload
length (including options), the aggregated ECN is patched into
the TOS byte, Flags/Offset are cleared, and the header checksum
is recomputed. `header[0]` is left untouched so the original
IHL / options are preserved (see §6).

## §6 Options (variable header size)

> "[Until the first fragment arrives,] one does not know where
> to copy the data from each fragment into the reassembly
> buffer. ... certain options are copied identically into every
> fragment of a datagram, other options, such as 'record route',
> are put in the first fragment only."

**Adherence:** met. PyTCP's reassembly **preserves the first
fragment's options** verbatim on completion. The RX handler
captures the full IHL-bounded first-fragment header bytes
into `IpFragData.header`; on completion the bytes are reused
as the reassembled header (with Total Length recomputed to
`len(header) + len(payload)` and Header Checksum
recomputed):

```python
header = bytearray(header_bytes)        # full first-fragment header incl. options
# header[0] left as-is — preserves the original IHL
struct.pack_into("!H", header, 2, len(header) + len(payload))
header[6] = header[7] = header[10] = header[11] = 0
struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
```

The first fragment is canonical per RFC 815 §6: copy_flag=1
options appear identically on every fragment (so the first
fragment's copy is the canonical bytes), and copy_flag=0
options appear only on the first fragment by construction.
Either way, the first fragment's options are the right
bytes for the reassembled datagram.

The TX-side symmetric handling — emitting the right options
on each outbound fragment — is audited under
`docs/rfc/ip4/rfc791__ip4/adherence.md` §3.1 (option
copy-flag on fragmentation).

## §7 The Complete Algorithm — flow keying

> "The correct reassembly buffer is identified by an equality of
> the following fields: the foreign and local internet
> address, the protocol ID, and the identification field."

**Adherence:** met. The flow key is
`IpFragFlowId(src, dst, id, proto)`
(`packet_handler__ip4__rx.py:315-320`). All four fields are
exactly the RFC 791 / RFC 815 reassembly tuple. The same
`IpFragFlowId` type is used for IPv6 reassembly (with v6
addresses) since the per-family difference is just the
address types — the flow store and admission machinery is
shared.

## §7 The Complete Algorithm — timer-based reaper

> "An implementation needs some sort of timer based mechanism
> which decrements the time to live field of each partially
> reassembled datagram, so that incomplete datagrams which
> have outlived their usefulness can be detected and deleted."

**Adherence:** met. PyTCP's reaper is a **lazy sweep** on every
admission (`ip_frag_table.py:152-155`):

```python
now = time()
self._flows = {
    flow: self._flows[flow]
    for flow in self._flows
    if now - self._flows[flow].timestamp < self._timeout
}
```

The timeout is configured via the `IP4__FRAG_FLOW_TIMEOUT = 5`
constant in `packages/pytcp/pytcp/stack/__init__.py:155` (5 seconds, matching
Linux `net.ipv4.ipfrag_time = 30` order-of-magnitude — PyTCP's
shorter value reduces memory pressure under fragment floods).
The lazy-sweep model matches Linux's `inet_frag_evictor`
approach: no dedicated reaper thread, the sweep amortises
across admissions.

A dedicated thread-based reaper would be an alternative; the
lazy approach is simpler and the only failure mode (incomplete
flow persists until the next fragment arrives) is bounded by
the bytes-per-flow ceiling (Python dict size).

## RFC 5722 §3 — Overlapping fragments (overlap-rejection hardening)

RFC 815 itself does not address overlapping fragments — the
attack surface was identified later, formalised in RFC 5722 for
IPv6 and tightened for IPv4 in subsequent operational guidance.
PyTCP applies the same rule to both families:

> "[An] entire datagram MUST be silently discarded ... if any of
> the fragments overlap one another in any way." (RFC 5722 §3)

**Adherence:** met. The overlap detection
(`ip_frag_table.py:162-171`) runs on every admission. On
detection the flow is **marked discarded** (not deleted) so
subsequent fragments from the same flow are silently dropped
(line 158-160). The `ip4__frag__overlap__drop` counter is
bumped at the RX handler (`packet_handler__ip4__rx.py:326-328`).

## RFC 791 §3.2 / RFC 6864 §4 — Atomic-fragment fast-path

**Adherence:** met. The `add_fragment` entry point returns
`COMPLETE` immediately on `offset == 0 and not flag_mf`
(`ip_frag_table.py:144-149`) without touching the flow store.
This guarantees that an atomic datagram (DF=1, MF=0, offset=0)
cannot be poisoned by a concurrent non-atomic reassembly that
happens to share src/dst/id/proto — the atomic frame
processes in isolation and never enters the table. RFC 6864 §4.1
explicitly requires this isolation; the audit for that RFC
cross-references back here.

---

## Test coverage audit

### §2 / §3 Reassembly happy path

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  contains a fragmentation receive matrix: two-fragment, three-
  fragment, out-of-order arrival, last-fragment-first arrival,
  full-coverage no-overlap.

**Status:** locked in.

### §6 Options preserved on reassembly

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py::TestPacketHandlerIp4RxRfc791OptionPreservedOnReassembly`
  Two-fragment reassembly with first fragment carrying
  [Router Alert + RR + NOP] and second carrying only the
  copy_flag=1 subset → reassembled packet preserves the
  first fragment's full option set, IHL reflects the
  preserved length, Total Length includes both header bytes
  (with options) and payload bytes. Includes a no-options
  regression case.

**Status:** locked in.

### §7 Flow keying by (src, dst, proto, id)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip_frag_table.py`
  asserts that fragments with different tuple values populate
  different flow entries.

**Status:** locked in.

### §7 Timer-based reaper

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip_frag_table.py`
  backdates a flow's timestamp via the `flows` live-view
  accessor and verifies the next admission sweeps it out.

**Status:** locked in.

### RFC 5722 — overlap rejection

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip_frag_table.py`
  Overlap matrix: exact-duplicate-offset, partial-overlap on
  either edge, full-containment.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies the `ip4__frag__overlap__drop` counter increments.

**Status:** locked in.

### Atomic-fragment fast-path (RFC 791 / RFC 6864)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip_frag_table.py`
  asserts that an `offset=0, flag_mf=False` admission returns
  `COMPLETE` without flow-store mutation.

**Status:** locked in.

### Discarded-flow drop-through (RFC 5722 §3 subsequent fragments)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip/test__ip_frag_table.py`
  Two-step: trigger overlap, then admit another non-overlapping
  fragment for the same flow → outcome must be `DISCARDED`.

**Status:** locked in.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Reassembly happy path (in/out-of-order arrival)       | locked in |
| Options preserved on completion (RFC 815 §6)          | locked in |
| Flow keying by (src, dst, proto, id)                  | locked in |
| Lazy-sweep timer reaper                               | locked in |
| Overlap rejection (RFC 5722)                          | locked in |
| Atomic-fragment fast-path (RFC 791 / RFC 6864)        | locked in |
| Discarded-flow drop-through                           | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §2 / §3 Reassembly correctness (any algorithm)        | met (sorted-offset dict, not hole-descriptor list) |
| §4 In-buffer hole-descriptor storage trick            | n/a (Python objects suffice) |
| §5 In-band list-head pointer placement                | n/a (Python attribute) |
| §6 Options handling on reassembly                     | met (first-fragment options preserved) |
| §7 Flow keying by (src, dst, proto, id)               | met    |
| §7 Timer-based reaper                                 | met (lazy sweep) |
| RFC 5722 overlap rejection (hardening)                | met    |
| RFC 791 / RFC 6864 atomic-fragment fast-path          | met    |

The reassembly is functionally complete. Phase-2 forwarder
work (e.g. re-encoding the reassembled datagram with options
back onto the forward path) inherits the preserved options
for free since the reassembled IPv4 packet now carries the
original first-fragment header bytes verbatim.
