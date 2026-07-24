# RFC 6437 — IPv6 Flow Label Specification

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6437                                              |
| Title       | IPv6 Flow Label Specification                     |
| Category    | Standards Track (Updates RFC 2460)                |
| Date        | November 2011                                     |
| Source text | [`rfc6437.txt`](rfc6437.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 6437. The audit was performed by reading the RFC
text fresh and inspecting `packages/pytcp/pytcp/protocols/ip6/ip6__flow_label.py`
plus `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`
directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 6437 host-side requirements. The
generator algorithm (`compute_ip6_flow_label`) is shipped
and the `_phtx_ip6` TX path consumes it by default — every
outbound IPv6 frame carries a 20-bit Flow Label derived
from the (src, dst) pair via BLAKE2s keyed by the
stack-wide `IP6__FLOW_SECRET`. The
`ip6.flow_label_generation` sysctl (default 1) toggles the
behaviour; flipping it to 0 reverts to RFC 8200 §3 "no
specific flow" emission (flow=0). The integration-test
harness defaults the sysctl to 0 so existing golden-byte
fixtures continue to match without per-fixture
regeneration; a dedicated
`test__ip6__rfc6437_flow_label.py` test class re-enables
the sysctl to exercise the auto-wire.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §2      | Flow Label is 20 bits, set by source, immutable on forward | met (wire format + auto-emit) |
| §3      | Source SHOULD set a Flow Label per flow (uniform random) | met (auto-wire shipped) |
| §5      | Forwarders MUST NOT modify Flow Label              | met (no forwarding today; Phase-2 honour by design) |
| §6.1    | ECMP/LAG using Flow Label                          | n/a (no PyTCP forwarder) |
| §6.2    | Stateful load balancing using Flow Label           | n/a (no PyTCP load balancer) |

---

## §2 Definition

> "The 20-bit Flow Label field in the IPv6 header is used
>  by a source to label sequences of packets to be treated
>  in the network as a single flow."

**Adherence:** met (wire format). The `Ip6Header`
dataclass at `packages/net_proto/net_proto/protocols/ip6/ip6__header.py`
carries the 20-bit `flow` field; `Ip6Assembler` exposes
`ip6__flow` as a kwarg. The wire codec packs the field
into the version/TC/FL header word per RFC 8200 §3.

> "The Flow Label is set to zero when no specific flow is
>  defined."

**Adherence:** met. The default value of `ip6__flow=0`
satisfies the "no specific flow" form for every PyTCP
emission path that does not opt into the §3 generator.

---

## §3 Flow Label Specification

> "To enable Flow Label based classification, source nodes
>  SHOULD assign each unrelated transport connection and
>  application data stream to a new flow."

**Adherence:** met. The "deliver unchanged" guarantee is
trivially met (PyTCP does not forward in Phase 1). The
"source SHOULD assign each unrelated flow" requirement is
met by the TX-path auto-wire:

- The **generator algorithm** is shipped at
  `packages/pytcp/pytcp/protocols/ip6/ip6__flow_label.py::compute_ip6_flow_label`:
  BLAKE2s-keyed hash of `(src, dst)` with the stack-wide
  16-byte `IP6__FLOW_SECRET`, folded to 20 bits.
- The **TX path auto-wire** is shipped at
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`:
  when `ip6.flow_label_generation` sysctl is non-zero
  (default 1), `_phtx_ip6` calls
  `compute_ip6_flow_label(src=ip6__src, dst=ip6__dst)`
  and passes the result to `Ip6Assembler` via the
  `ip6__flow` kwarg.

The integration test corpus's existing golden-frame
fixtures (which encode flow=0 in their IPv6 header word)
continue to match because `NetworkTestCase.setUp` pins
`ip6.flow_label_generation = 0` for the duration of each
test. The dedicated
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6437_flow_label.py`
flips the sysctl back to 1 in its own setUp to exercise
the auto-wire — three tests assert (a) non-zero Flow
Label on outbound frames, (b) on-wire Flow Label matches
the generator's output, (c) flow=0 when the sysctl is
disabled.

> "The Flow Label value MUST be chosen from an
>  approximation to a discrete uniform distribution."

**Adherence:** met by the generator (when wired). BLAKE2s
output is cryptographically uniform; folding to 20 bits
preserves uniformity. The
`TestIp6FlowLabel::test__lib__ip6_flow_label__fits_in_20_bits`
unit case pins the output-space bound.

> "An implementation SHOULD use the same Flow Label value
>  for all packets of a given flow."

**Adherence:** met by the generator. The generator hashes
(src, dst); same pair → same label. Pinned by
`TestIp6FlowLabel::test__lib__ip6_flow_label__same_flow_same_label`.
The PyTCP "flow" approximation is per-(src, dst) rather
than per-5-tuple — RFC 6437 §3 explicitly allows coarser
flow definitions ("flow could be a single TCP connection
or all of the traffic between two endpoints"). A future
Phase-1 polish item is to refine to per-5-tuple by
plumbing (sport, dport, proto) through the IPv6 TX path;
the (src, dst) approximation is RFC-conformant in the
meantime.

> "An implementation SHOULD use a random Flow Label value
>  to make it difficult for an attacker on the network to
>  inject packets with valid Flow Label values."

**Adherence:** met by the generator. The per-stack
16-byte `IP6__FLOW_SECRET` (generated at module import
via `secrets.token_bytes(16)` at
`packages/pytcp/pytcp/stack/__init__.py`) ensures the per-(src, dst)
flow label is unguessable to an off-path attacker.
Pinned by
`TestIp6FlowLabel::test__lib__ip6_flow_label__different_secret_different_label`.

---

## §5 Forwarding

> "Forwarding nodes MUST NOT modify the Flow Label."

**Adherence:** met. PyTCP does not forward in Phase 1.
When the Phase-2 forwarding plane lands, the immutability
guarantee will be enforced by design — the forwarder
reuses the inbound `Ip6Header` value when it constructs
the outbound packet.

---

## §6 Use by Network Elements

> "Routers and intermediate nodes MAY use the Flow Label
>  for ECMP / Link Aggregation, stateful load balancing,
>  flow-based QoS classification, etc."

**Adherence:** n/a. PyTCP has no forwarder, no load
balancer, no QoS classifier today. These are router /
operator concerns; a host stack's responsibility ends at
"set a uniform Flow Label per flow."

---

## Test coverage audit

### §3 Generator algorithm

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip6/test__ip6__flow_label.py::TestIp6FlowLabel`
  — 5 tests: fits-in-20-bits, same-flow-same-label,
  different-flows-different-labels, different-secret-
  different-label, different-source-different-label.

**Status:** locked in.

### §3 TX-path auto-wire

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6437_flow_label.py::TestIp6Rfc6437FlowLabelAutoWire`
  — 3 tests: outbound Echo Reply carries non-zero Flow
  Label when sysctl is enabled; on-wire Flow Label
  equals `compute_ip6_flow_label` output for the same
  (src, dst); flow=0 when sysctl is disabled.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Generator algorithm (uniform, stable, secret-keyed) | locked in |
| TX-path auto-wire                                   | locked in |
| `ip6.flow_label_generation` sysctl on/off           | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §2 Flow Label wire format (20 bits, header word)      | met    |
| §3 Source generator (uniform, per-flow stable)        | met    |
| §3 TX-path auto-wire (emit non-zero flow by default)  | met (`ip6.flow_label_generation` sysctl, default 1) |
| §5 Forwarder immutability                             | met (vacuous — no forwarding today) |
| §6.1 / §6.2 forwarder / load-balancer use             | n/a (no PyTCP forwarder) |

PyTCP fully ships RFC 6437 §3 — both the generator
algorithm and the TX-path auto-wire. Production traffic
carries non-zero per-(src, dst)-stable Flow Labels;
operators that need flow=0 (e.g. running behind an older
middlebox that treats non-zero flow as a special-case)
flip `ip6.flow_label_generation` to 0.

A future per-5-tuple refinement (sport, dport, proto)
would land at the socket layer where the 4-tuple is
known; it is RFC-conformant to start with per-(src, dst)
since RFC 6437 §3 allows flow definitions to vary across
implementations.

## Cross-references

- IPv6 header wire format: [`../rfc8200__ipv6/adherence.md`](../rfc8200__ipv6/adherence.md)
- IPv6 node requirements (RFC 6437 referenced from §5.1
  SHOULD): [`../rfc8504__ipv6_node_reqs/adherence.md`](../rfc8504__ipv6_node_reqs/adherence.md)
- The `IP6__FLOW_SECRET` allocation pattern mirrors
  `TCP__ISS_SECRET` and `TCP__FASTOPEN_SECRET` at the top
  of `packages/pytcp/pytcp/stack/__init__.py`.
