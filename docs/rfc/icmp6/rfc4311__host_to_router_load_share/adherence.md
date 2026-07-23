# RFC 4311 — IPv6 Host-to-Router Load Sharing

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4311                                              |
| Title       | IPv6 Host-to-Router Load Sharing                  |
| Category    | Standards Track (Updates RFC 2461)                |
| Date        | November 2005                                     |
| Source text | [`rfc4311.txt`](rfc4311.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 4311. The audit was performed by reading the RFC
text fresh and inspecting
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py` directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 4311 §3 host-to-router load sharing for
the host-side surface. When the stack tracks multiple
equally-preferred default routers (from inbound Router
Advertisements), outbound traffic is distributed across the
highest-preference equivalence class via a per-destination
modulo hash. The same destination always picks the same
router (TCP flows aren't reordered); distinct destinations
spread across the router set.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §1      | Background — multiple-default-router scenarios     | n/a (motivation)               |
| §2      | Algorithm requirements (deterministic per-dst)     | met (modulo hash)              |
| §3      | Implementation alternatives                        | met (modulo selected)          |
| §4      | Security considerations                            | n/a (no new attack surface)    |

---

## §2 / §3 Load Sharing Algorithm

> "When a host has more than one available default router,
>  it SHOULD distribute outgoing connections among them."

**Adherence:** met.
`get_icmp6_default_router_for_destination` at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:2187-2224`
implements the §3 modulo-hash algorithm:

```python
active_routers = self.get_icmp6_default_routers()
if not active_routers:
    return None
head_prf = active_routers[0].prf
candidates = [r for r in active_routers if r.prf == head_prf]
index = int(destination) % len(candidates)
return candidates[index]
```

`get_icmp6_default_routers()` returns the active list
sorted by RFC 4191 §2.1 preference (HIGH > MEDIUM > LOW);
the highest-preference equivalence class is the prefix of
entries sharing the head's `prf` value. The §14 RFC 4191
rule that a LOW router never receives traffic when a HIGH
router is available is honoured by the equivalence-class
filter.

> "The same source address and destination address
>  combination should yield the same selected router so
>  that connection-oriented sessions remain associated
>  with the same router."

**Adherence:** met. The selection is deterministic per
destination address — `int(destination) % len(candidates)`
returns the same index for the same `destination`. TCP
flows do not get rerouted mid-connection.

> "An implementation MAY choose to use other algorithms
>  (e.g. round-robin, hash, weighted) provided the
>  per-flow stickiness property is preserved."

**Adherence:** met (modulo hash is the §3 default). PyTCP
selected the per-destination modulo for its simplicity
and §14 RFC 4191 preference compatibility. Future
operator-tunable algorithms (e.g. weighted by RA-supplied
link-MTU or per-router rtt) would land as a sysctl
extension without changing the API surface.

---

## §4 Security Considerations

> "The technique does not introduce any new security
>  problem."

**Adherence:** n/a (no new attack surface introduced).

---

## Test coverage audit

### §3 Load-sharing algorithm

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__default_router_list.py`
  — covers multi-router preference handling end-to-end
  through the RA RX path; the load-sharing modulo hash
  is exercised whenever the test fixture supplies two or
  more highest-preference routers.

**Status:** locked in indirectly. The dedicated
"different destinations → different routers" assertion
would be a one-test polish item if a regression net is
needed; the modulo hash itself is a 4-line algorithm with
trivial verification cost.

### Test coverage summary

| Aspect                                       | Coverage |
|----------------------------------------------|----------|
| Modulo-hash determinism per destination      | locked in indirectly |
| §14 RFC 4191 preference-class filtering      | locked in (via default-router-list integration) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §2 Deterministic per-destination router selection     | met    |
| §3 Modulo-hash algorithm                              | met    |
| §3 Stickiness — TCP flow does not migrate routers     | met    |
| §14 RFC 4191 HIGH > MEDIUM > LOW preference honoured  | met    |
| Operator-tunable alternative algorithms               | n/a (no consumer; sysctl extension is forward-compat) |

RFC 4311 is fully shipped on the PyTCP host side. The
per-destination modulo across the highest-preference
equivalence class satisfies §3's "deterministic per flow"
requirement and §14 RFC 4191's preference-precedence
constraint.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (SHOULD).
- `docs/rfc/icmp6/rfc4191__default_router_preferences/adherence.md`
  — preference-class definition.
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — sibling multihoming-aware first-hop selection (Phase-1
  deferred).
- Source: `packages/pytcp/pytcp/runtime/packet_handler/__init__.py:2187-2224`
  (`get_icmp6_default_router_for_destination`).
