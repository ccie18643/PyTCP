# RFC 8028 — First-Hop Router Selection by Hosts in a Multi-Prefix Network

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 8028                                              |
| Title       | First-Hop Router Selection by Hosts in a Multi-Prefix Network |
| Category    | Standards Track (Updates RFC 4861, RFC 6724)      |
| Date        | November 2016                                     |
| Source text | [`rfc8028.txt`](rfc8028.txt)                      |

## Status: partial (SHOULD per RFC 8504 §5.10)

In a multi-prefix multi-router network — where a host has
addresses from prefix A advertised by router R_A and from
prefix B advertised by router R_B, and both upstreams
implement BCP 38 ingress filtering — picking the wrong
first-hop router for an outbound packet causes the
upstream provider to drop the packet (the packet's source
address doesn't match the prefix BCP 38 expects to see
behind that router).

RFC 8028 mandates that hosts pair source-address selection
with first-hop router selection — when the host picks
source `A::1`, it must route through `R_A`; when it picks
`B::1`, route through `R_B`.

**Shipped:** PyTCP records the announcing router with every
SLAAC/temporary address it forms, so the per-prefix gateway
state RFC 8028 needs is present.
`Icmp6SlaacAddress.router_address` and
`Icmp6TempAddress.router_address`
(`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:104`
and `:163`) capture the RA source that advertised the
prefix. The accessor
`get_icmp6_default_router_for_source(source=...)`
(`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:2226-2262`,
RFC 8028 §3) resolves the source address to the SLAAC entry
that owns it and returns the matching default router,
falling back to the highest-preference default router when
no source-matching entry exists.

**Deferred:** the accessor is not yet wired into the live
TX routing decision — the Ethernet-TX gateway lookup still
keys off the destination via the FIB rather than pairing
source selection with first-hop selection. Closing the gap
is the routing-integration step plus the companion Rule 5.5
update to RFC 6724 source selection.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.10
  — parent classification (SHOULD)
- `docs/rfc/ip6/rfc6724__default_address_selection/adherence.md`
  — companion deferred record (Rule 5.5)
- `docs/rfc/icmp6/rfc4191__default_router_preferences/adherence.md`
  — companion record (default-router preference consumed;
  per-prefix router state shipped)
