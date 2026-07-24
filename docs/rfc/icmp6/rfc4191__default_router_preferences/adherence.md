# RFC 4191 — Default Router Preferences and More-Specific Routes

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4191                                              |
| Title       | Default Router Preferences and More-Specific Routes |
| Category    | Standards Track (Updates RFC 2461 / RFC 2461-bis) |
| Date        | November 2005                                     |
| Source text | [`rfc4191.txt`](rfc4191.txt)                      |

## Status: partial (MUST per RFC 8504 §5.9, Type C host role SHOULD)

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §2.1    | Default Router Preference (Prf field)              | met    |
| §2.2    | RESERVED preference normalised to MEDIUM           | met    |
| §2.3    | Route Information Option                            | not implemented |
| §3      | Type C host more-specific-route table              | not implemented |

**§2.1 Default Router Preference — met.** The RA Preference
field (2-bit Prf; RFC 4191 §2.1) is parsed by the message
dataclass and consumed on the RX path:
`__phrx_icmp6__nd_router_advertisement`
(`packet_handler__icmp6__rx.py:896-899`) forwards
`packet_rx.icmp6.message.prf` into
`_update_icmp6_default_router`, which stores it on
`Icmp6DefaultRouter.prf`
(`packages/pytcp/pytcp/protocols/icmp6/nd/nd__router_state.py:67`,
class at `:53`). Per §2.2 a RESERVED (binary 10)
advertisement is normalised to MEDIUM at install time
(`__init__.py:1746`). The default-router accessor
`get_icmp6_default_routers` sorts active entries
HIGH > MEDIUM > LOW (`__init__.py:1781-1791`) so a consumer
picking `active[0]` gets the highest-preference router.

**§2.3 / §3 — not implemented.** RFC 4191 §3 introduces a
Type C host role with explicit per-prefix
more-specific-route table entries; PyTCP has no such table.
The Route Information option (RFC 4191 §2.3) is not parsed,
and there is no route table that source-address selection
consults when picking among candidate routers (closely
paired with RFC 8028 multihoming first-hop selection).
Closing this needs:

- Parsing the Route Information option (RFC 4191 §2.3),
  including the Route Lifetime, Prefix Length, Preference,
  and Prefix fields.
- A per-host route table with preference ordering.
- Source-address selection that consults the route table
  when picking among candidate routers.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.9
  — parent classification (MUST + Type C SHOULD)
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — companion record (multihoming first-hop selection)
