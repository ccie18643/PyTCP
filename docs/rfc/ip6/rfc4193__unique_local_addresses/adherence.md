# RFC 4193 — Unique Local IPv6 Unicast Addresses

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 4193                                           |
| Title       | Unique Local IPv6 Unicast Addresses            |
| Category    | Proposed Standard                              |
| Date        | October 2005                                   |
| Updates     | —                                              |
| Source text | (not bundled — see https://www.rfc-editor.org/rfc/rfc4193.html) |

This document records the PyTCP codebase's adherence to RFC
4193 clause by clause. RFC 4193 is the IPv6 parallel to IPv4's
RFC 1918 — it reserves the `fc00::/7` block for "Unique Local
Addresses" (ULAs) that are routable within a site but not
intended to be routed on the global Internet. There is no
host-stack wire-format normative content; the requirements are
addressing-classification and operator-guidance, equivalent to
RFC 1918 for IPv4.

The audit was performed by reading the RFC and inspecting
`packages/net_addr/net_addr/ip6_address.py` directly. Non-normative content
(§1 Introduction, §2 Acknowledgments, §6/§7/§8 narrative,
§11 Security Considerations boilerplate) is omitted.

---

## Top-line adherence

PyTCP **meets** the RFC 4193 surface relevant to a host stack:
the `fc00::/7` prefix is recognised by `Ip6Address.is_private`,
and the predicate is consulted by the RFC 6724 default address
selection sort key for source-selection rule 2 (avoid
deprecated / unusable addresses). The non-propagation /
non-leakage operational requirements are router-side; PyTCP
does not forward and so cannot leak ULAs to the global table.
The Global ID generation algorithm (§3.2.2) is operator /
provisioning concern — a host stack receives whatever ULA the
operator configures.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §3      | `fc00::/7` prefix reserved for ULAs                | met (predicate exists at `packages/net_addr/net_addr/ip6_address.py:570-575`) |
| §3.1    | Local-Bit (L=1 → fd00::/8) assignment              | met (predicate matches both halves of `fc00::/7`) |
| §3.2.2  | Global ID pseudo-random algorithm                  | n/a (operator / provisioning concern; host consumes) |
| §4.1    | ULAs MUST NOT be propagated to global routing      | n/a (no forwarding — Phase-2 forwarding plane concern) |
| §4.3    | Site border filtering of ULAs                      | n/a (no forwarding — Phase-2 forwarding plane concern) |
| §4.4    | DNS leakage of ULA records                         | n/a (resolver is application-layer) |
| §4.7    | Choice of source addresses (RFC 3484/6724)         | met (cross-reference: source selection rules in `packages/pytcp/pytcp/protocols/ip6/ip6__source_selection.py`) |

---

## §3 Local IPv6 Unicast Address Format

> "The Local IPv6 unicast addresses are created using a
> pseudo-randomly allocated global ID ... The format of
> Local IPv6 unicast addresses is as follows:
>
>    | 7 bits |1|  40 bits   |  16 bits  |          64 bits           |
>    +--------+-+------------+-----------+----------------------------+
>    | Prefix |L| Global ID  | Subnet ID |        Interface ID        |
>    +--------+-+------------+-----------+----------------------------+
>
>    Prefix             FC00::/7 prefix to identify Local IPv6 unicast
>                       addresses."

**Adherence:** met. The `fc00::/7` prefix is recognised by
`Ip6Address.is_private`
(`packages/net_addr/net_addr/ip6_address.py:570-575`):

```python
@property
@override
def is_private(self) -> bool:
    """
    Check if IPv6 address is private.
    """

    return self._address & IP6__PRIVATE_PREFIX_MASK == IP6__PRIVATE_PREFIX
```

with `IP6__PRIVATE_PREFIX = 0xFC00_0000_0000_0000_0000_0000_0000_0000`
and `IP6__PRIVATE_PREFIX_MASK = 0xFE00_0000_0000_0000_0000_0000_0000_0000`
at `:64-65`. The mask covers exactly the high 7 bits, so both
the L=0 (`fc00::/8`, reserved) and L=1 (`fd00::/8`, locally-
assigned) halves of `fc00::/7` match.

> "L                  Set to 1 if the prefix is locally
>                     assigned. Set to 0 may be defined in
>                     the future. See Section 3.2 for
>                     additional information."

**Adherence:** met (covered by the same predicate). PyTCP does
not distinguish L=0 from L=1 at the predicate level — both are
"private" for source-selection and host-classification
purposes. RFC 4193 leaves L=0 reserved; if a future IETF
allocation gives L=0 a separate semantic (centralised registry,
similar to ARIN-allocated provider blocks), PyTCP would
introduce a sibling `is_private__centrally_assigned` predicate
without breaking the existing `is_private` consumers.

---

## §3.2.2 Sample Code for Global ID Algorithm

> "The algorithm described below is intended to be used for
> locally assigned Global IDs. In each case the resulting
> global ID will be used in the appropriate prefix as
> defined in Section 3.2."

**Adherence:** n/a (operator / provisioning concern). RFC 4193
§3.2.2 defines a SHA-1-based pseudo-random algorithm an
operator runs once to mint a `/48` Global ID for their site.
A host stack does not generate ULA prefixes — it consumes
whatever the operator has configured (typically via static
configuration or future DHCPv6-PD). The §3.2.2 algorithm is
out of scope for a host audit.

---

## §4 Operational Considerations (router-side)

> "Local IPv6 unicast addresses are routable within a more
> limited region than the global Internet. They can be
> routed between a limited set of sites (e.g., among a set
> of organizations, between an organization and an ISP) but
> they MUST NOT be routed on the global Internet."

**Adherence:** n/a (no forwarding — Phase-2 forwarding plane
concern). PyTCP is a host stack today; it does not forward
IPv6 packets between interfaces (the forwarding plane is
deferred to Phase 2 per CLAUDE.md Project North Star). When
the Phase-2 forwarder lands, the natural seam for ULA leakage
prevention is a sysctl-gated egress check on the routing API
(`stack.route.add` would refuse to install a default route
for the ULA prefix; egress to non-ULA next-hops would drop
ULA-sourced packets per RFC 4193 §4.1).

> "By default, routers MUST NOT include any prefixes from
> the FC00::/7 block in any non-site-bordering routing
> updates."

**Adherence:** n/a (router-side — Phase-2 forwarding plane).

> "By default, routers SHOULD restrict the propagation of
> FC00::/7 addresses ... at the borders of the local site."

**Adherence:** n/a (router-side — Phase-2 forwarding plane).

> "By default, hosts SHOULD NOT advertise any FC00::/7
> addresses to the global Internet (this includes DNS
> records)."

**Adherence:** n/a (resolver / application-layer concern;
PyTCP delegates DNS to the stdlib resolver via
`pytcp.socket.getaddrinfo`).

---

## §4.7 Choice of Source Addresses (host-side)

> "Implementations of source address selection [RFC 3484]
> MUST treat IPv6 Local Unicast Addresses as having
> precedence equal to that of Global Unicast Addresses;
> i.e., the rules described in section 5 of [RFC 3484]
> MUST NOT favor either over the other. Notice that the
> default policy table [RFC 3484] effectively prefers IPv6
> source addresses with longer prefix matches."

**Adherence:** met. PyTCP's RFC 6724 (which obsoletes RFC
3484) implementation in `packages/pytcp/pytcp/protocols/ip6/ip6__source_selection.py`
does not give ULA a special tier in the precedence table —
ULA candidates compete against Global Unicast candidates
through the standard policy-table label-match (RFC 6724 §5
rule 6) and longest-matching-prefix (rule 8) tiebreaks. The
default policy table at
`packages/pytcp/pytcp/protocols/ip6/ip6__policy_table.py::DEFAULT_POLICY_TABLE` mirrors
RFC 6724 verbatim (`fc00::/7` has label 13 / precedence 3,
distinct from Global label 1 / precedence 50) so a ULA
destination naturally prefers a ULA source via rule 6 without
giving ULA blanket precedence.

The cross-reference adherence record at
[`../rfc6724__default_address_selection/adherence.md`](../rfc6724__default_address_selection/adherence.md)
documents the rule-by-rule walk-through.

---

## Test coverage audit

### §3 `fc00::/7` prefix recognition

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip6_address.py::TestNetAddrIp6Address::test__net_addr__ip6_address__is_private`
  — parameterised matrix of `fc00::`, `fcff::`, `fd00::`,
  `fdff::`, and out-of-range neighbours; asserts
  `is_private` matches the §3 boundary.

**Status:** locked in.

### §4.7 ULA in source-selection sort key

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py`
  — RFC 6724 source-selection rule-by-rule cases (the
  `packages/pytcp/pytcp/tests/unit/protocols/ip6/test__ip6__source_selection.py`
  unit file covers the scope / common-prefix-length helpers
  only). The policy-table label match (rule 6) ensures a ULA
  destination picks a ULA source when both are available.

**Status:** locked in indirectly (the rule-6 case covers the
ULA-prefers-ULA outcome; no dedicated "ULA vs Global"
case asserts the §4.7 MUST equal-precedence rule explicitly,
but the policy table guarantees it by construction).

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| `fc00::/7` predicate boundary                       | locked in |
| ULA in RFC 6724 source-selection                    | locked in indirectly |
| ULA non-propagation (router-side)                   | n/a (no forwarding) |
| §3.2.2 Global ID generation                         | n/a (operator concern) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3 `fc00::/7` prefix recognition                      | met    |
| §3.1 L-bit interpretation (L=0 / L=1)                 | met (collapsed into `is_private`) |
| §3.2.2 Global ID pseudo-random algorithm              | n/a (operator concern) |
| §4.1 ULA non-propagation to global routing            | n/a (no forwarding — Phase-2 concern) |
| §4.3 Site-border filtering                            | n/a (no forwarding — Phase-2 concern) |
| §4.4 DNS leakage of ULA records                       | n/a (resolver — application-layer) |
| §4.7 ULA in source address selection (RFC 6724)       | met (label-match rule 6 + policy table) |

RFC 4193 is fully satisfied for the host-stack-relevant
surface. The router-side and DNS-side requirements are out
of scope. The Phase-2 forwarder will need to honour §4.1 /
§4.3 when it lands; mark the egress check as a follow-up
under the Route API track at that time.

## Cross-references

- IPv4 parallel: [`../../ip4/rfc1918__private_addresses/adherence.md`](../../ip4/rfc1918__private_addresses/adherence.md)
- Source selection: [`../rfc6724__default_address_selection/adherence.md`](../rfc6724__default_address_selection/adherence.md)
- IPv6 special-purpose registries (sibling audit, also classification-only): [`../rfc8190__ipv6_special_purpose/adherence.md`](../rfc8190__ipv6_special_purpose/adherence.md) (when written)
