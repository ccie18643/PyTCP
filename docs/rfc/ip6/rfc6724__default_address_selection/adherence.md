# RFC 6724 — Default Address Selection for IPv6

| Field       | Value                                                            |
|-------------|------------------------------------------------------------------|
| RFC number  | 6724                                                             |
| Title       | Default Address Selection for Internet Protocol Version 6 (IPv6) |
| Category    | Standards Track (Updates RFC 4291; Obsoletes RFC 3484)           |
| Date        | September 2012                                                   |
| Source text | [`rfc6724.txt`](rfc6724.txt)                                     |

## Status: PARTIAL (source-selection rules 1, 2, 3, 6, 7, 8 shipped; IPv4 symmetry shipped; policy-table override shipped; DAS deferred)

PyTCP runs the RFC 6724 §5 default source-address-selection
algorithm on every outbound IPv6 packet whose source is
unspecified (`::`). The selector is `_select_ip6_source` on
the IPv6 TX mixin
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`); it
enumerates candidate sources from `_ip6_ifaddr`, applies a
lexicographic sort encoded with rules 1, 2, 3, 6, 7, and 8,
and returns the winner. The pure helpers — RFC 4007/4291
scope extraction and the §2.2 CommonPrefixLen — live in
`packages/pytcp/pytcp/lib/ip6_source_selection.py`; the §10.3 default policy
table backing rule 6 lives in
`packages/pytcp/pytcp/protocols/ip6/ip6__policy_table.py`.
Rules 4 (home address), 5 (outgoing interface), and 5.5
(next-hop) are no-ops on a single-interface host stack.

Rule 7 is gated by the `icmp6.use_tempaddr` sysctl matching
Linux semantics: `0` (no temp addresses to prefer), `1`
(temp addresses generated, no preference at TX), `2` (prefer
temp addresses at TX). With `use_tempaddr=2` the §18 RFC 8981
privacy benefit becomes observable on the wire — peers see
the random-IID temp source rather than the stable RFC 7217
IID.

Rule 6 consults the RFC 6724 §10.3 default policy table.
Default labels follow the RFC figure verbatim (label 0 for
::1/128, label 1 for the catch-all ::/0, label 2 for 6to4
2002::/16, label 4 for IPv4-mapped, label 5 for Teredo, label
13 for ULA fc00::/7, etc.). An operator may replace the active
table at runtime through `set_policy_table` /
`reset_policy_table` / `get_policy_table` on
`ip6__policy_table` — the PyTCP analogue of Linux
`ip addrlabel` (a dedicated control surface, not a `/proc/sys`
scalar, since a whole table is not a scalar sysctl). `lookup`
reads the active table each call (a copy-on-write reference
swap, lock-free under free-threading) so an override resolves
live for the rule-6 selector; `set_policy_table` rejects a
table with no ::/0 catch-all so `lookup` stays total.

The selector is invoked for both unicast and multicast
destinations with an unspecified source — a DHCPv6 SOLICIT to
the link-local-scoped `ff02::1:2` takes the link-local source,
matching Linux, which selects a source for a multicast send.
(Earlier the TX path gated selection on a unicast destination
and dropped every other src=:: multicast packet as malformed;
the gate now admits multicast and lets the §5 rule-2 scope
guard decide.) The DAD probe (NS with src=:: and no SLLA) and
MLDv2 report (src=::) short-circuit the selector ahead of this
— they MUST keep `src=::` regardless of the candidate set.

Per-RFC mechanism inventory:

| §          | Mechanism                                                  | Status                             | Where                                                                                            |
|------------|------------------------------------------------------------|------------------------------------|--------------------------------------------------------------------------------------------------|
| §2.1       | Configurable address-selection policy table                | met                                | `packages/pytcp/pytcp/protocols/ip6/ip6__policy_table.py` exposes `DEFAULT_POLICY_TABLE` + operator override (`set_policy_table` / `reset_policy_table` / `get_policy_table`, the `ip addrlabel` analogue) |
| §2.2       | CommonPrefixLen helper                                     | met                                | `common_prefix_len` (`packages/pytcp/pytcp/lib/ip6_source_selection.py`)                                        |
| §3.1       | Scope comparisons                                          | met                                | `ip6_address_scope` returns RFC 4007 / 4291 codepoints                                           |
| §5 rule 1  | Prefer same address                                        | met                                | `_select_ip6_source` short-circuits when the destination is owned                                |
| §5 rule 2  | Prefer appropriate scope                                   | met                                | sort key encodes `(scope >= dst_scope, -scope)`; the selector additionally returns `None` when the winner's scope < dst (RFC 4007 §6 hardening) |
| §5 rule 3  | Avoid deprecated addresses                                 | met                                | sort key consults `Icmp6SlaacAddress.state(now) is DEPRECATED`                                   |
| §5 rule 4  | Prefer home addresses                                      | not applicable (out of scope)      | mobility extensions excluded from PyTCP scope (CLAUDE.md project north star)                     |
| §5 rule 5  | Prefer outgoing interface                                  | not applicable (single interface)  | single-interface host stack; multi-interface support is a future Phase 2 concern                 |
| §5 rule 5.5| Prefer source whose first-hop matches next-hop (RFC 8028)  | not implemented (RFC 8028 deferred)| see `docs/refactor/nd_linux_parity.md` §23                                                       |
| §5 rule 6  | Prefer matching label (policy table)                       | met                                | `_select_ip6_source` sort key consults `ip6_policy_table.lookup`                                 |
| §5 rule 7  | Prefer temporary addresses                                 | met                                | gated by `icmp6.use_tempaddr=2`; rule-7 score in `_select_ip6_source` sort key                   |
| §5 rule 8  | Use longest matching prefix                                | met                                | sort-key tiebreak after rules 1/2/3                                                              |
| §6 (v4)    | IPv4 source-selection symmetry                             | met (rules 1, 2, 8)                | `_select_ip4_source` mirrors `_select_ip6_source` for the v4 family at TX                        |
| §6 (DAS)   | Destination address selection                              | not implemented                    | DNS-resolution selection (rules D1-D8) is out of scope at the stack layer                        |
| §10.3      | Default policy table                                       | met                                | `DEFAULT_POLICY_TABLE` mirrors RFC figure verbatim; operator override via `set_policy_table` (rejects a table with no ::/0 catch-all) |

## Test coverage

- `packages/pytcp/pytcp/tests/unit/lib/test__lib__ip6_source_selection.py`
  - `TestIp6AddressScope` — RFC 4007/4291 scope mapping for
    loopback, link-local, ULA, GUA, and the four multicast
    scope codepoints (interface-, link-, site-, global-)
  - `TestCommonPrefixLen` — symmetric, bounded
    `common_prefix_len` matching the §2.2 definition
  - `TestIp6AddressScopeEdgeCases` — unspecified address
    falls through to global scope; scope ordering is
    monotonic
  - `TestCommonPrefixLenInvariants` — `[0, 128]` bounds and
    matching the disagreement-bit definition
- `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py`
  - `TestRfc6724Rule1SameAddress` — rule 1 short-circuit
  - `TestRfc6724Rule2Scope` — global / link-local scope
    matching; selector returns `None` when only smaller-scope
    candidates exist (RFC 4007 §6 hardening); link-local
    source admitted for link-local unicast and link-local
    multicast (ff02::) destinations; rejected for global
    multicast (ff0e::)
  - `TestRfc6724Rule3Deprecated` — PREFERRED ranks above
    DEPRECATED; non-SLAAC addresses default to PREFERRED
  - `TestRfc6724Rule8LongestMatch` — longest common prefix,
    deterministic outcome for unrelated destinations
  - `TestRfc6724SelectorBoundaries` — empty candidate set
    returns `None`; rule order is preserved
    (rule 1 > rule 3)
- `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection_rule_7.py`
  - `TestRfc6724Rule7TempPreferenceEnabled` — `use_tempaddr=2`
    prefers temp over stable; outranks rule 8; rule 3
    (PREFERRED-over-DEPRECATED) still wins
  - `TestRfc6724Rule7TempNoPreference` — `use_tempaddr=1`
    leaves rule 8 to decide
  - `TestRfc6724Rule7TempDisabled` — `use_tempaddr=0` keeps
    rule 7 a no-op even if a temp address slips into the
    candidate set
- `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6__tx.py`
  - `TestPacketHandlerIp6TxValidation.test__stack__packet_handler__ip6__tx__src_unspec_multicast_dst_replaced`
    — the TX path runs §5 selection for a multicast
    destination (link-local source filled in for `ff02::1:2`)
    rather than dropping it
- `packages/pytcp/pytcp/tests/unit/protocols/ip6/test__ip6__policy_table.py`
  - `TestIp6PolicyTableLookup` — RFC §10.3 (precedence, label)
    pairs for ::1, 6to4, Teredo, ULA, deprecated site-local,
    deprecated 6bone, IPv4-mapped, IPv4-compatible,
    catch-all GUA, and link-local (falls through to ::/0)
  - `TestIp6PolicyTableShape` — 9-entry default table,
    typed records, ::/0 catch-all present
  - `TestIp6PolicyTableOverride` — `set_policy_table` overrides
    `lookup` live, `reset_policy_table` restores the default,
    `get_policy_table` returns the active snapshot, and a table
    with no ::/0 catch-all is rejected
- `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection_rule_6.py`
  - `TestRfc6724Rule6PolicyLabel` — matching label outranks
    longer non-matching prefix (rule 6 > rule 8); ULA
    source for ULA destination; rule 8 fallback when rule 6
    ties; rule 3 outranks rule 6
- `packages/pytcp/pytcp/tests/unit/lib/test__lib__ip4_source_selection.py`
  - `TestIp4AddressScope` — loopback / link-local / global
    scope mapping for the v4 family
  - `TestIp4CommonPrefixLen` — 32-bit common-prefix
    arithmetic; symmetric, bounded
  - `TestIp4SourceSelectionInvariants` — scope monotonicity,
    `[0, 32]` bounds
- `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  - `TestRfc6724Ip4Rule1SameAddress` — rule 1 short-circuit
  - `TestRfc6724Ip4Rule2Scope` — global-dst picks global
    source; link-local-dst picks link-local source
  - `TestRfc6724Ip4Rule8LongestMatch` — longest common
    prefix wins; deterministic outcome for unrelated dst
  - `TestRfc6724Ip4SelectorBoundaries` — empty candidate
    set returns `None`; rule 1 outranks rule 8

## Cross-references

- `docs/refactor/rfc6724_source_selection.md` — multi-commit
  implementation plan (§12c.1 → §12c.4 all shipped; only
  §10.3 sysctl-driven policy-table override and §6
  destination-address selection remain as out-of-scope or
  deferred sub-tasks)
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.6 —
  parent classification (MUST)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` §5.5.4 —
  source of the PREFERRED / DEPRECATED state machine the
  rule-3 path consumes
- `docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md` §18d —
  privacy-consumer pin for rule 7 (§12c.2)
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — companion deferred record for rule 5.5
- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md`
  — historical predecessor to RFC 8981 (rule 7 consumer)
