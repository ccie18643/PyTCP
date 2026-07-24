# RFC 4941 — Privacy Extensions for Stateless Address Autoconfiguration in IPv6

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4941                                              |
| Title       | Privacy Extensions for Stateless Address Autoconfiguration in IPv6 |
| Category    | Standards Track (Obsoletes RFC 3041; OBSOLETED by RFC 8981) |
| Date        | September 2007                                    |
| Source text | [`rfc4941.txt`](rfc4941.txt)                      |

## Status: SUPERSEDED by RFC 8981

RFC 4941 was obsoleted by **RFC 8981** in February 2021.
PyTCP tracks the modern spec at
[`docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md`](../rfc8981__temp_addresses/adherence.md);
that is where temporary-address-related implementation work
lands. Per nd_linux_parity §18, the generation (§18a,
`from_rfc8981_temp`) and RA-driven maintenance (§18b,
`_update_icmp6_temp_address`) halves have shipped; only the
§18c regeneration timer and §18d source-selection preference
remain deferred.

This record is retained for historical reference. The
two specs share the same overall mechanism (random per-prefix
IID + parallel temporary address + regeneration cycle); RFC
8981 tightens defaults (e.g. `TEMP_PREFERRED_LIFETIME`,
DESYNC_FACTOR computation), drops some MAY clauses, and
brings the wording in line with RFC 8504 §6.4 RECOMMENDED
status (RFC 4941 was SHOULD).

**Do not implement RFC 4941 directly.** Any privacy-extensions
work must follow RFC 8981.

## Cross-references

- `docs/rfc/icmp6/rfc8981__temp_addresses/adherence.md` —
  the canonical successor specification.
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.4
  — parent classification (RECOMMENDED in modern wording).
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC record.
- `docs/rfc/icmp6/rfc7217__stable_iid/adherence.md` —
  the orthogonal "stable but opaque IID" approach.
- `docs/rfc/ip6/rfc6724__default_address_selection/adherence.md`
  — temporary-address preference handling.
