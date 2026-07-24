# RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6

| Field       | Value                                                                            |
|-------------|----------------------------------------------------------------------------------|
| RFC number  | 8981                                                                             |
| Title       | Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6     |
| Category    | Standards Track (Obsoletes RFC 4941)                                             |
| Date        | February 2021                                                                    |
| Source text | (RFC text not yet copied locally — fetch from https://www.rfc-editor.org/rfc/rfc8981.txt when filling in the audit) |

## Status: §18a (random IID) and §18b (per-PI claim) shipped; §18c (regen) and §18d (RFC 6724 source-selection) deferred

### What ships now (§18a + §18b)

**§18a** — `Ip6IfAddr.from_rfc8981_temp(*, ip6_network)` at
`packages/net_addr/net_addr/ip6_ifaddr.py`. Each call produces a fresh 64-bit
random IID via `secrets.token_bytes(8)`, regenerates if the
draw lands in the RFC 5453 / RFC 2526 §3 reserved range
(Subnet-Router Anycast IID==0 or
0xfdff_ffff_ffff_ff80..ffff Reserved Subnet Anycast), and
gives up after 10 retries (safeguard against a broken
random source — at 64 bits the expected hit rate is
~7e-18). A shared `_is_reserved_iid()` helper at module
scope is exposed for §17's RFC 7217 generator to reuse
when its own reserved-IID check lands.

**§18b** — Per-prefix temp-address table parallel to
`_icmp6_slaac_addresses`. The mutator
`_update_icmp6_temp_address(*, prefix, valid_lifetime,
preferred_lifetime, router_address)` is invoked from the
RA RX path immediately after the stable
`_update_icmp6_slaac_address` call; it is sysctl-gated by
`icmp6.use_tempaddr` (default 0). When enabled:

- New prefix → generate via `Ip6IfAddr.from_rfc8981_temp`,
  spawn an async DAD claim via the §20.1
  `claim_ip6_address_async` helper (which runs DAD on a
  daemon worker thread without blocking the RX path),
  append `Icmp6TempAddress(address, prefix,
  preferred_until, valid_until, created_at,
  router_address)` to `_icmp6_temp_addresses`.
- Existing prefix → refresh `preferred_until` /
  `valid_until` deadlines but preserve the address (the
  regeneration cycle is §18c).
- `valid_lifetime=0` → remove the entry (RFC 4862
  §5.5.3 (e)(4) interaction).

Lifetimes are clamped at creation:

- `valid_until = now + min(advertised, TEMP_VALID_LIFETIME)`
  — TEMP_VALID_LIFETIME default 7 days
  (`icmp6.temp_valid_lifetime_s = 604800`).
- `preferred_until = now + max(0, min(advertised,
  TEMP_PREFERRED_LIFETIME) - DESYNC)` — TEMP_PREFERRED_LIFETIME
  default 1 day (`icmp6.temp_preferred_lifetime_s = 86400`),
  with `DESYNC = random.uniform(0, MAX_DESYNC_FACTOR)`
  (default 600s) subtracted to prevent fleet-wide
  synchronised regeneration.

The new sysctls match Linux's
`net.ipv6.conf.<iface>.{use_tempaddr,
temp_valid_lft, temp_prefered_lft, max_desync_factor}`.
PyTCP uses the corrected spelling `temp_preferred_lifetime_s`
rather than Linux's typoed `temp_prefered_lft`.

Per-RFC mechanism inventory:

| §       | Mechanism                                              | Status   | Where                                                                |
|---------|--------------------------------------------------------|----------|----------------------------------------------------------------------|
| §3.1    | `use_tempaddr` knob                                    | met      | `icmp6.use_tempaddr` sysctl, tristate {0,1,2}                        |
| §3.3.2  | Random 64-bit IID generation                           | met      | `Ip6IfAddr.from_rfc8981_temp` — §18a                                   |
| §3.3.2  | Reserved-IID avoidance (RFC 5453 / 2526)               | met      | `_is_reserved_iid()` helper                                          |
| §3.3.3  | Re-derive on DAD failure (`MAX_DESYNC_FACTOR` retries) | gap      | §18c / §20.3 (DAD-failure retry) — `IDGEN_RETRIES`                   |
| §3.4    | Per-PI lifetime refresh (preserve address)             | met      | `_update_icmp6_temp_address` existing-entry path                     |
| §3.4    | Lifetime clamp to `TEMP_*_LIFETIME`                    | met      | `min(advertised, TEMP_*)` at creation                                |
| §3.4    | Regeneration cycle before preferred_lifetime expires   | gap      | §18c (background thread)                                             |
| §3.5    | Source-address preference (RFC 6724 rule 7)            | gap      | §18d / §12c (RFC 6724 selector)                                      |
| §3.8    | Default constants (TEMP_VALID=7d, TEMP_PREF=1d, etc.)  | met      | `nd__constants.py` registers all four with Linux-parity defaults     |

### What remains deferred (§18c, §18d)

- **§18c — Regeneration subsystem**. Background thread
  rotates the temp address before its preferred lifetime
  expires (RFC 8981 §3.4 regeneration cycle). Without
  this, today's temp address is single-shot per prefix;
  it expires when `preferred_until` passes and is never
  regenerated until the next RA. Linux's regen machinery
  is in `addrconf.c::ipv6_create_tempaddr` /
  `manage_tempaddrs`.
- **§18d — RFC 6724 source-address selection consumer**.
  Without this, the temp address is created and DADed but
  TX still picks the stable RFC 7217 address. RFC 6724
  rule 7 ("prefer temporary addresses") makes the privacy
  benefit observable. Tracked under nd_linux_parity §12c
  — its own separate phase since RFC 6724 also affects
  IPv4 source selection.

The host still has the stable opaque IID from RFC 7217
(§17 shipped) by default, which already mitigates
cross-network correlation. RFC 8981 layered on top
adds additional unlinkability for outbound flows once
§18c/§18d ship.

### Tests

`packages/net_addr/net_addr/tests/unit/test__ip6_ifaddr.py::TestNetAddrIp6HostFromRfc8981Temp`
(§18a wire generator — already shipped):
- Output keeps source /64 prefix.
- Two consecutive calls yield different IIDs.
- /64 mask required.
- Reserved-IID values regenerated to non-reserved.
- Retry exhaustion raises `Ip6IfAddrSanityError`.

`packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc8981_temp.py`
(§18b wire-state + RX-driven claim — this commit):
- `TestIcmp6Nd__Rfc8981Temp__SysctlRegistration` —
  `icmp6.use_tempaddr` registered with default 0,
  validator accepts tristate {0,1,2}; lifetime constants
  registered with RFC 8981 §3.8 defaults.
- `TestIcmp6Nd__Rfc8981Temp__MutatorWireState` — direct
  mutator tests covering: sysctl=0 no-op, random IID
  derivation, lifetime clamping, valid_lifetime=0
  removal, refresh preserves address, lazy-aged accessor.
- `TestIcmp6Nd__Rfc8981Temp__RxDrivenClaim` — driving an
  RA via the RX path with sysctl=1 creates one stable
  + one temp entry; sysctl=0 creates only the stable
  entry; the DAD worker installs the temp address into
  `_ip6_ifaddr` after passing.

## Cross-references

- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md` —
  predecessor RFC; §19 marked superseded by RFC 8981.
- `docs/rfc/icmp6/rfc7217__stable_iid/adherence.md` —
  the orthogonal "stable but opaque IID" approach; the
  modern recommendation is **both** (stable IID for the
  long-lived address, RFC 8981 temporary IIDs for
  outbound flows).
- `docs/rfc/icmp6/rfc4429__optimistic_dad/adherence.md` —
  §20.1 async DAD refactor unblocked the per-PI claim
  path used by §18b; without it the temp-address claim
  would have to block the RX thread.
- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` —
  §6.4 RECOMMENDS implementation.
