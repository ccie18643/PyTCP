# IPv4 Audit Punch List

This document captures the inventory of remaining work after
the 2026-05-11 IPv4 audit-and-fix session. It is the
canonical reference for picking up the next track without
re-deriving the gap analysis.

The session shipped 8 commits forming a coherent "IPv4 audit
set + Phase-1 gap closures + IPv6 bonus" story on
`PyTCP_3_0__pre_release` (origin tip: `77ee76bc` after push).

## Session-shipped commits (newest first)

| Hash       | Title                                                                            |
|------------|----------------------------------------------------------------------------------|
| `ea4dc155` | IPv4 TX: gate outbound broadcast emission via 'ip4.allow_broadcast' sysctl (item C) |
| `f2cae9a6` | IPv4 RX: add RFC 3168 §5.3 wire-level reassembly tests (item B)                  |
| `9388a651` | IPv4 TX: register 'ip4.default_ttl' as runtime-tunable sysctl (item A)           |
| `d21b404e` | docs: add IPv4 audit punch list                                                  |
| `77ee76bc` | IPv6 TX: RFC 4007 §6 / RFC 4291 §2.5.6 link-local scope gate                     |
| `858308b0` | IPv4 fragmentation: RFC 791 §3.1 option-copy-flag + RFC 815 §6 reassembly preservation |
| `95a62524` | IPv4 TX: RFC 1112 §6.1 multicast TTL=1 + RFC 6864 §4.1 atomic ID=0 test          |
| `c6628b2e` | RFC 3168 adherence: refresh §5.3 status to met                                   |
| `e2dc5971` | IPv4/IPv6 reassembly: RFC 3168 §5.3 ECN aggregation                              |
| `ef855d30` | IPv4/IPv6 TX: extract iter_fragment_chunks helper                                |
| `435bbfd1` | IPv4 RFC adherence: add 16 audit records                                         |

## What shipped — by audit topic

- **RFC 791 §3.1** — option copy-flag on TX fragmentation + RFC
  815 §6 option preservation on RX reassembly. `Ip4Option.copy_flag`
  property, `Ip4Options.with_copy_flag(bool)` filter,
  `Ip4FragAssembler` options serialization, RX header rewrite
  preserves first-fragment IHL.
- **RFC 815** — reassembly machinery audited; §6 options
  preservation flipped from "stripped" to "preserved" via the
  fix above.
- **RFC 1112 §6.1** — outbound multicast TTL defaults to 1
  (was using `IP4__DEFAULT_TTL=64` for all destinations).
  `_phtx_ip4` resolves the `None` sentinel based on dst scope.
- **RFC 1191** — PMTUD audit existed pre-session; not touched.
- **RFC 1122 §3** — host requirements audited; §3.2.1.7 TTL
  configurability noted as informally met (module constant).
- **RFC 3168 §5.3** — ECN aggregation on reassembly. Shared
  IpFragTable now tracks per-offset ECN; aggregator follows
  Linux `ip_frag_ecn_table[]`; ECN_MIXED__DROP outcome for the
  §5.3 second branch. Benefits both IPv4 and IPv6.
- **RFC 6864 §4.1** — atomic-datagram ID=0 dedicated test added.
- **RFC 4007 §6 / RFC 4291 §2.5.6** — IPv6 link-local scope
  gate (bonus, not in the original 5-item list). RFC 6724
  selector returns `None` when no candidate has scope ≥ dst;
  explicit-src gate rejects scope mismatches with
  `DROPPED__IP6__SRC_SCOPE_MISMATCH`.

## What's left — by tier

### Phase-1 sharpenings

All three items A + B + C from the original session-close
punch list have shipped (commits `9388a651`, `f2cae9a6`,
`ea4dc155` on `PyTCP_3_0__pre_release`). No outstanding
Phase-1 sharpenings remain from the 2026-05-11 session
inventory.

### Phase-1 features — bigger, dedicated tracks

| # | Item | RFC | Effort | Notes |
|---|------|-----|--------|-------|
| ~~D~~ | ~~**IPv4 link-local autoconfig**~~ | ~~3927~~ | ~~2-4 days~~ | **SHIPPED** — phases 0 / 0.5 / 1 / 2 / 3 / 4 / 5 of the RFC 3927 track. **Reconciled 2026-05-30:** the end-state ACD does NOT run through a sanctioned `Ip4AddressApi` claim/retry surface — it runs in userspace over per-address `Ip4Acd` AF_PACKET sockets (`protocols/ip4/acd/ip4_acd.py`); the link-local client calls `Ip4Acd.claim` / `Ip4Acd.poll_conflict` directly (cross-ref `rfc3927_link_local_autoconfig.md`, `raw_link_socket.md`). Otherwise: subsystem skeleton + MAC-seeded RNG; claim + retry + rate-limit; §2.5 defend / abandon; §1.9 / §2.11 DHCP coordination; stack-side wiring. Plan doc: `docs/refactor/rfc3927_link_local_autoconfig.md`. Adherence record: `docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md` (every §-section met). |
| ~~E~~ | ~~**Multicast group membership API + IGMPv2/v3**~~ | ~~1112 / 2236 / 3376~~ | ~~Multi-day~~ | **SHIPPED.** IPv4 multicast group membership (RFC 1112 Level 2) — runtime `IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP`, membership refcount, per-socket source filters (`IP_ADD/DROP_SOURCE_MEMBERSHIP`, `IP_BLOCK/UNBLOCK_SOURCE`), Reports, Group-Specific Queries, RFC 3376 §7 v1/v2 querier-version fallback, and graceful Leave on stack.stop(). See `docs/refactor/igmp_refinements.md`, `igmp_version_fallback.md`, `igmp_source_specific_multicast.md`. Deferred (Phase-2 router only): IGMPv3 router/querier role. |
| ~~F~~ | ~~IPv6 audit set parity sweep~~ | ~~—~~ | ~~1-2 days~~ | **SHIPPED 2026-05-29.** Comparative IPv4↔IPv6 audit-set diff found the IPv6 data plane already well-implemented; the asymmetry was in the audit records, not the code. 1 code fix + 4 doc items: RFC 8200 §4.2 action-11 multicast suppression + RFC 4443 §2.4(e.3) code-2 exception (`5727911e`); new ip6 RFC 3168 (ECN) + RFC 2474 (DSCP) records + rfc8504 §5.12 flip (`c8effda6`); new ip6 RFC 2711 (Router Alert) record (`4c816c38`). Plan + findings: `docs/refactor/ipv6_audit_parity.md`. |

### Phase-2 items (project north-star — deferred until forwarding plane)

- **RFC 1812 §5** — full forwarding plane (the big one)
- **RFC 791 §3.1 / RFC 1812 §4.2.2.9** — forward-path TTL
  decrement + ICMP Time Exceeded emission
- **RFC 1122 §3.3.1.5 + RFC 1812 §4.3.3.2** — ICMP Redirect
  emission + RX route-cache update
- **RFC 6864 §4.3** — per-tuple non-atomic IPv4 ID partitioning
- **RFC 1122 §3.3.5** — source-route forwarding (LSRR/SSRR
  pointer advance)
- **RFC 1122 §3.3.4** — multihoming
- **RFC 3168 §9** — IP-in-IP tunnel ECN decapsulation
- **RFC 7126** — per-option drop knobs (RR/Timestamp/Stream ID)
- **RFC 6890** — special-purpose block predicates (CGN,
  Documentation, Benchmark) — host-side low-impact, becomes
  relevant for firewall plane

### From earlier in this session — DHCP track

The DHCPv4 client (multi-commit track that preceded the IPv4
audit work) is feature-complete through Phase 8.x with the
following items deferred:

- **DHCPv4 Phase 7** — multi-default-gateway / route-table
  integration. Blocked on PyTCP gaining a real route-table layer.
- **DHCPv4 Phase 9** — DHCPINFORM (§3.4). Niche, no PyTCP
  consumer for DNS/NTP/etc. config today. Discussed in this
  session.

See `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md` for the
full DHCPv4 adherence record.

## Cross-track context

### Autoconfiguration coverage

PyTCP now supports **all three** main IPv4 / IPv6
autoconfiguration mechanisms:

1. **DHCPv4** — full client, shipped in earlier session.
2. **IPv6 SLAAC** (RFC 4862) — shipped via ND track.
3. **IPv4 link-local autoconfig** (RFC 3927) — shipped via
   the RFC 3927 track (item D below).

### Phase-3 sanctioned API surfaces

The Phase-3 north-star (CLAUDE.md) lists seven sanctioned
consumer-API surfaces. Status as of 2026-05-12 (**Reconciled
2026-05-30:** Route API and Neighbor API have since shipped;
the Address API is the family-agnostic `AddressApi`, not
`Ip4AddressApi`):

| Surface           | Status                                                                                       |
|-------------------|----------------------------------------------------------------------------------------------|
| Socket factory    | shipped (BSD-style `socket()` factory + methods)                                             |
| Sysctl registry   | shipped (`pytcp.stack.sysctl`)                                                               |
| **Link API**      | **shipped 2026-05-12** — read (mac/mtu/name/is_running/flags/stats) + mutation (set_mtu, set_mac_address). `up()`/`down()` deferred to Phase-2 multi-interface track. See `docs/refactor/link_api.md`. |
| Address API       | shipped — `pytcp.stack.address` / `AddressApi` (family-agnostic: `add`/`remove`/`replace`/`list_ifaddrs`) |
| Route API         | **shipped** — host-mode FIB + `RouteApi` (`stack/route.py` + `runtime/fib.py`)               |
| Neighbor API      | **shipped** — `NeighborApi` (`stack/neighbor.py`)                                            |
| Introspection API | **shipped** — `LinkApi.stats` covers per-interface counters, and route-table / neighbor-cache / socket-list introspection landed with the daemon CLI (`pytcp ss` / `route` / `neighbor`, reading read-only snapshots of the FIB, neighbor caches, and socket list) |

### IPv4 #5 scope gate (closed)

The IPv4 link-local TX-source scope gate (RFC 3927 §2.6) was
originally deferred per CLAUDE.md "don't add validation for
scenarios that can't happen" — without RFC 3927 autoconfig
the stack never owned a 169.254/16 source. The gate landed
in Phase 0 of the RFC 3927 track; the autoconfig subsystem
landed in Phases 1-5 alongside. The symmetric IPv6 gate (RFC
4007 §6 / RFC 4291 §2.5.6) shipped earlier in commit
`77ee76bc`.

## Recommended next-track sequencing

All Phase-1 items on this punch list have since closed: the
small-win track (A + B + C), the big-feature track (item D —
RFC 3927 link-local autoconfig), item E (multicast group
membership + IGMP), and item F (IPv6 audit-set parity). The
only remaining items are the Phase-2 forwarding-plane entries
below.

## Cross-references

- `docs/rfc/ip4/` — 17 audit records (16 added this session +
  pre-existing RFC 1191 PMTUD)
- `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md` — DHCPv4
  adherence record
- `docs/refactor/rfc6724_source_selection.md` — IPv4 source
  selection track (per memory)
- `docs/refactor/socket_linux_parity_audit.md` — socket-API
  Linux parity (per memory; Phase-1 resume prompt at the doc head)
