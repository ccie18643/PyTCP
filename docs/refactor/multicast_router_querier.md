# Multicast router — querier role + multicast forwarding + FIB extensions — Phase 2 (M5)

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Track        | Phase 2 — router-grade parity (Project North Star)                    |
| Target       | Post-3.0.9 (optional follow-up to the unicast forwarding plane)       |
| Branch       | new `PyTCP_3_1_x` dev branch (own release cycle; does NOT block 3.0.9) |
| Status       | **PLANNED** — not started. Decomposes the parent plan's §8 into M5a–M5h |
| Parent       | [`router_forwarding_plane.md`](router_forwarding_plane.md) §8 (M5)     |
| Precedent    | `router_forwarding_plane.md` (M0–M4 shipped), `sysctl_per_interface.md`, `routing_table_host_mode.md` |

---

## §0. Scope and premise

The 3.0.9 unicast forwarding plane (M0–M4) made PyTCP a **unicast
router**. M5 makes it a **multicast router**: it takes the *querier*
role on each attached link (IGMP for IPv4, MLD for IPv6), maintains a
router-side view of which groups have listeners downstream, and —
optionally — replicates transit multicast datagrams out the
interfaces that have listeners. It also lifts the two `# Phase 2:`
FIB shortcuts (ECMP/multipath, policy routing) that the unicast plane
deliberately left in place.

**The premise that makes this tractable, exactly as with M0–M4: the
foundation already shipped.** PyTCP has the complete IGMPv1/v2/v3 and
MLDv1/v2 **host/member** side — membership reporting, version
fallback, SSM source filters, the report/leave state-change machine.
The Query wire codecs already **parse** (RX). The Timer subsystem is
event-driven and reusable. The `RouterTestCase` 3-interface harness
exists. M5 is the *router-side logic* at seams left as host-mode
stubs — it is not a multicast rewrite.

### Already in the tree (do not rebuild)

| Capability | Where | State |
|---|---|---|
| IGMP wire codecs — Query/Report(v1/v2/v3)/Leave parse + assemble (Query `assemble` is a `NotImplementedError` stub) | `net_proto/protocols/igmp/` (`igmp__message__query.py`, `…__v{1,2,3}_report.py`, `…__v2_leave.py`, `igmp__v3_group_record.py`) | shipped host-side |
| MLD wire codecs — MLDv1 Query/Report/Done + MLDv2 Query/Report/record parse (both Query `assemble`s are `NotImplementedError` stubs) | `net_proto/protocols/icmp6/message/mld1/`, `…/mld2/` | shipped host-side |
| Query float-code decode (RFC 3376 §4.1 / RFC 3810 §5.1) | `igmp__message__query.py::decode_igmp_float_code`, `packet_handler__icmp6__rx.py::_mld2_mrc_to_mrd_ms` | shipped |
| IGMP host state machine (RX Report-on-Query §5.2, TX state-change §5.1, v1/v2 compat §7.2.1) | `packet_handler__igmp__{rx,tx}.py` | shipped |
| MLD host state machine (RX §6 response, TX §6.1 state-change, MLDv1 compat §8) | `packet_handler__icmp6__{rx,tx}.py` (`_mld_*`) | shipped |
| Per-interface **host** group state (`_ip{4,6}_multicast_refs` / `_Ip{4,6}GroupMembership` / `_ip{4,6}_multicast_filters`) guarded by `_lock__multicast` | `runtime/packet_handler/__init__.py` | shipped |
| Join/leave public API (`stack.membership` / `stack.membership6`, Linux `IP_ADD_MEMBERSHIP` parity) | `stack/membership.py`, `stack/membership6.py` | shipped |
| Multicast filter value types (INCLUDE/EXCLUDE + source set, §3.2 / §4.2 merge) | `lib/ip4_multicast_filter.py`, `lib/ip6_multicast_filter.py` | shipped |
| IGMP/MLD host sysctls — `{igmp,mld}.{robustness,unsolicited_report_interval,query_interval,version}` | `igmp__constants.py`, `icmp6/mld__constants.py` | shipped |
| Event-driven Timer subsystem (`call_later` / `call_periodic` / `cancel` / `now_ms`, `TimerHandle`) | `runtime/timer.py` | shipped (`call_periodic` exists but is **unused** today) |
| Router Alert emission path (IGMP: IPv4 Router-Alert option + TTL 1; MLD: IPv6 HBH Router-Alert + Hop Limit 1) | `packet_handler__igmp__tx.py::_emit_igmp`, `packet_handler__icmp6__tx.py::__send_icmp6_mld_via_hbh_ra` | shipped |
| `RouterTestCase` 3-interface harness (if1 LAN-A/boot, if2 LAN-B, if3 upstream+default), `FakeTimer` `_advance(ms=)` | `tests/lib/router_testcase.py`, `tests/lib/fake_timer.py` | shipped M0 |
| FIB with egress dimension (`Route.oif`, `RouteScope`, `RouteProtocol`), destination-keyed longest-prefix `lookup` | `runtime/fib.py`, `stack/route.py` | shipped |

### The genuine gaps this plan closes

1. **No querier at all.** `IgmpRxHandler` and `Icmp6RxHandler` treat
   PyTCP as a host listener: an inbound Query only drives the *host*
   Report-on-Query machine; an inbound Report is counter-only. There
   is no querier election, no General-Query emission, no router-side
   group-membership table.
2. **Query `assemble` is unimplemented** in all three Query codecs
   (`IgmpMessageQuery.assemble`, `Icmp6Mld2MessageQuery` assembly,
   and the MLDv1 Query which shares the stub) — the one deliberate
   wire gap a querier must fill.
3. **No querier-side sysctls** — Query Response Interval, Startup
   Query Interval/Count, Last-Member Query Interval/Count are read
   off the wire on the host side but not configurable for emission.
4. **No multicast forwarding data plane** — a transit multicast
   datagram is not replicated to downstream listeners; there is no
   MFIB, no RPF check.
5. **Two `# Phase 2:` FIB shortcuts** — no ECMP/multipath
   (`fib.py` has no nexthop-group concept), no policy routing
   (`Route` carries no table id; only the Linux `main`/254 table
   exists).
6. Adherence records mark the querier role "n/a (Phase 2)" across
   RFC 2236 §3, RFC 3376 §6/§7/§8, RFC 2710 §3, RFC 3810 §5/§7/§8.

### Cut line

M5 is **optional and post-3.0.9**. It is a self-contained feature
with **zero dependency on the unicast plane** — it can ship on its
own release cycle. Within M5 there are three independent tracks that
can ship (or not) separately:

- **Querier control plane (M5a–M5e)** — the bulk. Makes PyTCP a
  standards-conformant IGMP/MLD querier: election, Queries,
  router-side membership table. **No forwarding required** — a
  querier is useful on its own (it is what maintains the membership
  state a downstream switch's snooping consumes).
- **Multicast forwarding data plane (M5f)** — the heaviest single
  milestone. Replicates transit multicast using the M5a–M5e
  membership table + an RPF check against the unicast FIB. Depends on
  the querier table.
- **FIB extensions (M5g, M5h)** — independent of everything above.
  Small, add-when-a-consumer-appears.

**Recommended minimum cut for a "PyTCP is a multicast router"
claim: M5a–M5e (querier) + M5f (forwarding).** M5g/M5h are orthogonal
and can land whenever a consumer needs them.

---

## §1. The core design decision — router state is NOT host state

The single most important design call, and the one most likely to be
gotten wrong: **the querier's group-membership table is a distinct
data structure from the host's joined-groups state.** They answer
different questions:

| Structure | Question it answers | Owner |
|---|---|---|
| `_ip{4,6}_multicast_refs` (`_Ip{4,6}GroupMembership`) | "Which groups did **we** (this stack, as an application host) join?" | host membership API (`stack.membership`) |
| **NEW** `_igmp_querier_state` / `_mld_querier_state` | "Which groups have **downstream listeners** on this link, learned from inbound Reports?" | the querier RX path (M5b/M5d) |

Conflating them is a latent bug: our own host joins must not appear
in the forwarding membership table unless a Report was actually seen
on the wire, and a downstream listener's group must not cause us to
deliver traffic to our own sockets. Keep them separate; the querier
table is populated **only** from inbound Reports (RFC 3376 §6.4 / RFC
3810 §7.4), never from our host join API.

**Placement.** The router membership table is per-interface state,
so it lives on the `PacketHandler` alongside the host structures,
under the same `_lock__multicast: threading.RLock` (free-threading
north star — every cross-thread structure gets a lock; reuse the
existing multicast lock since the two tables are mutated on the same
RX path). Follow the existing precedent: state on the handler,
behaviour in the `IgmpRxHandler` / `Icmp6RxHandler` /
`IgmpTxHandler` / `Icmp6TxHandler` sub-handlers.

**Router membership entry (sketch, per group, per interface):**

```
_QuerierGroupState (frozen where possible; the timers mutate):
    group:            Ip4Address | Ip6Address
    filter_mode:      INCLUDE | EXCLUDE          # RFC 3376 §6.2.1 group-timer state
    source_timers:    dict[src, deadline_ms]     # per-source timers (SSM)
    group_timer:      TimerHandle | None         # Group Membership Interval
    v1_host_present:  bool (IGMP only)           # §7.3.2 compat
    v2_host_present:  bool (IGMP only)           # §7.3.2 compat
```

The exact shape lands with M5b; it mirrors the RFC 3376 §6.2 "router
group and source timer state" table and the RFC 3810 §7.2 MLDv2
equivalent.

---

## §2. Milestone decomposition

Eight tests-first milestones. M5a is scaffolding; M5b–M5e are the
querier (IGMP first, then the MLD mirror); M5f is the forwarding data
plane; M5g/M5h are the independent FIB extensions.

Each milestone is one-or-more tests-first commits per
`.claude/rules/feature_implementation.md` §2 — the failing test
pins the RFC clause, the implementation flips it green, adherence
records update **in lockstep** (never a separate phase).

| Milestone | Deliverable | Depends on |
|---|---|---|
| **M5a** | Query **assemblers** (net_proto) + querier sysctls + `RouterTestCase` querier scaffolding | — |
| **M5b** | IGMPv3 querier: election, periodic General Query, router membership table from Reports, group timers | M5a |
| **M5c** | IGMP Group-/Group-and-Source-Specific Queries (fast-leave) + IGMPv1/v2 querier interop | M5b |
| **M5d** | MLDv2 querier: election, General Query, membership table (IPv6 mirror of M5b) | M5a |
| **M5e** | MLD Address-/Address-and-Source-Specific Queries + MLDv1 querier interop (mirror of M5c) | M5d |
| **M5f** | Multicast forwarding data plane — MFIB + RPF + replication | M5b, M5d, (M5g optional) |
| **M5g** | FIB ECMP / multipath (nexthop groups) | — (independent) |
| **M5h** | FIB policy routing / multiple tables | — (independent) |

---

## §3. M5a — Query assemblers + querier sysctls + harness scaffolding

The prerequisite wire + config + test surface. No querier behaviour
yet — this milestone makes the *pieces* the querier needs exist and
be tested in isolation.

### 3.1 net_proto — fill the Query `assemble` stubs (tests-first)

Three codecs currently raise `NotImplementedError` on assembly:

- `IgmpMessageQuery.assemble` (`igmp__message__query.py:304`) — build
  the RFC 3376 §4.1 v3 Query (and the 8-octet v2/v1 short form when
  `qrv`/`qqic`/sources are absent). Encode Max-Resp-Code via the
  inverse of `decode_igmp_float_code` (a new
  `encode_igmp_float_code`, RFC 3376 §4.1.1).
- `Icmp6Mld2MessageQuery` assembly
  (`icmp6__mld2__message__query.py`) — RFC 3810 §5.1 MLDv2 Query
  (28-octet base + source vector). MRC float-encode (inverse of
  `_mld2_mrc_to_mrd_ms`).
- `Icmp6Mld1MessageQuery.assemble` — RFC 2710 §3.1 fixed 24-octet
  MLDv1 Query (needed only for MLDv1-compat querier output in M5e;
  can slip to M5e, but the codec test belongs here).

Per `.claude/rules/net_proto.md`: tests-first against the wire
format, full assembler-operation matrix
(`test__igmp__message__query__assembler__operation.py`,
`test__icmp6__mld2__message__query__assembler__operation.py`), round-
trip parse↔assemble, byte-frame annotations per
`unit_testing.md` §5. The float-code encoders get their own unit
tests pinning the RFC 3376 §4.1.1 / RFC 3810 §5.1.3 mantissa/exp
boundary values.

**Note the invariant flip:** the module/class docstrings and the
adherence records currently say "RX-only; querier emission is Phase-2
router work." Those lines flip in this milestone (the codec is no
longer RX-only). Update `rfc3376__igmp_v3/adherence.md` §4.1,
`rfc3810__mld2/adherence.md` §4, `rfc2710__mld_v1/adherence.md` §3 in
lockstep.

### 3.2 Querier sysctls (per-interface)

The querier role is per-interface, so every knob is a per-interface
sysctl (`.claude/rules/pytcp.md` §2, `sysctl_per_interface.md`
pattern — `dict[str, T]` + `interface_scope`, read via
`sysctl_iface.get_for_iface`). Existing host knobs
(`{igmp,mld}.robustness`, `.query_interval`, `.version`) are
**reused**; the querier adds the emission-side intervals the host
side only ever read off the wire:

| New sysctl key | Default | RFC |
|---|---|---|
| `igmp.query_response_interval` | 10 000 ms (100 in ¹⁄₁₀ s) | RFC 3376 §8.3 |
| `igmp.startup_query_interval` | `query_interval / 4` = 31 250 ms | RFC 3376 §8.6 |
| `igmp.startup_query_count` | `robustness` = 2 | RFC 3376 §8.7 |
| `igmp.last_member_query_interval` | 1 000 ms | RFC 3376 §8.8 |
| `igmp.last_member_query_count` | `robustness` = 2 | RFC 3376 §8.9 |
| `mld.query_response_interval` | 10 000 ms | RFC 3810 §9.3 |
| `mld.startup_query_interval` | `query_interval / 4` | RFC 3810 §9.6 |
| `mld.startup_query_count` | `robustness` | RFC 3810 §9.7 |
| `mld.last_listener_query_interval` | 1 000 ms | RFC 3810 §9.8 |
| `mld.last_listener_query_count` | `robustness` | RFC 3810 §9.9 |

Plus one **enable gate** per family (see §3.3). Each knob lands via
the `sysctl_knob` skill workflow: register at the `*__constants.py`,
validator, tests-first, adherence Reference, §7.2 audit.

### 3.3 The enable gate — when does the querier run?

**Design decision (resolve in M5a, implement in M5b).** A querier
should only run on an interface that is acting as a multicast router.
Options:

- **(A) Ride `ip4.forwarding` / `ip6.forwarding`** (the per-interface
  unicast-forwarding knob from M1). Simple, and "I am forwarding on
  this link" ≈ "I am a multicast router on this link." But Linux
  gates multicast forwarding on a **separate** `mc_forwarding`
  sysctl set by a multicast routing daemon (mrouted/pimd) via
  `MRT_INIT`, not on `ip_forward`.
- **(B) New per-interface `ip4.mc_forwarding` / `ip6.mc_forwarding`
  knob** (default off), matching Linux. The querier activates when
  `mc_forwarding` is on for the interface.

**Recommendation: (B)**, for Linux parity and because the querier is
independently useful without unicast forwarding. Mark the decision
with a `# Phase 2:` note; default off means zero behaviour change for
existing host deployments (a querier that never activates is a host).
This mirrors the M1 "read-time OR of master + per-iface" precedent.

### 3.4 `RouterTestCase` querier scaffolding

The harness has no multicast-membership seeding and no querier
helpers today. Add (mirroring the M0–M4 helper style):

- `_enable_querier(*, family)` — set `ip{4,6}.mc_forwarding` on all
  test interfaces.
- `_drive_report(*, ingress, group, sources=…, record_type=…,
  version=…)` — build + inject an inbound IGMP/MLD Report from a
  downstream host, so tests can populate the router table.
- `_drive_query(*, ingress, src_ip, …)` — inject a **competing**
  querier's Query, for election tests (lower IP must win / lose).
- `_assert_query_emitted(emitted, *, egress, kind, group=…,
  sources=…, max_resp=…)` — parse a TX frame back into the Query
  probe and fluent-assert (per `integration_testing.md` §7.3 — parse
  to a typed probe, never hand-compare bytes).
- `_assert_membership(*, iface, group, present=True, mode=…,
  sources=…)` — introspect the router table (via a read-only
  snapshot accessor, §4).
- Stat helpers extend the existing `_assert_iface_packet_stats_rx`.

The `FakeTimer` `_advance(ms=)` (inherited from `IcmpTestCase`) is
the querier's whole test lever — General Query interval, response
timeouts, Group Membership Interval, Other Querier Present timeout
all fire deterministically under `_advance`.

---

## §4. M5b — IGMPv3 querier core

The heart of the querier. Election + General Query timer + the
router-side membership table populated from Reports.

### 4.1 Querier election (RFC 3376 §6.6.2, RFC 2236 §3)

Per-interface state machine: **Querier** ↔ **Non-Querier**.

- On enable (§3.3), interface starts in **Querier** state, sends
  `startup_query_count` General Queries spaced `startup_query_interval`
  apart (§8.6/§8.7).
- On receiving a Query from a source IP **lower** than our interface
  address on that link → become **Non-Querier**, start the **Other
  Querier Present** timer (`robustness × query_interval +
  query_response_interval / 2`, §8.5).
- Other Querier Present timer expires → become **Querier** again.
- Querier state: periodic General Query every `query_interval` (§8.2)
  to `224.0.0.1` / TTL 1 / Router-Alert (the existing `_emit_igmp`
  path already sets TTL 1 + Router-Alert; the destination changes to
  all-systems).

Election state is per-interface on the handler
(`_igmp_querier__is_querier: bool`,
`_igmp_querier__other_present_handle: TimerHandle | None`,
`_igmp_querier__general_query_handle: TimerHandle | None`).

### 4.2 General Query emission

New `IgmpTxHandler` method `_send_igmp_general_query()` — builds an
`IgmpMessageQuery` (v3 form, `group_address = 0.0.0.0`, `qrv =
robustness`, `qqic` encoding `query_interval`, `max_resp_code`
encoding `query_response_interval`) and emits via the existing
`_emit_igmp(message, ip4__dst=IGMP__ALL_SYSTEMS)`. Uses the M5a
assembler. Self-re-arming via `stack.timer.call_later` (the existing
host-side pattern — `call_periodic` is available but election
transitions retime the query, so self-re-arm is cleaner and matches
`_arm_state_change_retransmit`).

### 4.3 Router membership table from Reports (RFC 3376 §6.4)

Replace the counter-only `IgmpRxHandler.__phrx_igmp__report` (which
today just counts + does host-side v1/v2 suppression) with the
querier Report-processing state machine when the interface is a
querier:

- For each group record in a V3 Report, apply the §6.4 "Action on
  reception of Current-State / Filter-Mode-Change / Source-List-Change
  Record" table: update the group's filter-mode + per-source timers,
  (re)arm the Group Membership Interval group timer.
- Group timer expiry (RFC 3376 §6.5) → group removed from the table
  (no more listeners); if forwarding is active (M5f) this prunes the
  oif.
- The state transitions are the RFC 3376 §6.4 tables verbatim — this
  is the milestone's bulk. One integration test per table row.

**Host-side interaction:** when the interface is a querier, PyTCP
still may itself be a host member of a group (via `stack.membership`).
Its own membership must NOT be learned from the wire — but a General
Query it emits will (correctly) draw a Report from its *own* host
state machine (loopback is not modelled, so this is a non-issue in
the harness; document it). Keep the two tables separate per §1.

### 4.4 Read-only introspection (Phase-3 boundary)

Per the CLAUDE.md Phase-3 rule, router membership state is
observable only through a read-only, copy-by-value snapshot — never a
live reference. Add to the introspection surface (alongside
`stack.membership.list_memberships`) a
`stack.mroute`-style querier snapshot:
`list_querier_memberships(*, ifindex) -> tuple[QuerierGroupSnapshot, …]`.
This is the `ip mroute` / `/proc/net/igmp` equivalent. Immutable
snapshot, consistent with the M0–M4 introspection rule.

### 4.5 Stats + adherence

- New `PacketStatsTx` counters: `igmp__general_query__send`,
  `igmp__group_query__send` (M5c), `igmp__group_source_query__send`
  (M5c). New `PacketStatsRx`: `igmp__report__querier_learn`,
  `igmp__report__querier_prune`, `igmp__query__election_lost`.
  Update the field-count pins in `test__lib__packet_stats.py`
  (the M0–M4 lesson — the pins break on every counter addition).
- Adherence flips: `rfc2236__igmp_v2/adherence.md` §3 (querier
  behaviour) and `rfc3376__igmp_v3/adherence.md` §6 (router state) /
  §7 (query timers) / §8 (constants now emission-side) move from
  "out of scope (Phase 2)" to met, in lockstep.

---

## §5. M5c — IGMP specific queries + version interop

### 5.1 Group-Specific + Group-and-Source-Specific Queries

The "fast leave" mechanism (RFC 3376 §6.4.2). When a Report reduces
interest in a group (a `BLOCK_OLD_SOURCES` / `CHANGE_TO_INCLUDE`
record, or a v2 Leave in v2-compat mode), the querier sends
`last_member_query_count` Group-Specific (or Group-and-Source-
Specific) Queries spaced `last_member_query_interval` apart (§8.8/§8.9),
lowering the group/source timers so a still-interested listener
re-asserts before the group is pruned.

New `IgmpTxHandler._send_igmp_group_specific_query(group)` and
`_send_igmp_group_source_query(group, sources)` — Query with a
non-zero `group_address` (and source vector), the `s_flag`
(suppress-router-side-processing) semantics per §4.1.5, dst = the
group address.

### 5.2 IGMPv1 / IGMPv2 querier interop (RFC 3376 §7.3)

A querier must interoperate with older-version *hosts* and detect
older-version *queriers* on the link:

- **Older Version Querier Present** (§7.3.1) — a v1/v2 Query seen on
  the link forces the querier into v1/v2 compat for the Older Version
  Querier Present timeout. The querier then must emit v1/v2-format
  Queries (no source vector, v2 Max-Resp-Time semantics).
- **Older Version Host Present** (§7.3.2) — a v1/v2 Report seen for a
  group pins that group's compat mode; the querier suppresses source-
  specific behaviour for it and uses the older Group Membership
  Interval. The `_QuerierGroupState.v{1,2}_host_present` flags from §1.

Much of the host-side compat plumbing (`_igmp_host_compatibility_mode`,
the v1/v2 querier-present timers) is analogous and can be mirrored on
the querier side — but it is **separate state** (querier compat ≠ host
compat). Adherence: `rfc2236__igmp_v2/adherence.md` §3 fully met.

---

## §6. M5d — MLDv2 querier core (IPv6 mirror of M5b)

The IPv6 parallel. MLD is ICMPv6-based, so the querier lives in the
`Icmp6RxHandler` / `Icmp6TxHandler` sub-handlers, not a separate
protocol handler. The structure is a near-exact mirror of M5b with
the MLD RFC citations:

- **Election** — RFC 3810 §7.6.2 (lower link-local source wins),
  Other Querier Present timer §9.5. General Query to `ff02::1`, Hop
  Limit 1, HBH Router-Alert (the existing
  `__send_icmp6_mld_via_hbh_ra` path). Source of the Query is the
  interface **link-local** address (RFC 3810 §5.1.14) — note the M3
  wrinkle: `_phtx_ip6`'s RFC 4007 §6 scope check may need the same
  `_phtx_ethernet` bypass the ND-redirect used, or a relaxation for
  MLD (link-local source to a link-scope multicast dst is legal —
  ideally relax the scope check for link-local-src → link-local-scope-
  dst rather than bypass).
- **General Query emission** — new
  `Icmp6TxHandler._send_mld_general_query()` using the M5a
  `Icmp6Mld2MessageQuery` assembler.
- **Membership table from Reports** — replace the counter-only
  `__phrx_icmp6__mld2_report` (`packet_handler__icmp6__rx.py:1146`,
  which carries the explicit `# Phase 2: MLDv2 querier role goes
  here` marker) with the RFC 3810 §7.4 Action-on-reception state
  machine. Group timer §7.2, expiry prune §7.2.3.
- **Introspection** — `list_querier_memberships6(...)`.
- **Stats** — `icmp6__mld_general_query__send`,
  `icmp6__mld2_report__querier_learn/prune`,
  `icmp6__mld_query__election_lost`; field-count pins updated.
- **Adherence** — `rfc3810__mld2/adherence.md` §5/§7/§8 (the big
  "§7/§8 Querier-side Timers and Action on Reception" section at
  L274–298 and the "no test surface" note at L445–448) flip to met.

The MLDv2 Report is aggregated (one message carries many multicast
address records) — the §7.4 processing walks each record, same shape
as the IGMPv3 group-record walk.

---

## §7. M5e — MLD specific queries + MLDv1 interop (mirror of M5c)

- **Multicast-Address-Specific + Address-and-Source-Specific
  Queries** — RFC 3810 §7.6.3 fast-leave, `last_listener_query_*`
  timing. `Icmp6TxHandler._send_mld_address_query(group)` /
  `_send_mld_address_source_query(group, sources)`.
- **MLDv1 querier interop** — RFC 3810 §8. Older Version Querier
  Present (§8.3.1) forces MLDv1-format Query emission (the fixed
  24-octet form — needs the `Icmp6Mld1MessageQuery.assemble` from
  M5a §3.1); Older Version Host Present (§8.3.2) pins a group to
  MLDv1 mode. Mirror of the IGMP §7.3 interop, separate querier
  compat state. Adherence: `rfc2710__mld_v1/adherence.md` §3 querier
  role met.

---

## §8. M5f — multicast forwarding data plane

The heaviest single milestone, and the only one that touches the
**data** path rather than the control path. Deliverable: a transit
multicast datagram that arrives on the RPF interface is replicated
out every interface that has a downstream listener for the group.

This is a genuine new plane, structurally parallel to the M1 unicast
forward branch but with replication instead of a single next hop.
**It should get its own sub-plan doc** (`multicast_forwarding.md`)
when M5f is greenlit — the sketch here is the scoping, not the full
decomposition.

### 8.1 MFIB — multicast forwarding information base

A new per-`(source, group)` (or `(*, group)`) forwarding table:

```
MulticastRoute:
    source:    Ip4Address | Ip6Address | None   # None = (*, G)
    group:     Ip4Address | Ip6Address
    iif:       int                              # expected RPF ingress ifindex
    oifs:      frozenset[int]                   # egress interfaces with listeners
```

Populated from the querier membership tables (M5b/M5d): an interface
is in `oifs` for a group iff its querier table has a live membership
entry for that group. The `iif` is the RPF interface (§8.2). Lives in
`runtime/mfib.py` (new), one per family, `stack.ip4_mfib` /
`stack.ip6_mfib`, guarded by its own lock (free-threading north star).

### 8.2 RPF check (Reverse Path Forwarding)

A transit multicast datagram is accepted for forwarding **only** if
it arrived on the interface the unicast FIB would use to *reach its
source* (RPF). Reuse the existing unicast `lookup`:
`stack.ip4_fib.lookup(packet_rx.ip4.src, connected=…)` → the
route's `oif` must equal the ingress ifindex, else drop
(`ip4__mforward_rpf__drop`). This is the standard loop-prevention
check and is why multicast forwarding depends on the (already
shipped) unicast FIB.

### 8.3 Replication + the forward-or-deliver seam

Extend `_forward_or_deliver_ip{4,6}` (the M1 seam): a datagram with a
multicast destination that is not one of our own joined groups, on a
`mc_forwarding` interface, goes to a new
`Ip{4,6}MulticastForwardHandler.try_mforward_ip{4,6}`:

1. RPF check (§8.2) → drop on fail.
2. MFIB lookup `(src, dst)` → `oifs`. Empty → drop
   (`mforward_no_listeners__drop`).
3. For each `oif != iif`: decrement TTL/Hop Limit, recompute IPv4
   cksum, re-emit the **byte-identical** payload out that interface
   (the M1 `RawAssembler(ether_type=)` + `EthernetAssembler` →
   egress `_phtx_ethernet` pattern, dst = the group's L2 multicast
   MAC). One `mforward` stat bump per replica.
4. TTL/Hop scoping — multicast has tighter TTL-scope semantics
   (admin-scoped boundaries, RFC 2365); a datagram with TTL 1 is not
   forwarded. Respect the scope.

### 8.4 What M5f explicitly does NOT do

- **No PIM / DVMRP / any multicast routing protocol** — those are
  userspace daemons, out of scope per CLAUDE.md non-goals. The MFIB
  is populated purely from *local* querier state (directly-connected
  listeners), i.e. PyTCP is a "last-hop" multicast router only. A
  full mrouter needs a routing protocol to learn non-local (S,G)
  state; that stays out.
- **No `MRT_*` socket API** (the Linux multicast-routing setsockopt
  surface an mrouted uses) — the MFIB is populated internally, not by
  an external daemon. If a consumer ever needs the daemon API, it is a
  separate Phase-3 socket-surface item.

Adherence: RFC 1812 §5.2.4 multicast-forwarding clauses (currently
"n/a — host does not forward multicast") flip to met for the
last-hop case.

---

## §9. M5g — FIB ECMP / multipath (independent)

Lifts the `fib.py` shortcut: today one route = one next hop. ECMP =
multiple next hops per prefix (a nexthop group), with per-flow hashing
so a flow pins to one path.

- **Model** — `Route.gateway: A | None` becomes (or is joined by) a
  `nexthops: tuple[NextHop, …]` where `NextHop` carries
  `(gateway, oif, weight)`. The `fib.py:98` `# Phase 2:` note and the
  RouteTable docstring both already promise `lookup`'s signature is
  unchanged — honour that: `lookup` still returns one `Route`, but a
  multipath route resolves its member at lookup time via a flow hash.
- **Flow hash** — L3 (src,dst) or L3/L4 (src,dst,proto,sport,dport)
  hash mod `sum(weights)`, matching Linux `fib_multipath_hash_policy`.
  A new `fib.multipath_hash_policy` sysctl (0=L3, 1=L3/L4).
- **Consumer** — none today. This is add-when-needed; the milestone
  can be spec'd but parked until a multipath consumer (a test, an
  example, or a real dual-uplink topology) appears. Tests-first would
  use `RouterTestCase` with two upstream interfaces and assert flow
  pinning + even split across many flows.

Independent of the querier — can land any time.

---

## §10. M5h — FIB policy routing / multiple tables (independent)

Lifts the second `fib.py` shortcut: only the Linux `main`/254 table
exists.

- **Model** — `Route` gains `table: int = 254` (the `# Phase 2: table
  id` note at `fib.py:98` names this exactly). A rule table (`ip
  rule` equivalent) selects which route table a lookup consults based
  on match criteria (src prefix, fwmark, iif).
- **Consumer** — none today; PyTCP has no fwmark/netfilter surface
  (explicit non-goal), so the realistic policy-routing selectors are
  src-prefix and iif. Genuinely add-when-a-consumer-appears; likely
  the *last* thing to land, if ever.

Independent of everything. Spec'd here for completeness; do not build
speculatively.

---

## §11. Cross-cutting concerns

### 11.1 Free-threading

Every new cross-thread structure gets its own lock or reuses an
existing one under a documented invariant (north star: no "atomic
under the GIL"). The querier tables reuse `_lock__multicast` (same RX
path as host membership); the MFIB gets its own lock; ECMP nexthop
groups are read-mostly (copy-on-write under the FIB lock, matching the
existing `RouteTable._routes` snapshot pattern).

### 11.2 Timer test-determinism

Every querier timer (General Query interval, Other Querier Present,
Group Membership Interval, Last-Member Query) is driven by
`stack.timer.call_later` and therefore fires deterministically under
the harness `FakeTimer` `_advance(ms=)`. No wall-clock, no
`time.sleep` — the `unit_testing.md` §10a isolation rule. This is the
single biggest reason the querier is testable at all.

### 11.3 Stat-field pins

Every milestone that adds a `PacketStats{Rx,Tx}` counter updates the
field-count assertions in `test__lib__packet_stats.py` **in the same
commit** — the recurring M0–M4 breakage. Current baseline: RX=213,
TX=123.

### 11.4 Adherence-in-lockstep

Touching an RFC-governed path updates the relevant
`docs/rfc/**/adherence.md` in the same commit (never a separate
phase). The records to flip:

| Record | Sections flipping | Milestone |
|---|---|---|
| `ip4/rfc2236__igmp_v2/adherence.md` | §3 querier behaviour | M5b, M5c |
| `ip4/rfc3376__igmp_v3/adherence.md` | §4.1 (assemble), §6 router state, §7 timers, §8 constants | M5a, M5b, M5c |
| `ip4/rfc1112__ip4_multicasting/adherence.md` | querier-version fallback (router side) | M5c |
| `icmp6/rfc2710__mld_v1/adherence.md` | §3 querier role | M5a, M5e |
| `icmp6/rfc3810__mld2/adherence.md` | §4 (assemble), §5 state machine, §7 timers, §8 action-on-reception | M5a, M5d, M5e |
| `ip4/rfc1812__router_requirements/adherence.md` | §5.2.4 multicast forwarding (last-hop) | M5f |

Use the `rfc_adherence_audit` skill for any record that changes
adherence status substantially, including the test-audit section
(memory: RFC records audit the *tests* that lock each requirement,
not just the impl).

---

## §12. Sequencing summary

| Milestone | Deliverable | Blocks | Independent? |
|---|---|---|---|
| **M5a** | Query assemblers + querier sysctls + harness scaffolding | M5b–M5e | — |
| **M5b** | IGMPv3 querier core (election, General Query, membership table) | M5c, M5f | — |
| **M5c** | IGMP specific queries + v1/v2 interop | — | — |
| **M5d** | MLDv2 querier core (IPv6 mirror of M5b) | M5e, M5f | — |
| **M5e** | MLD specific queries + MLDv1 interop | — | — |
| **M5f** | Multicast forwarding (MFIB + RPF + replication) | — | needs M5b+M5d |
| **M5g** | FIB ECMP / multipath | — | ✅ fully independent |
| **M5h** | FIB policy routing / multiple tables | — | ✅ fully independent |

**Recommended cut for a "multicast router" release: M5a → M5e
(querier control plane) as a first release, then M5f (forwarding) as
a second.** M5g/M5h land independently whenever a consumer appears —
do not build them speculatively.

**Smallest useful increment:** M5a + M5b + M5d = a standards-
conformant IGMPv3/MLDv2 querier (General Queries + membership table)
without the older-version interop or forwarding. Genuinely shippable
and independently testable.

---

## §13. Deferred with rationale (NOT in M5)

- **Multicast routing protocols (PIM-SM/DM, DVMRP, IGMP proxy)** —
  userspace routing protocols, explicit CLAUDE.md non-goal. The MFIB
  is last-hop only (directly-connected listeners).
- **`MRT_INIT` / `MRT_ADD_MFC` multicast-routing socket API** — the
  Linux kernel↔mrouted control surface. No PyTCP consumer; would be a
  Phase-3 socket-surface item if an external multicast daemon ever
  needs to drive PyTCP's MFIB.
- **RGMP / IGMP snooping (switch role)** — PyTCP is a router/host, not
  a bridge; L2 snooping is out.
- **Bidirectional-PIM, MSDP, embedded-RP** — inter-domain multicast,
  far out of host/router-parity scope.
