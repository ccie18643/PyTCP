# Router forwarding plane — Phase 2 (PyTCP 3.0.9)

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Track        | Phase 2 — router-grade parity (Project North Star)                    |
| Target       | PyTCP 3.0.9 (unicast forwarding plane: M0–M4)                         |
| Branch       | `PyTCP_3_0_9`                                                         |
| Status       | **Not started** — plan only                                          |
| Follow-up    | M5 (multicast router / querier) + FIB extensions — optional, post-3.0.9 |
| Precedent    | `routing_table_host_mode.md`, `packet_handler_rewrite_plan.md`, `sysctl_per_interface.md` |

---

## §0. Scope and premise

PyTCP 3.0.9 turns the stack from a multi-homed **host** into a
**router**: a datagram that arrives on one interface and is not
addressed to us is forwarded toward its next hop out the correct
egress interface, with every ICMP error a forwarder is obligated to
originate.

**The premise that makes this tractable: the foundation already
shipped.** This is *not* a multi-interface rewrite — that landed in
3.0.6. What is missing is the forwarding *logic* at seams that were
deliberately left as host-mode stubs.

### Already in the tree (do not rebuild)

| Capability | Where | State |
|---|---|---|
| Per-interface handlers (own MAC / MTU / rings / ARP+ND caches / ifaddr lists / IP-id / frag tables) | `runtime/interface_table.py`, `runtime/packet_handler/` | shipped 3.0.6 |
| Runtime `add_interface` / `remove_interface` (RTM_NEWLINK/DELLINK) | `stack/__init__.py`, `stack/lifecycle.py` | shipped 3.0.6 |
| FIB with egress dimension — `Route.oif`, `RouteScope`, `RouteProtocol` (incl. `REDIRECT = 1  # Phase 2`) | `runtime/fib.py` | shipped 3.0.5 |
| Destination-keyed egress selection | `stack._egress_handler_via_fib(dst)`, `egress_packet_handler(dst)`, `connected_ip{4,6}_networks()` | shipped 3.0.6 |
| Forward-or-deliver seam (host-mode stub) | `_forward_or_deliver_ip4` / `_forward_or_deliver_ip6` | shipped 3.0.6 |
| Per-interface sysctl namespace (`net.<family>.conf.<iface>.<knob>`) | `stack/sysctl.py`, `lib/sysctl_iface.py` | shipped 3.0.6 |
| Multi-interface test affordance (`_add_interface` → `AddedInterface` with per-interface `drive_rx` / `frames_tx`) | `tests/lib/network_testcase.py` | shipped 3.0.6 |
| Transit-ICMP **codecs** (Time Exceeded, Dest-Unreachable incl. Frag-Needed, ICMPv6 Packet Too Big) | `net_proto/protocols/icmp{4,6}/` | shipped |
| ICMP-error emission template (embed offending datagram) | `__phrx_ip4__emit_parameter_problem`, `__phrx_ip4__emit_protocol_unreachable` | shipped |
| ICMPv6 Redirect codec + RX accept (host side) | `net_proto/…/icmp6__nd__message__redirect.py`, `packet_handler__icmp6__rx.py` | shipped |

### The genuine gaps this plan closes

1. No forward branch — `_forward_or_deliver_ip{4,6}` always drops a
   non-local datagram (`ip{4,6}__dst_unknown__drop`, "host does not
   forward").
2. No `ip_forward` / per-interface `forwarding` policy knob.
3. No TTL/Hop-Limit decrement + **transit** ICMP Time Exceeded.
4. No ICMP Destination Unreachable for a forwarded packet with no
   route / no reachable next hop.
5. No **transit** PMTU (ICMPv4 Fragmentation-Needed / ICMPv6 Packet
   Too Big) and no fragmentation of forwarded IPv4 packets.
6. No ICMP Redirect **generation** (and no ICMPv4 Redirect codec at
   all — `Icmp4Type.REDIRECT = 5` and the message class do not exist).
7. Two `rfc1812__router_requirements/adherence.md` records mark
   nearly every forwarding clause "n/a (Phase 2)".

### Cut line

**3.0.9 = M0–M4 (the unicast forwarding plane).** A complete "PyTCP
is a router" story: it forwards IPv4/IPv6 unicast, decrements the
lifetime field, and originates every ICMP error a forwarder must,
with the RFC 1812 audit closed.

**M5 (multicast router / IGMP+MLD querier role) and the FIB
extensions (ECMP/multipath, policy routing / multiple tables) are an
optional follow-up, deferred past 3.0.9** — see §8. Neither blocks
the 3.0.9 story; the querier is the most separable piece and the FIB
extensions are already `# Phase 2:` tagged in `fib.py`.

---

## §1. Design invariants

Carried from `CLAUDE.md` (Project North Star + conformance
precedence) and the shipped-code memories:

1. **RFC text first, Linux as tiebreaker.** Governing RFCs: 1812
   (router requirements), 1122 (host requirements — the forwarder
   still hosts), 792 / 4443 (ICMP), 791 / 8200 (IP), 1191 / 8201
   (PMTUD). Where a SHOULD/MAY menu exists, follow Linux
   (`net/ipv4/ip_forward.c`, `net/ipv6/ip6_output.c::ip6_forward`,
   `net/ipv4/route.c`, the `net.ipv4.conf.*` / `net.ipv6.conf.*`
   sysctls) and cite the file/sysctl in the commit body.
2. **Free-threading (no-GIL).** The forward path runs on RX threads
   concurrently with the Route API mutating the FIB and the Timer
   aging neighbor caches. Reuse the existing tiny-locked-surface
   structures (`RouteTable._lock`, `InterfaceTable`, the per-interface
   caches); introduce no "atomic under the GIL" shortcut. Any new
   shared structure gets its own lock. (`project_free_threading_north_star`.)
3. **Phase-3 boundary.** Every new operator knob lands on a sanctioned
   surface — a **sysctl** (`ip_forward`, `forwarding`, `send_redirects`,
   `accept_redirects`) via the per-interface framework, never a raw
   attribute. Introspection stays read-only copy-by-value.
4. **Do not foreclose the FIB extensions.** Keep the forward path
   consuming `RouteTable.lookup(dst, connected=…) → Route` unchanged
   so ECMP next-hop groups and policy tables slot in later behind the
   same entry point. Mark any single-next-hop shortcut `# Phase 2:`.
5. **Tests-first, integration-biased.** Forwarding is wire-level RX→TX
   behavior across interfaces; unit tests alone miss it. Every
   milestone opens with failing integration tests on the M0 harness.
6. **Adherence in lockstep.** Touching an RFC-1812 clause updates the
   relevant `adherence.md` in the *same* commit
   (`feedback_audit_in_lockstep_with_code`).

---

## §2. M0 — plan doc + `RouterTestCase` harness

**Goal:** the enabling test surface every later milestone asserts
against. No production behavior change.

### 2.1 This document

Committed as `docs/refactor/router_forwarding_plane.md`.

### 2.2 `RouterTestCase(NetworkTestCase)`

New file `packages/pytcp/pytcp/tests/lib/router_testcase.py`. Builds
on the existing `_add_interface` affordance (already returns an
`AddedInterface` with its own mocked TX ring, per-interface
`frames_tx`, ARP/ND tables, and a `drive_rx`).

**Canonical 3-interface "router-under-test" topology** (the smallest
that tests egress *selection*, not egress *inevitability* — with two
interfaces "forward out the other one" is unconditional and the FIB
longest-prefix match is never exercised as a choice):

```
        if-1  10.0.1.0/24            if-2  10.0.2.0/24
  ┌───────────────────────┐   ┌───────────────────────┐
  │ ROUTER (PyTCP)                                     │
  │  if-1 .1   if-2 .1   if-3 .1                       │
  └───────────────────────────────────┬───────────────┘
                              if-3  203.0.113.0/24 (upstream / default)
   HOST_A 10.0.1.91   HOST_B 10.0.2.92   UPSTREAM_GW 203.0.113.1
   (v6 parallels: 2001:db8:0:1::/64, ::2::/64, ::3::/64, default via if-3)
```

- if-1 = boot interface (the `NetworkTestCase` handler), re-addressed
  to the router role; if-2, if-3 via `_add_interface`.
- Static routes installed into `stack.ip4_fib` / `ip6_fib`: a default
  via UPSTREAM_GW on if-3; connected routes are synthesized from the
  interface ifaddrs by `lookup`.
- Per-interface ARP/ND tables seeded so next-hop resolution succeeds
  for the "happy path" hosts and misses for the "unreachable" host
  (mirroring the HOST_A-resolves / HOST_B-misses convention).
- `setUp` enables forwarding (`ip4.ip_forward=1`, `ip6.all.forwarding=1`)
  via `sysctl` override, restored in `tearDown`.

**Parameterizable, not hardcoded.** `RouterTestCase` exposes the
canonical 3-interface topology as the default, but the harness accepts
a smaller/larger interface set per test (redirect tests want ingress
== egress with 1–2 interfaces; RPF / multicast-replication in M5 wants
≥3).

### 2.3 Assertion helpers

- `_drive_forward(*, ingress: AddedInterface, frame: bytes) -> list[bytes]`
  — feed `frame` into the ingress interface, return frames emitted on
  **all** interfaces (so a test can assert the frame left the *right*
  egress and nowhere else).
- `_assert_forwarded_ip4(*, egress, src, dst, ttl_out, next_hop_mac, …)`
  — decode the egress frame, assert: Ethernet dst == next-hop MAC on
  the egress interface, IPv4 src/dst preserved, `ttl_out == ttl_in - 1`,
  header checksum valid, payload byte-identical. IPv6 parallel asserts
  Hop-Limit decrement.
- `_assert_icmp_error(*, to, type, code, embeds: bytes)` — the ingress
  interface emitted an ICMP error back to the source embedding the
  offending datagram's leading bytes.
- `_assert_no_forward()` — nothing was emitted on any egress interface
  (drop path).

### 2.4 Stat-counter fields (added here, exercised later)

Add to `PacketStatsRx` (`lib/packet_stats.py`) so M1+ assertions have
targets and the strict `_assert_packet_stats_rx(exact=True)` contract
holds:

```
ip4__forward                       ip6__forward
ip4__forward_disabled__drop        ip6__forward_disabled__drop
ip4__forward_no_route__drop        ip6__forward_no_route__drop
ip4__forward_ttl_exceeded__drop    ip6__forward_hop_exceeded__drop
ip4__forward_no_neighbor__drop     ip6__forward_no_neighbor__drop
ip4__forward_too_big__drop         ip6__forward_too_big__drop
ip4__forward_martian_dst__drop     ip6__forward_scope__drop
```

**Commit:** `test(router): RouterTestCase + 3-interface forwarding harness`.

---

## §3. M1 — core unicast forwarding

**Goal:** the minimum viable forwarder that never silently
blackholes: forward what fits, decrement lifetime, and emit Time
Exceeded (TTL=0) / Destination Unreachable (no route). These two ICMP
errors are inseparable from the decrement/lookup, so they land here,
not in M2.

### 3.1 The `ip_forward` / `forwarding` knob

Via the `sysctl_knob` skill + the per-interface framework:

| Key | Default | Linux parity |
|---|---|---|
| `ip4.ip_forward` (global master) | `0` (off) | `net.ipv4.ip_forward` |
| `ip4.forwarding` (per-interface) | follows master | `net.ipv4.conf.<iface>.forwarding` |
| `ip6.all.forwarding` (global master) | `0` (off) | `net.ipv6.conf.all.forwarding` |
| `ip6.forwarding` (per-interface) | follows master | `net.ipv6.conf.<iface>.forwarding` |

**Semantics (Linux-accurate):** a datagram is a forwarding candidate
iff forwarding is enabled on the **ingress** interface. Setting the
global master to 1 flips every interface (Linux `ip_forward=1` writes
`conf.all` + each `conf.<if>`). The per-interface check is
authoritative; the master is the convenience toggle. Default off — a
stack with no config keeps exact host behavior (the drop path below is
byte-for-byte the current stub).

### 3.2 Forward branch — `_forward_or_deliver_ip4`

When `self._if._accepts_local_dst_ip4(dst)` is False, instead of the
unconditional drop, run (new module
`packet_handler__ip4__forward.py`, the landing spot the RFC 1812
adherence doc already names):

```
1. forwarding enabled on ingress iface?          no  → drop, ip4__forward_disabled__drop
2. dst is martian/loopback/link-local/own-mcast? yes → drop, ip4__forward_martian_dst__drop
3. route = ip4_fib.lookup(dst, connected=…)       None→ ICMP Dest-Unreachable (net, code 0)
                                                        back to src; ip4__forward_no_route__drop
4. ttl_in = packet_rx.ip4.ttl; if ttl_in <= 1    → ICMP Time-Exceeded (TTL, code 0)
                                                        back to src; ip4__forward_ttl_exceeded__drop
5. next_hop = route.gateway or dst
   egress = handler owning route.oif (via stack egress seam)
6. next_hop_mac = egress._arp_cache.find_entry(ip4_address=next_hop)
   miss → queue + ARP probe (egress handler's own machinery);
          ip4__forward_no_neighbor__drop counted only on hard failure
7. if len(packet) > egress.mtu:  → M2 (transit PMTU); for M1, drop +
                                     ip4__forward_too_big__drop (placeholder,
                                     replaced by frag/PTB in M2)
8. rebuild IPv4 header: ttl = ttl_in - 1, recompute header checksum;
   re-enqueue onto egress TX toward next_hop_mac; ip4__forward++
return False   # forward path consumed the datagram
```

IPv6 `_forward_or_deliver_ip6` (`packet_handler__ip6__forward.py`)
mirrors this: Hop-Limit in place of TTL (no header checksum to
recompute), no fragmentation ever (routers don't fragment IPv6 → too-big
is Packet Too Big in M2), scope enforcement (never forward a
link-local source/destination off-link — `ip6__forward_scope__drop`).

**New TX helper.** Forwarding re-emits a *received* packet, distinct
from the origination path (`_phtx_ip4`). The forward module builds the
egress frame from the received IP bytes with the lifetime field
decremented — it does not re-run source selection or upper-layer
assembly. This is why it is its own file, not a branch in the existing
TX handler.

### 3.3 Time Exceeded + Destination-Unreachable emission

Clone the `__phrx_ip4__emit_parameter_problem` pattern (build the ICMP
message embedding the leading bytes of the offending datagram, send
back to `packet_rx.ip4.src` via that source's egress). New emitters:

- `emit_time_exceeded_ip4` (type 11, code 0) / `emit_time_exceeded_ip6`
  (type 3, code 0).
- `emit_dest_unreachable_ip4` (type 3, code 0 = net unreachable) /
  `emit_dest_unreachable_ip6` (type 1, code 0 = no route).

Both route the ICMP error back out whatever interface reaches the
original source (`stack.egress_packet_handler(src)`), respecting the
existing `icmp4_error_rate_limiter` / `icmp6_error_rate_limiter`
(RFC 1812 §4.3.2.8 / §4.3.3).

### 3.4 Tests + adherence (M1)

Integration on `RouterTestCase`: forward v4/v6 happy path (TTL/Hop
decrement, correct egress, next-hop MAC); forward disabled → host-drop
parity; TTL=1 → Time Exceeded + no forward; no route → Dest-Unreachable;
ingress-interface isolation (frame leaves only the selected egress).
Flip §5.2 (forward-or-deliver), §5.3.1 (TTL decrement), §4.3.3.1
(Dest-Unreachable), §4.3.3.5 (Time Exceeded) in both
`rfc1812__router_requirements/adherence.md` records.

**Commits:** `feat(sysctl): ip_forward / forwarding knobs`; `feat(ip4):
transit forwarding + TTL Time-Exceeded + no-route Unreachable`;
`feat(ip6): transit forwarding + Hop-Limit Time-Exceeded`.

---

## §4. M2 — transit PMTU + forwarded-packet fragmentation

**Goal:** stop blackholing oversized transit traffic; complete the
forwarder's Destination-Unreachable taxonomy.

1. **IPv4 Fragmentation-Needed** (type 3, code 4) with the egress MTU
   in the next-hop field, when a forwarded packet exceeds egress MTU
   **and** has DF set (RFC 1812 §4.3.3.3; Linux `ip_forward.c`).
   Reuse the existing `icmp4__message__destination_unreachable.py`
   `FRAGMENTATION_NEEDED` code.
2. **IPv4 forwarded-packet fragmentation** when DF is clear — fragment
   to egress MTU before re-enqueue (reuse `packet_handler__ip4_frag__tx`
   machinery; the router fragments, unlike the host-origination path
   that already fragments its own TX).
3. **IPv6 Packet Too Big** (type 2) with egress MTU, when a forwarded
   packet exceeds egress MTU (routers never fragment IPv6 — RFC 8200
   §5). Reuse `icmp6__message__packet_too_big.py`.
4. **Fuller Dest-Unreachable codes**: host unreachable (code 1) when
   next-hop ARP/ND resolution hard-fails; communication administratively
   prohibited (code 13) reserved for a future forward-drop policy.
5. **Embedded-datagram length + ICMP error rate-limiting** applied to
   every transit error (RFC 4443 §2.4, RFC 1812 §4.3.2.8) — reuse the
   shipped rate limiters.

Tests: DF-set oversize → Frag-Needed + no forward; DF-clear oversize →
fragments on egress; IPv6 oversize → Packet Too Big; next-hop
unresolvable → Host-Unreachable. Adherence: §4.3.3.3 (PMTU), §5.2.6
(fragmentation), plus RFC 1191 / 8201 transit rows.

**Commits:** `feat(ip4): transit PMTU Frag-Needed + forwarded-packet
fragmentation`; `feat(ip6): transit Packet Too Big`; `feat(icmp):
Host-Unreachable on next-hop resolution failure`.

---

## §5. M3 — ICMP Redirect generation

**Goal:** the router tells a sender about a better first hop when it
forwards a packet back out the interface it arrived on.

**Trigger (RFC 1812 §5.2.7.2, Linux `__ip_do_redirect`):** ingress
interface == egress interface, the next hop is on-link to the original
source, and `send_redirects` is enabled. Emit toward the source; the
gateway field is the better next hop.

1. **New knobs:** `ip4.send_redirects` / `ip6.send_redirects`
   (per-interface), default **on** for IPv4 (Linux
   `net.ipv4.conf.<if>.send_redirects=1`), model IPv6 per
   `net.ipv6.conf.<if>` behavior.
2. **ICMPv6 Redirect generation** — codec + host RX-accept already
   exist; add the generation path in the IPv6 forward module (build the
   ND Redirect with Target/Destination options, including the target
   link-layer address when known).
3. **ICMPv4 Redirect codec (new — does not exist).** Add via the
   net_proto message pattern: `Icmp4Type.REDIRECT = 5`, a
   `Icmp4RedirectCode` enum (0 net / 1 host / 2 tos+net / 3 tos+host),
   and `icmp4__message__redirect.py` (`*Message` / properties / parser /
   assembler / asserts) with the gateway-address field + embedded
   datagram. Full net_proto unit-test matrix (header asserts, parser
   integrity/sanity/operation, assembler operation).
4. **ICMPv4 Redirect generation** in the IPv4 forward module.
5. **(Sub-item) Host RX-accept of ICMPv4 Redirect** — install a
   `RouteProtocol.REDIRECT` route gated by `ip4.accept_redirects`
   (the FIB enum value is already reserved; ICMPv6 RX-accept already
   ships). Rounds out the redirect story on both sides.

Tests: hairpin forward (ingress==egress) → Redirect emitted with
correct gateway + still forwards the triggering packet; cross-interface
forward → no Redirect; `send_redirects=0` → suppressed; new ICMPv4
Redirect codec wire-format unit tests; host RX installs a redirect
route. Adherence: §4.3.3.2 (Redirect) + a new
`rfc792`/`rfc4443` redirect note.

**Commits:** `feat(net_proto): ICMPv4 Redirect message codec`;
`feat(sysctl): send_redirects knobs`; `feat(icmp6): ND Redirect
generation`; `feat(icmp4): Redirect generation + RX-accept route
install`.

---

## §6. M4 — RFC 1812 conformance sweep

**Goal:** close the residual host-vs-router requirements and flip the
two adherence records to "met" wherever the forwarding plane now
satisfies them.

Walk both `docs/rfc/ip4/rfc1812__router_requirements/adherence.md` and
`docs/rfc/icmp4/rfc1812__router_requirements/adherence.md` clause by
clause. Expected work items surfaced by the walk:

- **Martian-destination filter on forward** — never forward to
  loopback, unspecified, or (IPv4) directed-broadcast/limited-broadcast
  destinations (some ingress-source martian filters already ship;
  extend to the forward-destination side). RFC 1812 §5.3.7.
- **IPv6 scope enforcement** — never forward a link-local
  source/destination across interfaces (RFC 4007). Wired in M1's
  `ip6__forward_scope__drop`; audited here.
- **IP options on forward** — process Record-Route / Timestamp /
  (guarded) source-route options on the forwarded datagram per
  §5.2.4 (the parser already types them; the forward path must honor
  the record/timestamp semantics or drop per policy).
- **TTL=1 to a local address is delivered, not Time-Exceeded** —
  confirm the deliver branch precedes the forward branch (it does; the
  audit pins it).
- **Source-address validation** (§5.3.7) and **do-not-forward from a
  broadcast/multicast source** — confirm the existing sanity checks
  cover the forward path.
- **ICMP error source-address selection** (§4.3.2.5) and
  **rate-limiting** (§4.3.2.8) on transit errors — confirm reuse.

Deliverable: both adherence records show the forwarding clauses **met**
with test references, and the overall-assessment tables updated.

**Commits:** one per clause-group closed, each updating the adherence
record in lockstep; a final `docs(rfc): RFC 1812 forwarding clauses
met` sweep.

---

## §7. Cross-cutting inventory

### New files

| File | Milestone |
|---|---|
| `packages/pytcp/pytcp/tests/lib/router_testcase.py` | M0 |
| `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__forward.py` | M1 |
| `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__forward.py` | M1 |
| `packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__redirect.py` | M3 |
| Integration tests under `packages/pytcp/pytcp/tests/integration/protocols/{ip4,ip6,icmp4,icmp6}/` | M1–M3 |
| net_proto unit tests for the ICMPv4 Redirect codec | M3 |

### Touched files

`_forward_or_deliver_ip{4,6}` in the two RX handlers; `lib/packet_stats.py`
(new `ip{4,6}__forward*` counters); the constants modules for the new
sysctl registrations; `net_proto/.../icmp4__message.py` (add
`REDIRECT = 5`); both `rfc1812__router_requirements/adherence.md`
records; `docs/refactor/sysctl_framework.md` §1 knob table.

### New sysctls (all via the `sysctl_knob` skill)

`ip4.ip_forward`, `ip4.forwarding`, `ip6.all.forwarding`,
`ip6.forwarding` (M1); `ip4.send_redirects`, `ip6.send_redirects`
(M3). `ip4.accept_redirects` if not already present (M3 RX-accept).

### Adherence records

Update in lockstep: `docs/rfc/ip4/rfc1812__router_requirements/`,
`docs/rfc/icmp4/rfc1812__router_requirements/`. New rows referencing
RFC 1191 / 8201 (transit PMTU), 792 / 4443 (transit ICMP + Redirect).

---

## §8. M5 — optional follow-up (post-3.0.9)

**Deferred; not in the 3.0.9 cut.** Opened as its own plan/commit
series when the 3.0.9 unicast plane has landed and stabilized.

### 8.1 Multicast router / querier role

PyTCP has the full IGMP/MLD **host/member** side (membership reporting,
version fallback, SSM). The router side is the **querier**:

- IGMP querier — send General/Group-Specific Membership Queries,
  querier election (lowest-IP wins), the query/response timers,
  per-group membership state as a router. Query codecs already exist
  (`igmp__message__query.py`) and are marked "RX-only… querier role is
  Phase-2 router work".
- MLDv1/MLDv2 querier — the IPv6 parallel
  (`icmp6__mld{1,2}__message__query.py`).
- Multicast forwarding / replication + RPF (needs ≥3 interfaces in the
  harness — the parameterizable M0 topology already supports this).

This is the largest and most separable Phase-2 chunk; bundling it into
3.0.9 would bloat the release with a self-contained feature that has no
dependency on the unicast plane.

### 8.2 FIB extensions

Both already `# Phase 2:` tagged in `runtime/fib.py`:

- **ECMP / multipath** — multiple next-hops per prefix (nexthop
  groups). The `lookup` entry point is designed to absorb this without
  a signature change.
- **Policy routing / multiple tables** (`ip rule`, tables beyond
  `main`/254). `Route` carries no table id yet; add when a consumer
  appears.

### 8.3 Deferred with rationale

`icmp6.accept_redirects`-style host refinements, per-prefix RA lifetime
tracking as a router, and RFC 1812 §5 clauses that only apply to a
transit role PyTCP does not yet take (e.g. transit Router Alert
handling) — tracked in the adherence records as "n/a (M5)".

---

## §9. Sequencing summary

| Milestone | Deliverable | Blocks |
|---|---|---|
| **M0** | Plan + `RouterTestCase` 3-interface harness + stat fields | everything |
| **M1** | `ip_forward` knob + forward branch + Time-Exceeded + no-route Unreachable | M2–M4 |
| **M2** | Transit PMTU (Frag-Needed / Packet Too Big) + IPv4 forwarded fragmentation + Host-Unreachable | M4 |
| **M3** | ICMP Redirect generation (+ new ICMPv4 codec, host RX-accept) | M4 |
| **M4** | RFC 1812 conformance sweep + adherence records flipped | release |
| M5 | *(optional follow-up)* multicast querier + FIB ECMP/policy | — |

Each milestone is tests-first (integration-biased), `make lint` +
`make test` clean per commit, adherence updated in lockstep, and
version/docstring bumps ride the normal cadence. No `git push` without
an explicit ask.

---

## §10. Risks / open questions

1. **Forward-path TX re-injection vs. the origination TX path.** The
   forward module must re-emit received bytes with a decremented
   lifetime without re-running source selection / upper-layer assembly.
   Confirm the cleanest seam onto the egress handler's TX ring
   (probably a dedicated `forward_ip{4,6}(packet_rx, *, egress,
   next_hop_mac)` that assembles an Ethernet frame around the existing
   IP payload). *Resolve in M1 spike.*
2. **Next-hop ARP/ND miss under forwarding.** The host TX path queues
   and probes on a cache miss. For transit traffic, decide the queue
   policy (bounded per-next-hop queue, drop-with-Host-Unreachable after
   N probes) — Linux drops after `unres_qlen`. *Resolve in M1/M2.*
3. **Global-master ↔ per-interface knob coupling.** Decide whether the
   master write eagerly stamps every per-interface knob (Linux) or is
   evaluated as `master OR per-iface` at read time. Eager-stamp matches
   Linux `ip_forward` most closely. *Resolve in M1.*
4. **ICMP error source address.** RFC 1812 §4.3.2.5 constrains the
   source of a router-originated ICMP error. Reuse `select_local_ip*_
   source(dst)` for the interface facing the original sender. *Confirm
   in M1.*
5. **Loopback interface interaction.** Ensure the `lo` handler is never
   selected as a forwarding egress and locally-destined-to-any-own-IP
   still short-circuits before the forward branch. *Regression test in
   M0/M1.*

---

## §11. Cross-references

- `CLAUDE.md` — Project North Star (Phase 2), conformance precedence.
- `docs/refactor/routing_table_host_mode.md` — FIB + Route API (the
  `Route.oif` / destination-keyed `lookup` this plane consumes).
- `docs/refactor/packet_handler_rewrite_plan.md` — per-interface
  handlers + the `forward_or_deliver` seam this plane fills.
- `docs/refactor/sysctl_per_interface.md` — the per-interface conf
  plane hosting the forwarding knobs.
- `docs/rfc/ip4/rfc1812__router_requirements/adherence.md` and
  `docs/rfc/icmp4/rfc1812__router_requirements/adherence.md` — the gap
  maps flipped by M1–M4.
- `.claude/skills/sysctl_knob/SKILL.md` — knob workflow (M1, M3).
- `.claude/rules/{feature_implementation,integration_testing,net_proto}.md`
  — tests-first, harness, and the ICMPv4 Redirect codec pattern.
