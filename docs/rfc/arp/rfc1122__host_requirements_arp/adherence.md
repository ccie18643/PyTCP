# RFC 1122 §2.3.2 — Host Requirements (ARP)

| Field       | Value                                                        |
|-------------|--------------------------------------------------------------|
| RFC number  | 1122                                                         |
| Title       | Requirements for Internet Hosts -- Communication Layers      |
| Section     | §2.3.2 (Address Resolution Protocol -- ARP)                  |
| Category    | Internet Standard (STD 3)                                    |
| Date        | October 1989                                                 |
| Source text | [`rfc1122.txt`](rfc1122.txt) §2.3.2                          |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 1122
§2.3.2 (the host-side ARP cache requirements). The §2.3.2.1
(ARP Cache Validation) and §2.3.2.2 (ARP Packet Queue)
sub-sections are audited individually.

The §3 IPv4 and §4 TCP sub-sections of RFC 1122 are audited
under
[`docs/rfc/tcp/rfc1122__host_requirements/`](../../tcp/rfc1122__host_requirements/adherence.md)
and [`docs/rfc/icmp4/rfc1122__host_requirements_icmp/`](../../icmp4/rfc1122__host_requirements_icmp/adherence.md).
The base RFC 826 wire format / algorithm audit lives at
[`../rfc826__arp/adherence.md`](../rfc826__arp/adherence.md);
the RFC 5227 probe / announce / defense audit lives at
[`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under
`packages/pytcp/pytcp/protocols/arp/arp__cache.py` (the IPv4
adapter), `packages/pytcp/pytcp/lib/neighbor.py` (the generic
`NeighborCache[A, P]` NUD state machine it inherits) and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__{rx,tx}.py`
directly. Adherence levels use the canonical descriptive
language: **met**, **not met**, **partial**, **not implemented**,
**vacuous**.

The §2.3.1 (Trailer Encapsulation) sub-section is summarised
inline as out-of-scope: trailer encapsulation is a deprecated
1980s mechanism and PyTCP correctly does not implement it; the
host-requirements compliance summary at RFC 1122 §2.5 lists it
as MUST NOT default-on, MAY support — PyTCP's choice of
"never support" is allowed.

---

## §2.3.2.1 — ARP Cache Validation

> "An implementation of the Address Resolution Protocol
> (ARP) [LINK:2] MUST provide a mechanism to flush
> out-of-date cache entries."

**Adherence:** **met**. `ArpCache` inherits the generic
`NeighborCache._subsystem_loop`
(`packages/pytcp/pytcp/lib/neighbor.py:406-501`): every 100 ms
(the shared `SUBSYSTEM_SLEEP_TIME__SEC = 0.1`) the loop ages
each entry through the RFC 4861 NUD states — a confirmed
`REACHABLE` entry that has not been reconfirmed for
`neighbor.reachable_time` seconds transitions to `STALE`
(`neighbor.py:453-454`), and the three-tier GC pass
(`neighbor.py:503-585`) evicts `FAILED` and aged-out `STALE`
entries once the cache crosses `neighbor.gc_thresh1`. The
`PERMANENT` state is the lone eviction exception
(`neighbor.py:542`); RFC 1122 §2.3.2.1 mentions "manual
flush" as a non-mandatory implementation detail and PyTCP's
approach is consistent.

> "If this mechanism involves a timeout, it SHOULD be
> possible to configure the timeout value."

**Adherence:** **met**. The NUD timing knobs
(`neighbor.reachable_time`, `neighbor.retrans_timer`,
`neighbor.gc_stale_time`, and the solicit-count / GC-threshold
family) live in
`packages/pytcp/pytcp/lib/neighbor__constants.py` and are
registered with the sysctl registry under the `neighbor.*`
namespace. An operator tunes them at boot via the
`stack.init(sysctls={...})` bag or at runtime via
`pytcp.stack.sysctl["neighbor.reachable_time"] = ...`; the
cache loop resolves each knob through
`sysctl_iface.get_for_iface(...)` once per iteration
(`packages/pytcp/pytcp/lib/neighbor.py:425-429`), so a mutation
is picked up on the next pass. The Linux equivalents are
`net.ipv4.neigh.default.base_reachable_time` and
`net.ipv4.neigh.default.gc_stale_time`.

For RFC 1122 §2.3.2.1's proxy-ARP-on-the-order-of-a-minute
guidance, an operator running on a proxy-ARP-heavy LAN can
dial in a short reachability lifetime — e.g.
`pytcp.stack.sysctl["neighbor.reachable_time"] = 60` — to
tune the appropriate timeout without editing the source.

Per-interface timeouts (Linux's `net.ipv4.neigh.<iface>.*`
namespace) are already modelled by the knobs'
`interface_scope=True` storage: the operator addresses
`neighbor.<ifname>.<field>` or the `neighbor.default.<field>`
template. Binding more than one cache to a non-default
interface name lands with multi-interface support (Phase 2).

> "A mechanism to prevent ARP flooding (repeatedly sending
> an ARP Request for the same IP address, at a high rate)
> MUST be included. The recommended maximum rate is 1 per
> second per destination."

**Adherence:** **met**. The NUD state machine gates ARP
Requests exactly as RFC 1122 requires — one solicit per
in-flight resolution, then a bounded retransmit schedule.
On the first cache miss `NeighborCache._find_entry`
(`packages/pytcp/pytcp/lib/neighbor.py:201-231`) creates a
single `INCOMPLETE` entry and fires one broadcast solicit;
every subsequent `find_entry` while the entry is still
`INCOMPLETE` returns `None` **without** re-soliciting
(`neighbor.py:243-244`), so a burst of TX attempts to an
unresolved IP produces exactly one Request, not one per
packet. Retransmits are driven only by the subsystem loop,
gated by `neighbor.retrans_timer` (default 1 s —
`neighbor.py:469`) and hard-capped at
`neighbor.max_multicast_solicit` (default 3) probes before
the entry transitions to `FAILED` (`neighbor.py:465-467`).
The refresh / probe path (`PROBE` state) is likewise gated
by `retrans_timer` and capped at
`neighbor.max_unicast_solicit` (`neighbor.py:475-478`).

This mirrors Linux's `net/core/neighbour.c`, which gates new
probes via the `NUD_INCOMPLETE` state, the `unres_qlen`
queue, and the `mcast_solicit` / `ucast_solicit` per-entry
counters; PyTCP implements the same primitives.

> "DISCUSSION: The ARP specification [LINK:2] suggests but
> does not require a timeout mechanism to invalidate cache
> entries when hosts change their Ethernet addresses. The
> prevalence of proxy ARP ... has significantly increased
> the likelihood that cache entries in hosts will become
> invalid, and therefore some ARP-cache invalidation
> mechanism is now required for hosts."

**Adherence:** **met**. The NUD aging mechanism described
above satisfies this — a stale mapping is reconfirmed by a
unicast probe (or aged out to `FAILED`) rather than trusted
indefinitely.

> "IMPLEMENTATION: Four mechanisms have been used,
> sometimes in combination, to flush out-of-date cache
> entries. (1) Timeout — Periodically time out cache
> entries, even if they are in use."

**Adherence:** **met**. Implementation (1) is what PyTCP
does: a `REACHABLE` entry transitions to `STALE` after
`neighbor.reachable_time` seconds
(`packages/pytcp/pytcp/lib/neighbor.py:453-454`) and is then
reconfirmed by a unicast probe. The "even if they are in
use" wording is satisfied because the age check keys on the
entry's `state_changed_at`, not `last_used_at`: recent use
does not postpone the `REACHABLE → STALE` transition
(`last_used_at` only influences the LRU order of the
hard-cap GC tier — `neighbor.py:585-589`).

> "(1) ... Note that this timeout should be restarted when
> the cache entry is 'refreshed' (by observing the source
> fields, regardless of target address, of an ARP
> broadcast from the system in question)."

**Adherence:** **met**. `ArpCache.add_entry()` delegates to
`NeighborCache._add_entry`
(`packages/pytcp/pytcp/lib/neighbor.py:246-293`), which
transitions the named entry to `REACHABLE` with a fresh
`state_changed_at` timestamp (`neighbor.py:285,604-613`),
restarting the aging clock. The `__update_arp_cache` helper
in the RX handler runs this path on every RFC-826-compliant
ARP packet (Request **or** Reply) whose SPA falls in our
subnet
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:91-129,244,288`),
which satisfies the "regardless of target address"
requirement.

> "(2) Unicast Poll — Actively poll the remote host by
> periodically sending a point-to-point ARP Request to it,
> and delete the entry if no ARP Reply is received from N
> successive polls."

**Adherence:** **met**. PyTCP's `PROBE`-state refresh path
sends the poll as a **unicast** ARP Request. The
`_solicit_arp` callback routes the `cached_mac is not None`
case to
`self._owner.send_arp_unicast_request(arp__tpa=...,
ethernet__dst=cached_mac)`
(`packages/pytcp/pytcp/protocols/arp/arp__cache.py:167-186` →
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:195`
`send_arp_unicast_request`). RFC 1122 §2.3.2.1
IMPLEMENTATION (2) calls for the "point-to-point" form so
that only the actual cached neighbour wakes up to reply
rather than every host on the segment; this is what PyTCP
does today.

The "delete after N successive failed polls" counter is
present too: an entry in `PROBE` that reaches
`neighbor.max_unicast_solicit` unanswered unicast probes
transitions to `FAILED` and is then GC-evicted
(`packages/pytcp/pytcp/lib/neighbor.py:475-478`), which is the
complete IMPLEMENTATION (2) form.

> "(3) Link-Layer Advice — If the link-layer driver
> detects a delivery problem, flush the corresponding ARP
> cache entry."

**Adherence:** **not implemented**. The TX ring
(`packages/pytcp/pytcp/runtime/tx_ring.py`) does report `os.writev` errors
via `tx_ring__os_error__drop` on the shared
`PacketStatsTx` (post the recent rings refactor), but
there is no plumbing back from "writev failed for a packet
destined to MAC X" to "flush the ARP cache entry that
mapped IP Y to MAC X". RFC 1122 lists this only as one of
four IMPLEMENTATION alternatives (no MUST), so the absence
is RFC-compliant; mentioning it here for the audit trail.

> "(4) Higher-layer Advice — Provide a call from the
> Internet layer to the link layer to indicate a delivery
> problem."

**Adherence:** **not implemented**. Same as (3) — RFC 1122
lists this as an alternative implementation, not a
requirement. PyTCP relies on (1) Timeout exclusively.

---

## §2.3.2.2 — ARP Packet Queue

> "The link layer SHOULD save (rather than discard) at
> least one (the latest) packet of each set of packets
> destined to the same unresolved IP address, and transmit
> the saved packet when the address has been resolved."

**Adherence:** **met — and exceeded.** PyTCP saves
unresolved packets in a bounded per-neighbour queue and
flushes them all on resolution, mirroring the Linux
`neigh->arp_queue` (`net/core/neighbour.c`):

- On a cache miss the IPv4 Ethernet-TX path calls
  `stack.arp_cache.enqueue_pending(...)` for both the
  on-link and the gateway branch
  (`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`),
  appending the dropped Ethernet frame to the INCOMPLETE
  entry's pending queue.
- The generic `NeighborCache` (`packages/pytcp/pytcp/lib/neighbor.py`)
  holds the pending packets in a `deque` bounded by the
  `neighbor.unres_qlen` sysctl (Linux
  `net.ipv4.neigh.default.unres_qlen`; default 64,
  sized to hold every fragment of a maximum-size IPv4
  datagram at a 1500-byte MTU). On overflow the **oldest**
  packet is dropped (Linux drop-from-head policy), keeping
  the newest within the bound.
- When the ARP Reply arrives, `__update_arp_cache` →
  `arp_cache.add_entry` → `NeighborCache._add_entry`
  drains the whole queue and re-emits every frame in
  **FIFO arrival order** through the resolved MAC. The
  same generic mechanism serves IPv6/ND, so the latent
  fragmented-IPv6 case is covered too.

The RFC's SHOULD floor is "at least one (the latest)";
PyTCP exceeds it by saving *all* packets within the
bound. This is required for correctness, not just
performance: a fragmented datagram is several link-layer
packets, and a single-slot "latest only" queue would
make every fragmented datagram to an unresolved neighbour
unreassemblable. There is no RFC interaction beyond
§2.3.2.2 itself.

> "DISCUSSION: Failure to follow this recommendation
> causes the first packet of every exchange to be lost.
> Although higher-layer protocols can generally cope with
> packet loss by retransmission, packet loss does impact
> performance."

**Adherence:** N/A (discussion paragraph). The above
analysis matches the discussion's prediction.

---

## §2.3.1 — Trailer Encapsulation (out of scope)

RFC 1122 §2.3.1 describes a 1980s-era optimisation
("trailer encapsulation") for `4.2BSD` and similar systems.
The summary at RFC 1122 §2.5 marks the host requirement as
"Send Trailers by Default Without Negotiation" MUST NOT,
"Send Trailers After Negotiation" MAY. PyTCP correctly
does not send trailer ARP replies and never advertises
trailer support — so the RFC requirement is **vacuously
met (deliberate non-implementation of an optional
feature)**.

---

## Summary of compliance with the RFC 1122 §2.5 host-requirements
## checklist (the table at lines 1513–1516 of `rfc1122.txt`)

The §2.5 summary table lists the §2.3.2 row of the host
requirements; pasting it here for traceability:

| Requirement                                  | RFC ref     | MUST | SHOULD | MAY | PyTCP status                |
|----------------------------------------------|-------------|------|--------|-----|-----------------------------|
| Flush out-of-date ARP cache entries          | 2.3.2.1     | x    |        |     | met                         |
| Prevent ARP floods                           | 2.3.2.1     | x    |        |     | met — see §2.3.2.1          |
| Cache timeout configurable                   | 2.3.2.1     |      | x      |     | met (neighbor.* sysctls)    |
| Save at least one (latest) unresolved pkt    | 2.3.2.2     |      | x      |     | met (exceeds — bounded queue) |

All four requirements are now met: both MUSTs (flush
out-of-date entries, prevent ARP floods) via the NUD state
machine, the timeout-configurable SHOULD via the
`neighbor.*` sysctls, and the §2.3.2.2 SHOULD (save the
latest unresolved packet) met and exceeded by the bounded
per-neighbour queue.

---

## Test coverage audit

### §2.3.2.1 — Timeout-based eviction

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCachePermanent::test__lib__neighbor__permanent_skips_all_aging`
  — pins that `PERMANENT` entries are never aged.
- **Unit:**
  `..::TestNeighborCacheReachableToStale::test__lib__neighbor__reachable_transitions_to_stale_after_reachable_time`
  — pins the `neighbor.reachable_time` threshold: a
  `REACHABLE` entry aged past it transitions to `STALE`.
- **Unit:**
  `..::TestNeighborCacheGcPass::test__lib__neighbor__gc_evicts_failed_above_thresh1`
  — pins the GC eviction of aged-out entries once the cache
  crosses `neighbor.gc_thresh1`.

**Status:** **locked in**.

### §2.3.2.1 — "Timeout restarted on refresh"

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheProbeToReachable::test__lib__neighbor__add_entry_in_probe_returns_to_reachable`
  — pins that `add_entry` for a probed IP transitions the
  entry back to `REACHABLE`, which restarts the aging clock
  via a fresh `state_changed_at`.

**Status:** **locked in**.

### §2.3.2.1 — ARP flood prevention (MUST, MET)

**Locked in.** Pinned at both layers:

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheFindMiss::test__lib__neighbor__find_repeated_within_retrans_no_new_solicit`
  — repeated `find_entry` on an `INCOMPLETE` entry fires no
  additional solicit; and
  `TestNeighborCacheIncompleteRetransmits::test__lib__neighbor__incomplete_transitions_to_failed_after_max_multicast_solicit`
  — retransmits are capped at
  `neighbor.max_multicast_solicit`.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__resolution_flow.py::TestArpResolutionFlow::test__arp__resolution__rate_limit_at_wire_level`
  — a burst of outbound packets to an unresolved IP emits
  exactly one ARP Request on the wire; and
  `..::test__arp__resolution__per_ip_independence` covers
  per-destination granularity (IP `X` and `Y` do not
  throttle each other).

### §2.3.2.1 — Configurable timeout (SHOULD, MET)

**Locked in.**
`packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheSysctlOverrides::test__lib__neighbor__reachable_time_sysctl_override_honoured`
confirms that overriding `neighbor.reachable_time` through
the sysctl registry drives the `REACHABLE → STALE`
transition at the new threshold.

### §2.3.2.1 — Unicast vs broadcast refresh poll

The unicast-refresh behaviour is captured by
`packages/pytcp/pytcp/tests/unit/protocols/arp/test__arp__cache.py::TestArpCacheSolicitCallback::test__arp_cache__solicit_probe_fires_unicast_request`
(the `cached_mac is not None` solicit path calls
`send_arp_unicast_request(ethernet__dst=cached_mac)`) and by
`..::test__arp_cache__solicit_incomplete_fires_broadcast_request`
(the `cached_mac is None` path fires the broadcast
`send_arp_request`).

**Status:** **locked in**.

### §2.3.2.2 — Save unresolved packet (SHOULD, MET — exceeded)

**Locked in.** Pinned at both layers:

- Unit (`packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py`,
  `TestNeighborCachePendingQueue`): all queued packets
  flush in FIFO order on resolution; the queue is bounded
  by `neighbor.unres_qlen` and drops the **oldest** on
  overflow (keeping the newest within the bound).
- Integration
  (`packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__resolution_flow.py`):
  drives three outbound IPv4 packets to an unresolved IP,
  then an inbound ARP Reply, and asserts all three are
  flushed in FIFO arrival order with the resolved MAC.
- Adapter
  (`packages/pytcp/pytcp/tests/unit/protocols/arp/test__arp__cache.py`):
  `enqueue_pending` appends to the INCOMPLETE entry's
  pending queue.

PyTCP saves *all* packets within the bound (not just the
latest), exceeding the SHOULD floor — required so a
fragmented datagram (multiple link-layer packets) to an
unresolved neighbour survives resolution intact.

### Test coverage summary

| §         | Aspect                                                | Coverage                                                   |
|-----------|-------------------------------------------------------|------------------------------------------------------------|
| §2.3.2.1  | Flush out-of-date entries via timeout                 | locked in                                                  |
| §2.3.2.1  | Timeout restarted on refresh                          | locked in                                                  |
| §2.3.2.1  | ARP flood prevention                                  | locked in (unit + integration)                             |
| §2.3.2.1  | Timeout configurable                                  | locked in (unit: TestNeighborCacheSysctlOverrides)         |
| §2.3.2.1  | Refresh-poll form (unicast IMPL (2))                  | locked in (unit: TestArpCacheSolicitCallback)              |
| §2.3.2.2  | Save at least one unresolved packet                   | locked in (unit + integration)                             |

---

## Overall assessment

| Aspect                                 | Status                                              |
|----------------------------------------|-----------------------------------------------------|
| Flush out-of-date entries (MUST)       | met                                                 |
| Configurable timeout (SHOULD)          | met (neighbor.* sysctls; per-interface deferred to Phase 2) |
| Prevent ARP floods (MUST)              | met                                                 |
| Timeout restarted on refresh           | met                                                 |
| Refresh-poll form                      | met (unicast IMPL (2)) + failed-poll counter        |
| Save unresolved packet (SHOULD)        | met (exceeds — bounded queue)                       |
| Trailer encapsulation                  | met (deliberate non-implementation; allowed)        |

### Principal compliance gaps

None outstanding. The three requirements this record
previously tracked as open are all closed by the NUD state
machine (`packages/pytcp/pytcp/lib/neighbor.py`) that replaced
the flat ARP cache:

1. **MUST: ARP flood prevention** — the `INCOMPLETE` state
   fires one solicit per resolution and retransmits are
   gated by `neighbor.retrans_timer` / capped by
   `neighbor.max_multicast_solicit`.

2. **SHOULD: Save the latest unresolved packet** — the
   bounded per-neighbour `queued_packets` deque saves every
   packet within `neighbor.unres_qlen` and flushes them in
   FIFO order on resolution (exceeds the "at least one"
   floor).

3. **SHOULD: Configurable timeout** — the NUD timing knobs
   are `neighbor.*` sysctls, tunable at boot
   (`stack.init(sysctls={...})`) and at runtime
   (`pytcp.stack.sysctl[...] = ...`).

The one remaining non-normative item is IMPLEMENTATION (3) /
(4) — link-layer / higher-layer delivery-failure advice —
which RFC 1122 lists as optional alternatives; PyTCP relies
on the Timeout mechanism (IMPLEMENTATION (1)) exclusively.
