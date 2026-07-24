# Introspection API — State observation surface

| Field           | Value                                                                                                |
|-----------------|------------------------------------------------------------------------------------------------------|
| Status          | partial — counters, routes, neighbors, and sockets all readable as frozen snapshots; not yet unified behind one `stack.introspect` namespace |
| Module paths    | In-process `stack.link.stats` / `stack.route.list_routes()` / `stack.neighbor.list_neighbors()`; out-of-process `client.ss` / `client.route` / `client.neighbor` and the `pytcp ss` / `route` / `neighbor` CLI |
| Linux analogue  | `/proc/net/route`, `/proc/net/arp`, `ss`, `/proc/net/dev`, `ip -s link show`                        |

## Purpose

The Introspection API is PyTCP's read-only state-observation
surface — the canonical way for monitoring tools, operator
CLIs, and debugging consumers to inspect stack state
without mutating it. Mirrors Linux's `/proc/net/*` files
and the `ss` (`socket statistics`) tool.

Per CLAUDE.md Phase-3 design implications: **state
introspection is read-only and copy-by-value**. Accessors
return immutable snapshots, never live references that
the caller could mutate. The Linux equivalent is
`/proc/net/*` text — readable, never writable by reading.

## Current state (Phase 1 — partial)

Four categories of introspection, all reading as frozen
copy-by-value snapshots; what is not yet done is unifying
them behind a single `stack.introspect` namespace.

| Category               | Status                                                         |
|------------------------|----------------------------------------------------------------|
| Per-interface counters | **shipped** — `stack.link.stats` returns a frozen `LinkStats` snapshot |
| Route table            | **shipped** — `stack.route.list_routes()` (in-process) / `client.route` / `pytcp route`, returning frozen `Route` snapshots |
| Neighbor cache         | **shipped** — `stack.neighbor.list_neighbors()` (in-process) / `client.neighbor` / `pytcp neighbor`, returning frozen snapshots |
| Socket list            | **shipped** — `client.ss.list_sockets()` / `pytcp ss` return frozen `SocketSnapshot`s; `stack.sockets` is a `SocketTable` (a read-only in-process wrapper is still pending) |

### Shipped: `LinkApi.stats`

`pytcp.stack.link.stats` returns a `LinkStats` frozen
dataclass with eight buckets — Linux's `ip -s link show`
RX/TX block equivalent.

```python
from pytcp.stack import link

s = link.stats
# rx_packets / rx_bytes / rx_errors / rx_dropped
# tx_packets / tx_bytes / tx_errors / tx_dropped
```

Full documentation at [`link_api.md`](link_api.md) §LinkStats.

### Shipped: socket list

`client.ss.list_sockets()` (and the `pytcp ss` CLI) return
a `tuple[SocketSnapshot, ...]` — a frozen dataclass exposing
address family, socket type, local / remote address, local /
remote port, state, and queue depths, mirroring Linux's
`ss -tan` columns. The snapshots are built by
`pytcp.stack.socket_introspect`.

In-process, `stack.sockets` is a `SocketTable` populated by
every `bind()` / connect path. A read-only snapshot wrapper
over it for in-process callers (matching the out-of-process
`client.ss` surface) is the one remaining piece.

## What ships today vs. the unified namespace

The per-category reads all ship; the remaining work is
consolidating them behind one `stack.introspect` namespace.

```python
# Per-interface
stack.link.stats                          # shipped
stack.link.name                           # shipped

# Per-route (Route API)
stack.route.list_routes(family=...)       # shipped

# Per-neighbor (Neighbor API)
stack.neighbor.list_neighbors(family=...) # shipped

# Per-socket
client.ss.list_sockets()                  # shipped (out-of-process); frozen SocketSnapshots

# Consolidated namespace
stack.introspect.list_sockets()           # not yet (single unified namespace)
stack.introspect.is_running               # not yet (today: stack.link.is_running)
stack.introspect.startup_time             # not yet
```

Each accessor returns a frozen, copy-by-value snapshot.

## Phase-3 alignment

The introspection contract per CLAUDE.md is verbatim:

> State introspection is read-only and copy-by-value.
> Route-table / neighbor-cache / socket-list / packet-
> counter accessors return immutable snapshots, never
> live references the caller could mutate. The Linux
> equivalent is `/proc/net/*` text — readable, never
> writable by reading.

`LinkApi.stats`, `stack.route.list_routes()`,
`stack.neighbor.list_neighbors()`, and the out-of-process
`client.ss` / `client.route` / `client.neighbor` surfaces
all meet this — each returns a frozen snapshot. The one
remaining gap is a read-only in-process wrapper over the
`stack.sockets` `SocketTable`, so an in-process caller can
still reach a live reference there.

## Deferred / out of scope

- **`ss`-style filtering** (Linux `ss -tan dst :22`) — not
  a Phase-1 concern; raw-list iteration covers the use
  cases.
- **Per-CPU counters** — Linux exposes per-CPU counters
  for hot paths; PyTCP is single-threaded per-subsystem
  so this doesn't apply.
- **Netlink-style event subscriptions** — Linux's
  `RTM_NEWLINK / DELLINK` events. The Address API's
  `subscribe_conflicts` is the closest existing
  equivalent; a generic "watch any stack event"
  subscription is Phase-2+.

## Plan / history

- No standalone refactor plan — the Introspection surface
  grows incrementally as the Link / Route / Neighbor APIs
  ship.
- Link API stats: shipped 2026-05-12; see
  [`link_api.md`](link_api.md) §LinkStats.
- Socket-list consolidation: tracked under the socket
  parity audit (`docs/refactor/socket_linux_parity_audit.md`).

## Cross-API dependencies

- **Link API**: provides per-interface counters today.
- **Route API**: will provide FIB introspection when
  shipped.
- **Neighbor API**: will provide ARP / ND cache
  introspection when shipped.
- **Socket factory**: socket-list introspection wraps
  `pytcp.stack.sockets` once consolidated.
