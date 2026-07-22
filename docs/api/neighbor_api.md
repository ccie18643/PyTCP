# Neighbor API — Neighbor-control surface

| Field           | Value                                                                          |
|-----------------|--------------------------------------------------------------------------------|
| Status          | **shipped** — static entries + flush + snapshot                                |
| Module path     | `pytcp.stack.neighbor` (`NeighborApi`, instance `stack.neighbor`)              |
| Linux analogue  | `ip neighbor add` / `ip neighbor del` / `ip neighbor show` / RTNETLINK `RTM_NEWNEIGH` |
| Refactor plan   | packet-handler rewrite / Neighbor API (see `docs/refactor/`)                   |

## Purpose

The Neighbor API is PyTCP's neighbor-control consumer
surface — the canonical way to add / remove / list ARP +
ND cache entries and to flush stale state, mirroring
Linux's `ip neighbor` family. The dynamic caches
(`pytcp.protocols.arp` ARP cache, `pytcp.protocols.icmp6.nd`
ND cache) still auto-populate on RX and age out per the RFC
4861 NUD framework and the `neighbor.*` sysctls; the API
adds the operator / consumer surface on top.

## Surface

`stack.neighbor` is a `NeighborApi`; `list_neighbors`
returns read-only `NeighborSnapshot` values. Family is
inferred from the address (IPv4 → ARP cache, IPv6 → ND
cache).

```python
from pytcp import stack
from pytcp.runtime.socket import AddressFamily
from net_addr import Ip4Address, MacAddress

# Read — Linux 'ip neighbor show' (copy-by-value snapshot)
stack.neighbor.list_neighbors()                          # → tuple[NeighborSnapshot, ...]
stack.neighbor.list_neighbors(family=AddressFamily.INET4)  # 'ip -4 neighbor show'

# Mutation
stack.neighbor.add(ip=Ip4Address("10.0.1.5"), mac=MacAddress("02:00:00:00:00:05"))  # nud permanent
stack.neighbor.remove(ip=Ip4Address("10.0.1.5"))
stack.neighbor.flush(family=AddressFamily.INET4)

# Per-interface scoping (Linux 'ip neighbor ... dev <if>')
stack.neighbor.interface(ifindex).add(ip=..., mac=...)
```

`add` installs a **permanent** entry (Linux `nud
permanent`): it never ages out and dynamic learning never
overrides it — useful for closed-network deployments where
ARP/ND traffic should be suppressed. The CLI verbs `pytcp
neighbor` (`add` / `del` / `flush` / `show`) drive the same
surface over the daemon IPC boundary
(`pytcp.client.client__neighbor`).

## Linux equivalents covered

- `ip neighbor show` (and `ip -4` / `ip -6`) — `list_neighbors`.
- `ip neighbor add <ip> lladdr <mac> nud permanent` — `add`.
- `ip neighbor del` — `remove`.
- `ip neighbor flush` — `flush`.
- `ip neighbor ... dev <if>` — `interface(ifindex)` scoping.

## Deferred / out of scope

- **NUD administrative-state override** — Linux's
  `nud none` / `nud reachable` administrative modes are
  niche; only `nud permanent` (static) is exposed.
- **ND-purge on address removal** — when an address is
  removed (Address API), Linux purges related ND cache
  entries; PyTCP defers that cleanup.

## Cross-API dependencies

- **Sysctl**: NUD aging parameters
  (`neighbor.reachable_time`, `neighbor.retrans_timer`,
  etc.) are sysctl-tunable and govern the dynamic entries
  the API coexists with.
- **Link API**: `interface(ifindex)` scopes the neighbor
  operations to a specific interface's caches.
- **Address API**: the caches map on-link addresses within
  the host networks bound via the Address API.
