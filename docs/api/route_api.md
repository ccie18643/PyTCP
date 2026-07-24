# Route API — Routing-control surface

| Field           | Value                                                                              |
|-----------------|------------------------------------------------------------------------------------|
| Status          | **shipped** — host-mode FIB + operator surface                                     |
| Module path     | `pytcp.stack.route` (`RouteApi`, instance `stack.route`); table in `pytcp.runtime.fib` |
| Linux analogue  | `ip route add` / `ip route del` / `ip route show` / RTNETLINK `RTM_NEWROUTE`       |
| Refactor plan   | [`routing_table_host_mode.md`](../refactor/routing_table_host_mode.md)             |

## Purpose

The Route API is PyTCP's routing-control consumer surface —
the canonical way to add / remove / list routes and default
gateways, mirroring Linux's `ip route` family. It sits over
a real host-mode FIB (`pytcp.runtime.fib.RouteTable`): the
default gateway is FIB state, not a per-`IfAddr` attribute
(the old `Ip4IfAddr.gateway` / `Ip6IfAddr.gateway` fields
were removed), and the Ethernet-TX path resolves the next
hop via a destination-keyed FIB lookup.

## Current implementation (Phase-1 host mode)

- A per-family FIB (`RouteTable` for IPv4 / IPv6) holds
  connected routes (derived from bound host networks) plus
  explicitly-installed routes and the default route.
- Next-hop selection is a longest-prefix lookup against the
  FIB, keyed on the packet's destination.
- `Route` carries a destination prefix, an optional
  gateway, `RouteProtocol` (who installed it — boot / static
  / DHCP), `RouteScope`, and an optional outgoing interface.

Phase-2 (router-grade) items remain deferred — see below.

## Surface

`stack.route` is a `RouteApi`. `Route`, `RouteProtocol`,
`RouteScope`, and `RouteTable` are exported from
`pytcp.stack` (re-exported from `pytcp.runtime.fib`).

```python
from pytcp import stack
from pytcp.stack import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily
from net_addr import Ip4Address, Ip4Network

# Read — immutable snapshot
stack.route.list_routes(family=AddressFamily.INET4)   # → tuple[Route, ...]

# Mutation
stack.route.add_route(
    route=Route(destination=Ip4Network("192.0.2.0/24"), gateway=Ip4Address("10.0.1.1")),
)
stack.route.remove_route(destination=Ip4Network("192.0.2.0/24"))   # → count removed
stack.route.replace_default(gateway=Ip4Address("10.0.1.1"), protocol=RouteProtocol.STATIC)
stack.route.remove_default(family=AddressFamily.INET4)             # → count removed
```

The CLI verbs `pytcp route` (`add` / `del` / `show`) drive
the same surface over the daemon IPC boundary
(`pytcp.client.client__route`).

## Linux equivalents covered

- `ip route show` — `list_routes`.
- `ip route add <net> via <gw>` — `add_route`.
- `ip route del` — `remove_route`.
- default-route replace — `replace_default` / `remove_default`.

## Deferred / out of scope

Per CLAUDE.md non-goals: **no userspace routing protocols**
(BGP, OSPF, RIP) — those belong outside the stack. The
Route API is for the static / kernel-managed route table
that operator tools and the RX-side forwarding decision
consume.

Phase-2 (router-grade) items still deferred:

- ICMP Redirect emission (RFC 1812 §4.3.3.2 / RFC 1122
  §3.3.1.5) — the forwarder generates Redirects when an
  RX route lookup discovers the same-subnet next hop.
- RX route-cache update on received Redirect.
- Source-route forwarding (LSRR/SSRR pointer advance) —
  RFC 1122 §3.3.5.
- Multi-table / policy routing (`ip route ... table <name>`).
- `ip route get <dst>` as an operator command (the FIB
  lookup exists internally on the TX path).

## Cross-API dependencies

- **Address API**: connected routes are derived from the
  host networks bound via the Address API; source-address
  selection consumes the same bindings.
- **Link API**: routes carry an outgoing interface; the
  single-interface Phase-1 stack makes this implicit,
  Phase-2 multi-interface makes it a real per-interface
  pointer.
- **Sysctl**: `net.ipv4.conf.*.forwarding` — the master
  enable for the FIB-as-forwarder mode (Phase-2; not
  registered today, host mode does not forward).
