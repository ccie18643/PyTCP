# PyTCP Consumer APIs

This directory documents the **Phase-3 sanctioned consumer
APIs** — the seven surfaces PyTCP exposes to consumer code
(tests, examples, CLI tools, eventually external
applications). CLAUDE.md's Project North Star §Phase 3
describes the design: PyTCP becomes a self-contained
"kernel" exposing a small Linux-mirrored set of user-facing
APIs; everything else is internal to the stack.

Consumer code MUST use only these surfaces — never
reach into `packet_handler.*`, `pytcp.lib.*` internals, or
any other implementation-detail module. The architectural
seam each API provides is what the Phase-3 IPC channel sits
behind without changing the consumer-facing shape: as of
3.0.8 that channel has shipped (`pytcp.ipc` / `pytcp.client`
over AF_UNIX, with the `pytcp.daemon` owning the stack), so
these surfaces are consumed both in-process and out-of-process
through the same API shape.

## Surface inventory

| Surface                                           | Plane                  | Linux equivalent                                       | Status     | Doc                                            |
|---------------------------------------------------|------------------------|--------------------------------------------------------|------------|------------------------------------------------|
| **Socket factory** + methods                      | Data                   | `socket(2)`                                            | shipped    | [`socket_api.md`](socket_api.md)               |
| **Sysctl registry** (`pytcp.stack.sysctl`)        | Protocol-policy control | `/proc/sys/net/`                                       | shipped    | [`sysctl_registry.md`](sysctl_registry.md)     |
| **Link API** (`pytcp.stack.link`)                 | Link control           | `ip link` / RTNETLINK `RTM_NEWLINK`                    | shipped    | [`link_api.md`](link_api.md)                   |
| **Address API** (`pytcp.stack.address`)           | Network-layer control  | `ip addr` / RTNETLINK `RTM_NEWADDR`                    | shipped    | [`address_api.md`](address_api.md)             |
| **Route API** (`pytcp.stack.route`)               | Routing control        | `ip route` / RTNETLINK `RTM_NEWROUTE`                  | shipped    | [`route_api.md`](route_api.md)                 |
| **Neighbor API** (`pytcp.stack.neighbor`)         | Neighbor control       | `ip neighbor` / RTNETLINK `RTM_NEWNEIGH`               | shipped    | [`neighbor_api.md`](neighbor_api.md)           |
| **Introspection API**                             | State observation      | `/proc/net/route`, `/proc/net/arp`, `ss`, `/proc/net/dev` | partial    | [`introspection_api.md`](introspection_api.md) |

## What "shipped" means

A surface marked **shipped** is:

- Implemented and tested.
- Stable enough for consumer use across a release cycle.
- Used internally by at least one PyTCP component (e.g.
  the DHCPv4 client uses the Address API; the link-local
  autoconfig client uses the Address API + Sysctl
  registry; integration tests use Sysctl + Socket
  surfaces).
- Documented in this directory with the canonical
  consumer-facing reference.

A surface marked **partial** has some functionality
exposed but the design is incomplete. The doc lists what
works today and what is deferred.

A surface marked **not yet** does not exist as code; the
doc captures the intent + Linux analogue so future work
has a starting point.

## What's deliberately NOT here

Per CLAUDE.md's Project North Star "explicit non-goals":

- Hardware offloads, XDP / AF_XDP, kernel-bypass paths.
- Netfilter / eBPF / nftables hooks.
- Crypto extensions (AH, ESP, IPsec, MACsec).
- Mobility extensions (MIPv6, NEMO, RH2 mobility
  processing).
- Userspace routing protocols (BGP, OSPF, RIP).

These are out of scope regardless of phase.

## Doc structure (template)

Each per-API doc follows the same shape:

1. **Header table** — module path, Linux equivalent,
   status, plan / refactor docs.
2. **Purpose** — what the surface is for; who consumes it.
3. **Read surface** — properties / list methods. Type
   signatures + return semantics.
4. **Mutation surface** — methods that change state. Type
   signatures + preconditions + side effects.
5. **Examples** — copy-pasteable consumer snippets.
6. **Deferred / out of scope** — what won't ship in
   Phase-1, with rationale.
7. **Plan / history** — pointers to the relevant refactor
   docs + the canonical commits that built the surface.

## Cross-references

- **CLAUDE.md** — Project North Star, Phase-3 design
  implications (the source of truth for these surface
  boundaries).
- **Per-RFC adherence records** — `docs/rfc/<family>/rfcXXXX__<name>/adherence.md`.
- **Refactor plans** — the `docs/refactor/*.md` track that
  built each surface, e.g. [`link_api.md`](../refactor/link_api.md),
  [`address_api_unification.md`](../refactor/address_api_unification.md),
  [`routing_table_host_mode.md`](../refactor/routing_table_host_mode.md),
  [`rfc3927_link_local_autoconfig.md`](../refactor/rfc3927_link_local_autoconfig.md),
  and [`dhcp4_client_full_parity.md`](../refactor/dhcp4_client_full_parity.md).
