# PyTCP-net_addr

An alternative to Python's standard-library `ipaddress` module —
originally built for the [PyTCP](https://github.com/ccie18643/PyTCP)
TCP/IP stack, fully usable on its own.

```python
from net_addr import Ip6Address, Ip4Network, Ip4Address, MacAddress

Ip6Address("2001:db8::1").is_global                 # True
Ip4Network("10.0.0.0/24")[10]                       # Ip4Address("10.0.0.10")
MacAddress("02:00:00:00:00:07").is_multicast        # False
Ip4Address("10.0.0.1") in Ip4Network("10.0.0.0/8")  # True
```

## Why

A correct, immutable, strict-parsing address library with no runtime
dependencies and a single clean exception tree — suitable for protocol
stacks, network tooling, and anywhere `ipaddress` is too loose or does
not give you hashable / orderable / MAC / wildcard / interface-address
value types.

## Features

- **Value types** — `Ip4Address`, `Ip6Address`, `MacAddress`,
  `Ip4Network` / `Ip6Network`, `Ip4Mask` / `Ip6Mask`,
  `Ip4Wildcard` / `Ip6Wildcard` (ACL / firewall, non-contiguous),
  `Ip4IfAddr` / `Ip6IfAddr`.
- **Immutable & efficient** — `__slots__`, hashable, totally
  ordered, `@final` leaves; equality never crosses address families.
- **Multi-form constructors** — string, integer,
  `bytes` / `bytearray` / `memoryview`, copy, or unspecified, via one
  positional argument.
- **Strict parsing** — POSIX `inet_pton` only; legacy octal / hex /
  short-form leniencies and hybrid MAC separators are rejected.
- **RFC-accurate classification** — global / private / link-local /
  loopback / multicast / documentation / reserved; RFC 4007 IPv6
  zone identifiers; IPv4-mapped, 6to4 and Teredo extraction.
- **CIDR arithmetic** — `subnets()`, `supernet()`,
  `address_exclude()`, `hosts()`, RFC 4632 `summarize()`,
  containment and overlap.
- **IPv6 interface-identifier generators** — EUI-64, RFC 7217
  stable-privacy, RFC 8981 temporary; solicited-node multicast and
  multicast-MAC mapping.
- **Rich formatting** — expanded form, MAC hyphen / Cisco notations,
  zero-padded radix, reverse-DNS PTR names.
- **One exception tree** — every failure is a `NetAddrError`
  subclass; never a bare builtin.
- **Fully typed** — ships `py.typed` (PEP 561); strict-mypy clean.

## Type hierarchy

Two ABC roots — `Base` (the value-type contract: `__str__` / `__repr__`
/ `__eq__` / `__hash__`) and `Ip` (the IP-version mixin: `version` /
`is_ip4` / `is_ip6`, mixed into every IP-versioned family but **not**
`MacAddress`). Concrete leaves are `@final`:

```
Base                         value-type contract
Ip                           IP-version mixin

Address(Base)
├── IpAddress(Address, Ip)
│   ├── Ip4Address  @final
│   └── Ip6Address  @final
└── MacAddress      @final   (no Ip mixin — a MAC has no IP version)

IpNetwork[A, M](Base, Ip)    ├── Ip4Network  @final   └── Ip6Network  @final
IfAddr[A, N](Base, Ip)       ├── Ip4IfAddr   @final   └── Ip6IfAddr   @final
IpMask(Base, Ip)             ├── Ip4Mask     @final   └── Ip6Mask     @final
IpWildcard(Base, Ip)         ├── Ip4Wildcard @final   └── Ip6Wildcard @final

IpVersion                    IntEnum (IP4 / IP6)
```

The generics use PEP 695 syntax: `IpNetwork[A, M]` is parameterised
over its address and mask type, `IfAddr[A, N]` over its address and
network type. `@final` on every leaf is load-bearing — the
`isinstance(other, type(self))`-based `__eq__` / `__hash__` is
symmetric and hash-consistent only for non-subclassable leaves.

## Public API

`from net_addr import …` exposes the concrete value types, the ABCs
(for typing), the `IpVersion` enum, the length constants
(`IP4__ADDRESS_LEN`, `IP6__ADDRESS_LEN`, `MAC__ADDRESS_LEN`), and the
full `*Error` tree. The opt-in `ClickType*` argument types
(`ClickTypeIp4Address`, `ClickTypeIp6IfAddr`, …) are re-exported
lazily — `from net_addr import ClickTypeIp4Address` works but pulls in
`click` only on first access, so the base import stays stdlib-only.

`Ip4IfAddr` / `Ip6IfAddr` are **pure `(address, network)` value
pairs** — there is no mutable per-address metadata. A default gateway
is *not* interface-address state: it is routing state, owned by the
consuming stack's routing table (FIB) / Route API. Mutating a value
type means constructing a fresh instance, never assigning to a field.

## Exception model

One tree, three catchable supersets per leaf, never a bare builtin:

```
NetAddrError
├── IpAddressError / IpNetworkError / IfAddrError / IpMaskError / IpWildcardError
│     ├── <axis> base ...FormatError   (construction failed — bad literal)
│     ├── <axis> base ...SanityError   (precondition / invariant / range / format-code)
│     └── per-type umbrellas: Ip4AddressError, Ip6NetworkError, ...
└── MacAddressError → MacAddressFormatError / MacAddressSanityError
```

`*FormatError` is construction failure; `*SanityError` is everything
else (a precondition such as `multicast_mac` on a non-multicast
address, a bad `subnets()` / `address_exclude()` argument, an
out-of-range `network[i]`, an unknown `__format__` code). Mask and
wildcard types have a Format axis only — they can fail only at
construction. PyTCP does **not** mirror stdlib `ipaddress`'s
`ValueError` / `IndexError`: catch `NetAddrError` (or a precise
subclass) instead.

## Installation

```bash
pip install PyTCP-net_addr
```

Stdlib-only. The optional Click argument types are an extra:

```bash
pip install "PyTCP-net_addr[cli]"   # adds click; exposes the net_addr ClickType* params
```

## Requirements

Python **3.14+** (the library uses PEP 695 generics and modern
typing).

## Current state (3.0.8)

- 23 source modules; **2636 unit tests**, ~99% source coverage (the
  remaining lines are `@abstractmethod` stub bodies, a documented
  unreachable `NoReturn` guard, and the lazy-`click` `__getattr__`
  exercised in subprocess probes).
- Addressing-RFC fidelity (RFC 4291 scopes, 5952 canonical text, 4007
  zones, 1918 / 4193 classification, 7217 / 8981 IID generation) is
  encoded **in code + unit tests**, not in `docs/rfc` — by design,
  since this is a value-type library, not a wire protocol. The
  authoring contract lives in
  [`.claude/rules/net_addr.md`](https://github.com/ccie18643/PyTCP/blob/master/.claude/rules/net_addr.md).

## License

GPL-3.0-or-later. Part of the PyTCP project by Sebastian Majewski.
