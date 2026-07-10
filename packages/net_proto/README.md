# PyTCP-net_proto

The network-protocol packet **parse / assemble / validate** layer of
the [PyTCP](https://github.com/ccie18643/PyTCP) TCP/IP stack —
extracted as its own distribution and usable on its own.

```python
from net_proto import IpProto
from net_proto.protocols.udp.udp__parser import UdpParser
from net_proto.protocols.udp.udp__assembler import UdpAssembler

datagram = UdpAssembler(udp__sport=12345, udp__dport=53, udp__payload=b"query")
parsed = UdpParser(packet_rx)          # raises UdpIntegrityError / UdpSanityError on bad wire input
```

## Why

Strict, RFC-grounded, fully-typed wire-format codecs for the
common Internet protocols, with a single clean validation-error
tree and no runtime dependencies beyond the address library it is
built on.

## Protocol coverage

Each protocol is a parser / assembler pair over a frozen header
dataclass, with integrity + sanity validation and typed wire enums.

| Family | Governing RFC(s) |
|---|---|
| Ethernet II | RFC 894 / 7042 (EtherType) |
| IEEE 802.3 + LLC / SNAP | IEEE 802.3 / 802.2 / RFC 1042 |
| ARP | RFC 826 |
| IPv4 (+ options: LSRR/SSRR, RR, Timestamp, Router-Alert, CIPSO) | RFC 791 / 1108 / 2113 |
| IPv6 | RFC 8200 |
| IPv6 Hop-by-Hop / Destination Options (PadN, Jumbo, RouterAlert, Tunnel-Limit, CALIPSO) | RFC 8200 / 2675 / 2711 |
| IPv6 Routing / Fragment extension headers | RFC 8200 / 5095 |
| ICMPv4 | RFC 792 / 1122 |
| ICMPv6 | RFC 4443 |
| ICMPv6 Neighbor Discovery (+ options) | RFC 4861 / 8106 |
| ICMPv6 MLDv2 (+ MLDv1 compatibility) | RFC 3810 / 2710 |
| IGMP (host membership: IGMPv1/v2/v3 + source-specific) | RFC 1112 / 2236 / 3376 |
| TCP (+ options: MSS, WScale, SACK, Timestamps, AccECN, Fast-Open) | RFC 9293 / 2018 / 7323 / 9768 / 7413 |
| UDP | RFC 768 |
| DHCPv4 (+ options) | RFC 2131 / 2132 |
| DHCPv6 (+ options) | RFC 8415 |
| DNS (A / AAAA query + response, name compression) | RFC 1035 |

## The six-file pattern

Every protocol under `protocols/<proto>/` follows the same layout
(see [`.claude/rules/net_proto.md`](https://github.com/ccie18643/PyTCP/blob/master/.claude/rules/net_proto.md)):

- `<proto>__header.py` — the frozen `*Header` dataclass
  (`@dataclass(frozen=True, kw_only=True, slots=True)`) + the
  `*HeaderProperties` read-mixin + the RFC ASCII diagram + struct
  constants.
- `<proto>__base.py` — `*` base composing header (+ options +
  payload) with the shared dunders (`__len__` / `__str__` /
  `__repr__` / `__buffer__`).
- `<proto>__parser.py` — the three-phase RX pipeline:
  `_validate_integrity()` → `_parse()` → `_validate_sanity()`.
- `<proto>__assembler.py` — the keyword-only TX constructor +
  `assemble(buffers, /)` with checksum injection.
- `<proto>__errors.py` — the `*IntegrityError` / `*SanityError`
  pair.
- `<proto>__enums.py` + `options/` — protocol enums and TLV
  options where the protocol has them.

## Validation-error model

One two-axis tree, rendered with a canonical category + protocol
prefix so tests and logs match exactly:

```
PacketIntegrityError → "[INTEGRITY ERROR][<PROTO>] ..."   (structural / wire-shape)
PacketSanityError    → "[SANITY ERROR][<PROTO>] ..."      (logical invariant)
```

**Integrity vs sanity:** integrity checks run on the raw frame
before fields are trusted (length bounds, checksum, header
shape); sanity checks run on already-parsed fields (a port of 0,
a reserved-bit violation). Both raise typed `*Error`s — **never
`assert`** — so they survive `python -O` (assertions stripped),
because they defend against hostile wire input. Conversely,
`*Header.__post_init__` and `*Assembler.__init__` use `assert`
(programmer-error guards, OK to strip under `-O`); any
wire-reachable bound an `assert` guards is **mirrored** as a
typed raise in `_validate_integrity`. This wire-input vs
programmer-input discipline (rule §9.2) is AST-clean across the
package.

## Typed wire enums

Protocol codepoints are `ProtoEnumByte` / `ProtoEnumWord`
subclasses (`EtherType`, `IpProto`, `Icmp6Type`, `ArpOperation`,
…), never bare ints. Unknown wire codepoints are materialised
natively via the stdlib `enum.Enum._missing_` hook (an
`UNKNOWN_<value>` identity-stable pseudo-member) — no third-party
`aenum` dependency.

## Install

```bash
pip install PyTCP-net_proto
```

Depends only on `PyTCP-net_addr` (the address value-type
library) — no other runtime dependencies. Fully typed (ships
`py.typed`, PEP 561); strict-mypy clean.

## Requirements

Python **3.14+** (PEP 695 generics on the assembler stacking,
modern typing throughout).

## Current state (3.0.8)

- ~270 source modules; **6024 unit tests**, ~99% source coverage
  (the remaining lines are protocol dunders, `from_buffer`
  unpacking, and a few integrity-rejection branches with no
  dedicated rejection test — test-completeness, not defects).
- Per-RFC adherence records live in
  [`docs/rfc/`](https://github.com/ccie18643/PyTCP/tree/master/docs/rfc) (the wire-format header / parser
  / assembler / options rows are net_proto's surface). The
  parser RFC-adherence pass and the assembler audit pass are both
  CLOSED; follow-up audits A–L are complete (see
  `docs/refactor/net_proto_remaining_audits.md`).

## License

GPL-3.0-or-later. Part of the PyTCP project by Sebastian Majewski.
