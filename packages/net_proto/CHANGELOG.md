# Changelog

All notable changes to **PyTCP-net_proto** are recorded here. This
package (the protocol packet library — parse / assemble / validate) is
released in lockstep with `PyTCP` and `PyTCP-net_addr` — they share a
version. Releases before 3.0.8 are on the
[GitHub Releases page](https://github.com/ccie18643/PyTCP/releases).

## 3.0.9 — 2026-08-09

### Added

- **IGMP / MLD Query assemblers.** The `IgmpMessageQuery`,
  `Icmp6Mld2MessageQuery`, and `Icmp6Mld1MessageQuery` codecs now
  serialise their wire forms (previously RX-parse-only), plus the
  RFC 3376 §4.1.1 Max Resp Code / QQIC float-code encoder
  (`encode_igmp_float_code`) — the wire support the Phase-2 IGMPv3 /
  MLDv2 multicast-router querier emits in `PyTCP` 3.0.9.
- **ICMPv4 Redirect message codec.** A new `Icmp4Type.REDIRECT = 5`
  message class (`icmp4__message__redirect.py`) with `Icmp4RedirectCode`
  and the full parser / assembler / unit-test matrix — the wire support
  the Phase-2 IPv4 router emits (ICMP Redirect generation) in `PyTCP`
  3.0.9.

## 3.0.8 — 2026-07-23

### Added

- **DNS message codec** — a new `dns/` protocol family: enums, header,
  name codec, question / resource-record parser and assembler, with
  name-bearing and structured RDATA decoded into typed objects. Backs
  the `pytcp host` DNS-lookup tool.

### Changed

- IPv4 / IPv6 parsers accept loopback-sourced / own-IP packets (a
  `from_loopback` flag on `PacketRx`), supporting the stack-internal
  loopback interface added in `PyTCP` 3.0.8.

### Tests & tooling

- Mutation-audit hardening: a broad sweep of kill-proven tests closing
  real gaps across TCP (options, AccECN, Fast Open, option walkers),
  UDP checksum handling, ICMPv4 / ICMPv6 message length and
  trailing-padding tolerance, IPv4 / IPv6 parser bounds, DHCPv4 /
  DHCPv6 option-code guards, and DNS header flag distinctness.
- The `Buffer` alias moved to `net_addr` (the dependency-graph bottom).
- Typing modernization: gratuitous string-quoted annotations dropped,
  forbidden override-ignores refactored, 8 more mypy strict error codes
  enabled.

### Compatibility

Requires Python 3.14+. Depends on `PyTCP-net_addr==3.0.8`.
