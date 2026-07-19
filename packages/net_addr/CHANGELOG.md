# Changelog

All notable changes to **PyTCP-net_addr** are recorded here. This
package (the standalone address value-type library) is released in
lockstep with `PyTCP` and `PyTCP-net_proto` — they share a version.
Releases before 3.0.8 are on the
[GitHub Releases page](https://github.com/ccie18643/PyTCP/releases).

## 3.0.8 — 2026-07-19

### Changed

- The `Buffer` alias (`bytes | bytearray | memoryview`) now lives here,
  in `net_addr` — the bottom of the dependency graph and its canonical
  home.
- `Address`'s per-leaf value-type contract is now properly abstract.

### Tests & tooling

- Mutation-audit hardening: kill-proven tests pinning the RFC 5453
  reserved-IID predicate, `from_rfc7217` golden vectors, the MAC I/G
  bit, wildcard application, `IpNetwork` subnetting / overlap / merge /
  `summarize` boundaries, total-ordering directions, and `__format__`
  width / unknown-spec rejection.
- Typing modernization: gratuitous string-quoted annotations dropped,
  8 more mypy strict error codes enabled, `@override` enforced on all
  test fixture hooks.

### Compatibility

Requires Python 3.14+. No runtime dependencies (stdlib only; the
`click` CLI helpers remain an opt-in `[cli]` extra).
