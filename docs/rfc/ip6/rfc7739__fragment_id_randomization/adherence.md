# RFC 7739 — Security Implications of Predictable Fragment Identification Values

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7739                                              |
| Title       | Security Implications of Predictable Fragment Identification Values |
| Category    | Informational                                     |
| Date        | February 2016                                     |
| Source text | [`rfc7739.txt`](rfc7739.txt)                      |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 7739 for the IPv6 TX
path. The IPv6 fragmentation emit site
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__tx.py::_phtx_ip6_frag`)
draws a fresh 32-bit Fragment Identification per outbound
datagram from `secrets.randbelow(2**32)` — Python's
cryptographic-quality random source.

The previous implementation used a stack-wide monotonic
`+1` counter (`PacketHandler._ip6_id`), which made the
next Fragment Identification trivially predictable. RFC
7739 §5 surveys the attack vectors enabled by predictable
Fragment IDs (off-path injection, fragmentation-DoS, and
identity-correlation across packets) and recommends
moving to randomized values. Combined with PyTCP's
existing strict-overlap policy (RFC 5722 §3, commit
`604eebbf`) and atomic-fragment isolation (RFC 6946 §4,
commit `909c3e06`), randomization closes the remaining
ID-collision attack surface.

The `_generate_ip6_frag_id()` helper is a module-level
function rather than a method so the test infrastructure
in `packages/pytcp/pytcp/tests/lib/network_testcase.py` can override it
with a deterministic counter — fixture-based integration
tests that bake specific Identification values into wire-
frame fixtures retain their existing IDs.

The IPv4 TX side **still uses a monotonic counter**
(`PacketHandler._ip4_id`); RFC 7739 covers v4 ID
predictability too, but its parent classification in RFC
8504 is v6-specific and the IPv4 16-bit ID has different
collision characteristics (RFC 6864). This record
documents the v6 side as shipped and the v4 side as out
of scope.

---

## §1 Introduction

> "An attacker who can guess the next Fragment Identification
> value used by a victim host ... can inject malicious
> fragments..."

**Adherence:** N/A (motivation). PyTCP's randomized v6
generator removes the predictability that enables the
attacks the section describes.

## §3-§4 Algorithm Surveys

> "Linear / sequential generators ... predictable
> Identifier ... per-destination predictable ..."

**Adherence:** N/A (analysis of vulnerable algorithms).
PyTCP's previous monotonic counter falls into the §3.1
"Predictable" category; the post-`secrets.randbelow(2**32)`
implementation matches §4.1 "Random per-packet".

## §5 Mitigations — the normative recommendation

> "All these algorithms produce Fragment Identification
> values that are very hard for an attacker to predict."

**Adherence:** shipped. The `secrets` module uses
`os.urandom()` underneath (CPython implementation), which
is the system's cryptographic-quality random source —
satisfying §5.1's "cryptographic random" requirement.

> "Note that some implementations (e.g., Linux) use a
> different Fragment Identification counter for each
> {Source Address, Destination Address} tuple..."

**Adherence:** PyTCP picks a single per-burst value from
the global random source rather than a per-tuple PRNG.
Both approaches satisfy §5: per-tuple PRNG is more
sophisticated but the simple per-burst random pick has
better birthday-collision properties for typical traffic
volumes, since the entire 32-bit ID space is available
per draw rather than per (src, dst) tuple. Linux's
approach was arguably driven by the per-CPU counter
performance of `__ipv6_select_ident` — PyTCP has no such
contention concern.

---

## Test coverage audit

| Clause | Test file / class |
|--------|-------------------|
| Per-burst randomization (not monotonic +1) | `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6_frag__tx.py::TestPacketHandlerIp6FragTx::test__stack__packet_handler__ip6_frag__tx__frag_id_is_randomized_per_burst` |
| ID stable within a burst (all fragments share one ID) | Same class :: `test__stack__packet_handler__ip6_frag__tx__id_shared_within_burst` |
| Existing fixture-driven tests retain known IDs via `NetworkTestCase` patch | `packages/pytcp/pytcp/tests/lib/network_testcase.py::NetworkTestCase.setUp` (patches `_generate_ip6_frag_id` with a deterministic counter) |

The randomization assertion uses a 10-draw sequence and
asserts that the deltas are not all `+1`. Probability of
a 10-draw uniform sample producing every-delta-of-1 is
≈ 1 in 2^288 — vacuously zero in practice.

---

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.1
  — parent classification (SHOULD)
- `docs/rfc/ip6/rfc5722__overlapping_fragments/adherence.md`
  — companion shipped record (overlap detection
  eliminates one of the predictable-ID attack vectors)
- `docs/rfc/ip6/rfc6946__atomic_fragments/adherence.md` —
  companion shipped record (atomic-fragment isolation
  eliminates another predictable-ID vector)
- Implementing commit: TBD (this commit)
