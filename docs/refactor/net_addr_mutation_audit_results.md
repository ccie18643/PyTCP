# net_addr — Full Mutation-Test Audit (results)

Run date: 2026-06-07 → 2026-06-08, branch `PyTCP_3_0_8`.
Tool: cosmic-ray 8.4.6, whole `net_addr` package, full net_addr unit
suite (2 617 tests) as the per-mutant test-command, `ulimit -v 3 GB`,
per-mutant `timeout = 10 s`. Methodology + safety rails: see
[`net_addr_mutation_audit.md`](net_addr_mutation_audit.md).

**This document proposes corrections only — no fixes were applied, no
commits, no push.** `net_addr` source is pristine (`git diff --
packages/net_addr` empty).

---

## 1. Headline numbers

| Metric | Value |
|--------|-------|
| Source-only mutants (tests excluded) | 5 968 |
| Killed | 4 665 |
| Survived | 1 303 |
| **Raw mutation score** | **78.2 %** |
| Survivors that are **provably / structurally equivalent** | 917 |
| Survivors that are **genuine runtime mutants** (reviewable) | 386 |
| **Adjusted score** (excluding equivalent survivors) | **92.4 %** (4 665 / 5 051) |

The raw 78.2 % understates the suite. **70 % of the survivors (917 /
1 303) are equivalent mutants that no runtime test can kill** — a
structural artifact of running cosmic-ray against a heavily-annotated
Python 3.14 codebase (see §3). Excluding them, the effective score is
**92.4 %**, which is strong. The genuine gap surface is 386 mutants,
and it concentrates in two modules (§4).

No timeouts and no memory-bomb mutants occurred — every one of the
5 968 mutants completed with `WorkerOutcome.NORMAL`. The `ulimit -v`
cap and the full-suite runner both did their jobs; the trial-run
hazards (arithmetic `**` OOM, narrow-scope false positives) did not
recur.

---

## 2. Per-module score

| Survived / total | Score | Module |
|------------------|-------|--------|
| 285 / 353 | 19.3 % | `click_types.py` |
| 204 / 1046 | 80.5 % | `ip_network.py` |
| 142 / 1072 | 86.8 % | `ip6_address.py` |
| 104 / 488 | 78.7 % | `ip6_ifaddr.py` |
| 83 / 452 | 81.6 % | `address.py` |
| 73 / 374 | 80.5 % | `ip4_address.py` |
| 64 / 259 | 75.3 % | `mac_address.py` |
| 57 / 212 | 73.1 % | `ip6_mask.py` |
| 51 / 227 | 77.5 % | `ip4_mask.py` |
| 48 / 92 | 47.8 % | `ip6_wildcard.py` |
| 48 / 92 | 47.8 % | `ip4_wildcard.py` |
| 39 / 191 | 79.6 % | `ip_ifaddr.py` |
| 31 / 199 | 84.4 % | `ip_mask.py` |
| 30 / 114 | 73.7 % | `ip_wildcard.py` |
| 14 / 247 | 94.3 % | `ip4_network.py` |
| 10 / 261 | 96.2 % | `ip6_network.py` |
| 7 / 32 | 78.1 % | `ip_address.py` |
| 7 / 18 | 61.1 % | `base.py` |
| 4 / 17 | 76.5 % | `ip.py` |
| 2 / 62 | 96.8 % | `ip4_ifaddr.py` |
| 0 / 121 | 100 % | `errors.py` |
| 0 / 22 | 100 % | `buffer.py` |
| 0 / 13 | 100 % | `__init__.py` |
| 0 / 4 | 100 % | `ip_version.py` |

**`click_types.py`'s 19.3 % is almost entirely an artifact** — 275 of
its 285 survivors are PEP 604 union-annotation mutations (§3.1). Its
*runtime* surface (the 12 `convert` methods) is thin and its true gap
is tiny. Likewise the wildcard modules' 47.8 % is mostly equivalent
comparison mutants (§3.3), not real holes.

---

## 3. The equivalent-mutant classes (917 survivors — no correction possible)

These mutate the source but provably cannot change any runtime
behaviour a test could observe. They are the irreducible noise floor
of mutation-testing a modern typed Python codebase. Each is justified
below.

### 3.1 PEP 604 union annotations under PEP 649 lazy evaluation — 814 survivors

The single largest class. cosmic-ray rewrites the `|` in every
`X | Y` type annotation (`param: Parameter | None` →
`param: Parameter ** None`; `-> Ip6Address | Ip4Address` →
`-> Ip6Address / Ip4Address`; PEP 695 `type Buffer = bytes | …`
aliases likewise). Under **PEP 649 (Python 3.14 lazy annotations)**
these expressions are stored as un-evaluated `__annotate__` closures
and are *never executed at runtime* unless something calls
`typing.get_type_hints()` — which the net_addr unit suite never does.

So the mutated `Parameter ** None` annotation never runs; the mutant
survives every conceivable runtime test. **mypy strict + pyright are
the gate for these, and they are green.** A test cannot and should
not try to kill them.

Distribution: `click_types.py` 275 (its signatures are annotation-
dense), the rest spread across every module's method signatures and
class-attribute annotations.

> **This is the headline methodological finding.** Any future mutation
> run on PyTCP (all three packages are 3.14, annotation-dense) will
> show the same inflation. Treat union-annotation `|` survivors as a
> known-equivalent class and exclude them before reading the score.

### 3.2 Type-checker-only decorators — 99 survivors

`RemoveDecorator` removing a decorator that has **zero runtime
effect**:

- **`@override` — 73.** Pure PEP 698 marker; removing it changes
  nothing at runtime (only mypy's `explicit-override` notices).
- **`@overload` — 2.** Type-only; the real implementation follows.
- **`@abstractmethod` — 18.** Removing *one* from a class that has
  *other* abstract methods leaves the class abstract, so
  `test__abstract_stubs.py`'s "cannot instantiate" assertion still
  passes. (Removing the *last* one would be killable, but net_addr's
  ABCs each declare several.) Treated as equivalent in practice.

These are killable only by a type checker, not a unit test — and
mypy/pyright already enforce them.

### 3.3 Comparisons on interned / singleton operands — a subset of the comparison survivors

`==` → `is` on small interned ints (`len(x) == 4` → `len(x) is 4`,
True for CPython small-int interning) and on `IpVersion` enum members
(`self.version == other.version` → `self.version is other.version`,
identical for enum singletons). These appear throughout the wildcard
and address `__eq__`/version-guard paths and inflate those modules'
survivor counts. Equivalent — the `is`/`==` distinction is invisible
for interned operands.

### 3.4 Disjoint-bitfield combiners — a subset of the EUI-64 / IID `|` survivors

In `from_eui64`, the three fields combined with `|` occupy disjoint
byte ranges by construction (high-MAC `<<16` in bytes 0-2, the
`0xFFFE` marker in bytes 3-4, low-MAC in bytes 5-7), and the final
`prefix | interface_id` combines a /64-masked prefix (low 64 bits
zero) with a < 2⁶⁴ IID. When operands share no set bits, `|`, `^`,
and `+` are identical, so `BitOr_BitXor` / `BitOr_Add` on those sites
are equivalent regardless of input. (The `&` masks on the same lines
are *not* equivalent and were correctly killed.)

---

## 4. The genuine gap surface (386 runtime survivors)

After removing the equivalent classes, the reviewable survivors
localize sharply:

| Review survivors | Module | Where |
|------------------|--------|-------|
| 134 | `ip_network.py` | network-algebra methods (§4.1) |
| 102 | `ip6_ifaddr.py` | the 3 IID generators (§4.2) |
| 35 | `ip_ifaddr.py` | base-class construction / containment |
| 25 | `ip6_address.py` | scope / multicast predicates |
| 20 | `address.py` | `__eq__` / `__int__` / `__buffer__` paths |
| ~70 | everything else | diffuse comparison / number mutants |

Two modules account for 60 % of the genuine surface.

### 4.1 `ip_network.py` — under-pinned network algebra (134) — **biggest real gap**

The algorithmically-rich methods are tested for a few cases but their
internal arithmetic is not pinned. Survivor concentration by method:

| Survivors | Method | Surviving-mutation character |
|-----------|--------|------------------------------|
| 29 | `_summarize_ints` | `align = bits if lo == 0 else (lo & -lo).bit_length() - 1` (L107) alone carries 24 — the alignment/block-size arithmetic of `summarize()` is barely exercised |
| 15 | `subnets` | `prefixlen_diff = new_prefix - prefixlen` (L407) ×11 — subnet-count arithmetic |
| 11 | `address_exclude` | the `while s1 != other and s2 != other` exclusion loop (L486/496/498) |
| 10 | `_merge_spans` | `merged[-1] = (…, max(merged[-1][1], hi))` (L124) — adjacent-span merge |
| 10 | `__contains__` | `int(self.address) <= int(other) <= int(self.last)` (L263/266) — **boundary not tested** (kill-proven, §5.2) |
| 24 | `__lt__/__le__/__gt__/__ge__` | `(int(addr), int(mask)) ⊕ (…)` — the **mask tiebreak** (same address, different prefix length) is not tested |
| 9 | `__format__` | `format_spec[-1:] == "s"` and width arithmetic |
| 6 | `overlaps` | `int(self.address) <= int(other.last)` boundary |
| 4 | `subnet_of`, 4 `__getitem__`, 3 `supernet`, 4 `_mask_int` | misc boundary / arithmetic |

`ip4_network.py` (94.3 %) and `ip6_network.py` (96.2 %) score well
because the *concrete* subclasses are well-tested; the gap is in the
**shared generic `IpNetwork` base**, whose algebra is only reachable
via a concrete subclass and is exercised on too few inputs.

### 4.2 `ip6_ifaddr.py` — IID generators (102), mixed real-gap and inherent-equivalent

| Survivors | Generator | Verdict |
|-----------|-----------|---------|
| 33 | `from_eui64` | **Real gap, kill-proven (§5.1):** the test uses a degenerate MAC (`02:00:00:11:22:33`, OUI all-zero) *and* a degenerate prefix (`2001:db8::/64`, bits only in the top 16). Netmask-arithmetic mutants on the `(1<<128)-(1<<64)` combine survive because the prefix has no bits in positions 16-63. A non-degenerate MAC + a full-/64 prefix kills most of these. The remaining disjoint-bitfield `|`→`^`/`+` mutants are equivalent (§3.4). |
| 35 | `from_rfc7217` | **Mixed:** shares the same prefix-coverage gap on the masked-combine step (killable with a full prefix). The mutants *inside* the SHA-256 hash digest arithmetic are effectively equivalent unless a test recomputes the exact RFC 7217 hash and asserts the byte-exact IID — worth one such golden-vector test. |
| 28 | `from_rfc8981_temp` | **Largely inherent-equivalent:** the IID is a `secrets`-random draw, so tests can only assert structural properties (length, U/L + `u`/`g` bits, RFC 5453 reserved-range avoidance). Arithmetic mutants that change *which* random IID is produced are un-killable by a non-deterministic-output test. Only the reserved-range rejection logic (`_is_reserved_iid`) is deterministically pin-able. |

---

## 5. Kill-proven proposed corrections

Two representative gaps were verified the safe way (apply the real
survivor mutation by hand → confirm the existing test passes / the
new assertion fails → revert + clear `__pycache__`).

### 5.1 `from_eui64` (and `from_rfc7217`) — non-degenerate fixtures — **KILL-PROVEN**

**Survivor mutation reproduced:** `((1 << 128) - (1 << 64))` →
`((1 << 128) - (1 << 65))` (a real `NumberReplacer` survivor on
`ip6_ifaddr.py:165`).

- Under the mutation, the existing test fixture
  (`02:00:00:11:22:33` in `2001:db8::/64`) still yields
  `2001:db8::ff:fe11:2233` → **mutant survives**.
- A full-/64 prefix exposes it: `02:00:00:11:22:33` in
  `2001:db8:aaaa:bbbb::/64` yields `2001:db8:aaaa:bbba:0:ff:fe11:2233`
  under the mutation vs the correct `2001:db8:aaaa:bbbb:0:ff:fe11:2233`
  → **a test asserting the correct value kills it.**

**Proposed test** — add parametrized cases to
`TestNetAddrIp6HostFromEui64` in
`packages/net_addr/net_addr/tests/unit/test__ip6_ifaddr.py`:

```python
def test__net_addr__ip6_host__from_eui64__non_degenerate(self) -> None:
    """
    Ensure 'from_eui64()' embeds every MAC byte and every prefix
    bit — a non-degenerate MAC (bits in every octet) in a fully
    populated /64 so a corrupted netmask, U/L flip, or field
    placement changes the result.

    Reference: RFC 4291 §2.5.1 (modified EUI-64 IIDs).
    """

    # aa:bb:cc:dd:ee:ff — the canonical EUI-64 vector; U/L flip aa->a8.
    host = Ip6IfAddr.from_eui64(
        mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
        ip6_network=Ip6Network("2001:db8:aaaa:bbbb::/64"),
    )
    self.assertEqual(
        host.address,
        Ip6Address("2001:db8:aaaa:bbbb:a8bb:ccff:fedd:eeff"),
        msg="EUI64 must flip the U/L bit, insert FF:FE, and keep the full /64 prefix.",
    )
```

Add a second vector (`12:34:56:78:9a:bc` in `fe80::/64` →
`fe80::1034:56ff:fe78:9abc`) to harden the U/L flip across a different
first octet. The same non-degenerate-prefix principle applies to the
`from_rfc7217` tests.

### 5.2 `IpNetwork.__contains__` — boundary addresses — **KILL-PROVEN**

**Survivor mutation reproduced:**
`int(self.address) <= int(other) <= int(self.last)` →
`… <= int(other) < int(self.last)` (a real `LtE_Lt` survivor on
`ip_network.py:263`).

- Under the mutation, `Ip4Address("10.0.0.255") in Ip4Network("10.0.0.0/24")`
  returns **False** (correct: True) — a test asserting the last
  address is contained **kills it**.
- A mid-range address (`10.0.0.1`) stays True under the mutation, so
  the existing tests (which only check mid-range membership) let it
  survive.

**Proposed test** — extend the `__contains__` matrix in
`packages/net_addr/net_addr/tests/unit/test__ip4_network.py` (and the
IPv6 sibling) with the two boundary cases:

```python
# network address itself (lower boundary) and last/broadcast
# address (upper boundary) must both be contained.
{"_member": "10.0.0.0",   "_network": "10.0.0.0/24", "_result": True},
{"_member": "10.0.0.255", "_network": "10.0.0.0/24", "_result": True},
# one below / one above are NOT contained.
{"_member": "9.255.255.255", "_network": "10.0.0.0/24", "_result": False},
{"_member": "10.0.1.0",      "_network": "10.0.0.0/24", "_result": False},
```

The lower/upper *exclusion* cases also kill the symmetric
`int(self.address) <= other` → `<` mutant.

---

## 6. Proposed corrections — analysis-backed (not individually kill-proven)

High-leverage, derived from the §4 survivor concentration. Each closes
a cluster; none was individually kill-proven (the two above validate
the method).

| Priority | Module / method | Proposed test addition |
|----------|-----------------|------------------------|
| 1 | `ip_network.py` `summarize` / `_summarize_ints` | Parametrized matrix over ranges with **varied alignment**: a single host, a power-of-two-aligned block, a misaligned range that must split into several CIDRs, an empty/inverted range. Assert the exact returned CIDR list. Kills the 24 L107 alignment-arithmetic mutants. |
| 2 | `ip_network.py` `__lt__`/`__le__`/`__gt__`/`__ge__` | Add **same-address, different-mask** pairs (`10.0.0.0/24` vs `10.0.0.0/25`) so the mask tiebreak is pinned — currently only different-address pairs are tested, leaving the second tuple element's comparison unkilled. |
| 3 | `ip_network.py` `address_exclude` | Cases where the excluded network is at the **low edge, high edge, and middle** of the parent, plus exclude-equals-self and exclude-not-contained. Pins the `s1 != other` / `s2 != other` loop. |
| 4 | `ip_network.py` `subnets` / `supernet` | Assert the exact subnet **list and count** for a multi-bit `prefixlen_diff` (e.g. `/24` → `/26` = 4 subnets) — kills the L407 `new_prefix - prefixlen` arithmetic mutants. |
| 5 | `ip_network.py` `_merge_spans` (via `summarize`/`collapse`) | Adjacent (`10.0.0.0/25` + `10.0.0.128/25`), overlapping, and gapped span sets — pins the `max(...)`/`+ 1` merge arithmetic. |
| 6 | `ip_network.py` `__format__` | One case per format spec the method supports (`s`, width, the default) asserting the exact string — kills the L331 `format_spec[-1:] == "s"` cluster. |
| 7 | `ip6_ifaddr.py` `from_rfc7217` | One byte-exact golden vector (fixed prefix + MAC + secret + dad_counter → known IID) so the SHA-256-fed arithmetic is pinned. |
| 8 | `ip6_ifaddr.py` `_is_reserved_iid` | Cases at each RFC 5453 reserved-range edge (Subnet-Router anycast `…:0:0:0:0`, the reserved `…fdff:ffff:ffff:ff80`–`…ffff` block) asserting accept/reject. |
| 9 | `mac_address.py` (75.3 %) | Review the `__eq__`/multicast/broadcast-bit predicate survivors; add the bit-boundary cases. |
| 10 | `ip_wildcard.py` / `ip*_wildcard.py` | The real (non-equivalent) survivors are in `__or__`/`__ror__` application and the `__eq__` `>=`/`<=` mutants — assert wildcard-apply results and unequal-wildcard inequality. |

---

## 7. Overall assessment

`net_addr`'s test suite is **strong** — a 92.4 % equivalent-adjusted
mutation score over 5 968 mutants, with `errors.py`, `buffer.py`,
`__init__.py`, `ip_version.py`, and the concrete `ip4_network` /
`ip6_network` / `ip4_ifaddr` modules at or near 100 %. The construction
/ format / equality / hashing contracts of the value types are
well-pinned.

The genuine weakness is narrow and clear:

1. **The generic `IpNetwork` base's network-algebra methods**
   (`summarize`, `subnets`, `address_exclude`, `_merge_spans`,
   partial-order comparison, `__contains__` boundaries, `__format__`)
   are under-pinned — tested for representative cases but not for the
   arithmetic/boundary edges. This is the single highest-value place
   to add tests (§5.2, §6 rows 1-6).
2. **The IPv6 IID generators** use degenerate fixtures
   (`from_eui64`, `from_rfc7217`) — easily hardened with non-degenerate
   MAC + full-/64 prefix vectors (§5.1) — and one inherently-random
   generator (`from_rfc8981_temp`) whose arithmetic is not unit-pinnable
   by design (only its structural invariants are).

Recommended order: land §5.1 and §5.2 first (kill-proven, small,
high-confidence), then work §6 rows 1-6 (the `ip_network` algebra) as
the main push. Everything else is either equivalent noise (§3) or
low-yield.

**Methodology note for future PyTCP mutation runs:** always compute the
equivalent-adjusted score. On this 3.14, annotation-dense codebase the
PEP 604/649 union-annotation class (§3.1) alone depresses the raw score
by ~14 points and will recur on `net_proto` and `pytcp`. cosmic-ray has
no annotation-aware operator filter, so the adjustment is manual — the
classifier query in this audit (signature-line detection on
`ReplaceBinaryOperator_BitOr_*`) is the reusable tool.
