# net_proto — Mutation-Test Audit Plan

**Goal.** Mutation-test the entire `net_proto` package, triage
survivors (equivalent vs real gap), and close the real gaps with
kill-proven unit tests — the same exercise as the net_addr audit, scaled
up ~4.5× and re-shaped for net_proto's structure.

**This plan does NOT restate the methodology.** All the rails, the
equivalent-mutant classes, the kill-proof discipline, the results-doc
shape, and the self-verification checklist live in the
[`mutation_testing` skill](../../.claude/skills/mutation_testing/SKILL.md).
**Read the skill first; this document is the net_proto-specific
delta** — scale strategy, shard layout, prioritization, and the
equivalence/gap classes peculiar to wire codecs.

The net_addr audit is the worked precedent:
`docs/refactor/net_addr_mutation_audit.md` (runbook) and
`…_results.md` (results, 78.2 %→80.5 % raw, 92.4 %→95.2 % adjusted, then
killable-surface complete).

---

## 0. Measured baseline (2026-06-08, branch `PyTCP_3_0_8`)

| Fact | net_proto | (net_addr for scale) |
|---|---|---|
| Source modules | 270 | 24 |
| Source lines | 38 166 | 4 894 |
| **Source-only mutants** | **27 007** | 5 968 |
| Test modules | 271 | — |
| Full unit suite | **5 803 tests, ~0.30 s** (0.6 s wall) | 2 617, 0.20 s |
| Per-protocol suite (udp) | 78 tests, 0.005 s (0.18 s wall) | — |

Per-mutant cost is dominated by **interpreter startup (~0.15 s)**, not
the tests. A single serial full-package scan ≈ 27 007 × ~0.6 s ≈
**4.5 h**. Sharding per protocol with a per-protocol test scope cuts the
per-mutant wall to ~0.18 s → **~1.3 h** of compute, and lets you
prioritize / stop early.

### Mutant hot-spots (where to expect both volume and gaps)
```
667  protocols/dhcp4/options/dhcp4__options.py
516  protocols/dhcp4/options/dhcp4__option__classless_static_route.py
483  protocols/ip4/options/ip4__option__timestamp.py
431  protocols/dns/dns__header.py          422  protocols/tcp/tcp__header.py
397  protocols/igmp/message/igmp__message__query.py
367  protocols/ip4/ip4__header.py          362  protocols/dhcp6/options/dhcp6__options.py
325  protocols/icmp6/.../nd__option__dnssl.py
324  lib/inet_cksum.py                     323  lib/int_checks.py
308  protocols/ip4/options/ip4__option__cipso.py
```

---

## 1. The load-bearing structural insight — protocols are independent

In net_addr everything shares one flat namespace, so the test-command
had to be the **whole** package suite (rail #2). net_proto is
different: **each protocol's source is exercised only by that
protocol's own tests** (`tests/unit/protocols/<proto>/…`). A udp parser
mutant cannot be killed by a tcp test, and vice-versa. So a
**per-protocol test scope is the CORRECT scope, not a dangerous
narrowing** — it does not produce the false-positive survivors rail #2
warns about.

The **one exception is `lib/`** (`inet_cksum`, `int_checks`,
`proto_struct`, `proto_enum`, `proto_parser`, `proto_assembler`,
`buffer`, …) — shared by every protocol. A `lib/` mutant must run the
**full** net_proto suite.

This gives the shard layout in §2.

---

## 2. Shard layout

One cosmic-ray DB + config per shard. **20 protocol shards + 1 lib
shard.** Each shard's `module-path` is the source subtree; each shard's
`test-command` is the matching test scope.

| Shard | `module-path` | test-command scope (the runner's `find`) |
|---|---|---|
| `<proto>` (×20) | `packages/net_proto/net_proto/protocols/<proto>` | `tests/unit/protocols/<proto>` **+** `tests/unit/lib` |
| `lib` | `packages/net_proto/net_proto/lib` | the **full** `tests/unit` suite |

Including `tests/unit/lib` in each protocol shard is cheap insurance:
a protocol mutant that only a lib-level test would catch (rare) still
gets killed. The protocol list (by priority, §3):

```
tcp ip4 ip6 udp icmp4 icmp6 arp ethernet            # P0 core codecs
ip6_frag ip6_hbh ip6_dest_opts ip6_routing          # P1 IPv6 ext headers
igmp dhcp4 dhcp6 dns                                 # P1 stateful/optional
ethernet_802_3 llc snap raw                          # P2 framing
lib                                                   # run LAST (full suite)
```

### Shard mechanics (per shard `<S>`)
Mirror the skill §3, with the scoped runner:
```bash
# runner /tmp/cr_<S>.sh  (ulimit cap, rail #1)
#!/bin/bash
ulimit -v 3145728
cd /root/PyTCP
PYTHONPATH=/root/PyTCP exec python -m unittest \
  $(find packages/net_proto/net_proto/tests/unit/protocols/<S> \
        packages/net_proto/net_proto/tests/unit/lib -name 'test__*.py')

# config /tmp/cr_<S>.toml
[cosmic-ray]
module-path = "packages/net_proto/net_proto/protocols/<S>"
timeout = 10.0
test-command = "bash /tmp/cr_<S>.sh"
[cosmic-ray.distributor]
name = "local"
```
Then: clear `__pycache__` → smoke the runner (must be OK) → `init` →
**delete any `%/tests/%` jobs from the sqlite** (rail #4; with a
protocol `module-path` there should be none, but verify) → `exec` in
background → watch memory.

**Run shards SEQUENTIALLY.** Concurrent `cosmic-ray exec` on the shared
checkout cross-contaminate each other's in-place mutations (net_addr
lesson) — a tcp shard mutating `tcp__parser.py` while a udp shard's
test run transitively imports tcp would mis-score. (Parallelism is
possible only with one `git worktree` per shard; not worth it here —
sequential is ~1.3 h.)

After **any** interrupted shard, `git status` / `git diff` the package
and `git checkout` any stranded mutant (rail #6 — this bit the net_addr
run).

---

## 3. Prioritization & stopping rule

Run P0 first (the core wire codecs carry the real correctness risk and
the bulk of consumers). After each shard, record raw + adjusted score
and the genuine-gap count. **Stop-early rule:** if three consecutive
shards yield zero genuine (non-equivalent) gaps, the suite is proven
strong there — skim the rest at lower priority. Conversely, the
options-heavy modules (dhcp4/ip4 options, dns/igmp) are the highest-
mutant and likeliest to harbor real arithmetic/TLV gaps; do not skip
them.

---

## 4. net_proto-specific EQUIVALENT classes (beyond the skill §4 list)

Expect the skill's nine classes (PEP 604 annotations will again be the
single biggest, and `@override` decorators are *everywhere* in the
six-file pattern). Add these net_proto-specific equivalents:

1. **`ProtoEnum.__str__` match/case return strings** — `case X:
   return "ARP"`. The human-readable name is rarely asserted verbatim,
   so `RemoveDecorator`/string-adjacent mutants on the `__str__` arms
   survive. Cosmetic; equivalent unless a test pins the exact string.
2. **`assert` in `__post_init__` MIRRORED by a typed raise in
   `_validate_integrity`** — net_proto.md §9.2 mandates that every
   wire-reachable `__post_init__` bound also be enforced by a
   `raise <Proto>IntegrityError` in the parser. When both exist, a
   mutation of the `__post_init__` assert condition is **backstopped**
   by the parser's typed raise (same class as net_addr's
   `_is_contiguous_mask`): the integrity test still fails on the wire,
   so the assert mutant looks killed — but the *assert itself* is
   redundant on that path. Treat assert-condition mutants as
   equivalent-by-backstop **only after confirming** the mirror exists;
   if it doesn't, the assert mutant is a REAL gap (and so is the
   missing mirror — flag it per §9.2).
3. **Bit-field packing in header `__buffer__`** — `self.hlen << 10 |
   flag_ns << 8 | …`. Disjoint shifted fields → `|` ≡ `^` ≡ `+`
   (skill §4 class 3). The shift *amounts* (`<< 10`) are NOT
   equivalent — a wrong shift corrupts the wire and a round-trip test
   kills it.
4. **`pshdr_sum` / checksum-zero-slot packing** — header `__buffer__`
   packs the cksum slot as `0`; the real cksum is injected later. A
   mutation of that literal `0` is overwritten downstream → equivalent.
5. **`struct` format-string constants** — cosmic-ray mutates code, not
   the *characters inside* a string literal, so `"! HH HH"` is not
   mutated char-by-char. NumberReplacer on a *numeric* struct
   offset/length used in slicing IS real.

---

## 5. net_proto-specific REAL-gap patterns to hunt

The §8 test matrix in `unit_testing.md` (header asserts / parser
integrity / parser sanity / parser operation / assembler operation /
options) makes the *baseline* strong — so, exactly as in net_addr, the
survivors cluster in the arithmetic and boundary details the matrix
doesn't fully pin:

- **Parser integrity/sanity comparison bounds** — the canonical
  net_proto bug class (the historical UDP `plen <` vs `<=` fix). A
  `<=`→`<` / `==`→`>=` on a length/offset check, killable only by a
  frame landing *exactly* on the boundary (min-valid and max-valid
  frames — the §8.4 "boundary-accepted" class is meant to catch these;
  mutation testing finds where it's incomplete).
- **Checksum offset literals** — the `buffer[6:8]` / `buffer[16:18]`
  cksum slice offsets and `inet_cksum(..., init=…)`. A wrong offset
  must break a round-trip test; if it survives, the round-trip isn't
  asserting the cksum bytes.
- **Options/TLV length & type arithmetic** — the dhcp4/ip4 options and
  the icmp6 ND options (the mutant hot-spots). Option length fields,
  `index + opt_len` walk arithmetic, padding-to-alignment — likely the
  richest real-gap seam.
- **Enum codepoint comparisons** — remember `ProtoEnum` is plain
  `Enum`, so `member == int` is False; tests must compare member-to-
  member. A `from_int` / `_missing_` boundary (known vs unknown
  codepoint) mutation needs a test with both an in-set and an
  out-of-set wire byte.
- **`from_buffer` field unpack order / slicing** — `_frame[a:b]`
  offsets; a wrong slice must change a parsed field a test asserts.
- **Degenerate/weak frame fixtures** (skill §6) — an all-zero payload
  or a header where many fields are 0 hides field-placement bugs; use
  non-degenerate, distinct field values.

---

## 6. Aggregation & deliverable

Each shard writes its own survivors into its sqlite. Aggregate:

1. **Per-shard score table** — raw + equivalent-adjusted, gap count.
   The package-wide raw score = Σ killed / Σ total across shards.
2. **Cross-shard equivalent accounting** — quantify the skill §4 + §4
   (this doc) classes once, package-wide.
3. **Survivor ledger** — genuine gaps only, `module:line` + operator +
   proposed (kill-proven) test, grouped by protocol.
4. **Mirror-audit callouts** — any `__post_init__` assert with **no**
   `_validate_integrity` mirror (net_proto.md §9.2 violation surfaced
   by an un-backstopped assert mutant) is both a test gap *and* a
   source gap; flag it for a real fix, not just a test.

Deliverable: `docs/refactor/net_proto_mutation_audit_results.md`
(same shape as the net_addr results doc). Corrections land per
`unit_testing.md` §8 (the per-protocol matrix) and §7.2 docstring
audit; each is kill-proven and committed test-only, citing the mutation
it pins.

---

## 7. Effort estimate

| Phase | Estimate |
|---|---|
| Setup + P0 shards (8 core codecs, ~9 k mutants) | ~0.5 h compute + triage |
| P1 shards (ext headers, dhcp/dns/igmp, ~14 k mutants) | ~0.7 h compute + triage |
| P2 + lib shards (~4 k mutants) | ~0.3 h compute + triage |
| **Total cosmic-ray compute** | **~1.5 h** (sequential, scoped runners) |
| Triage + kill-proven corrections | the bulk of the human time — scales with genuine-gap count, unknown until P0 lands |

Expect the *adjusted* baseline to start high (the §8 matrix is
thorough); the value is in the options/boundary seams §5 calls out.

---

## 8. Quick-start (first shard = tcp)

```bash
cd /root/PyTCP && source venv/bin/activate
S=tcp
cat > /tmp/cr_$S.sh <<EOF
#!/bin/bash
ulimit -v 3145728
cd /root/PyTCP
PYTHONPATH=/root/PyTCP exec python -m unittest \\
  \$(find packages/net_proto/net_proto/tests/unit/protocols/$S \\
         packages/net_proto/net_proto/tests/unit/lib -name 'test__*.py')
EOF
chmod +x /tmp/cr_$S.sh
cat > /tmp/cr_$S.toml <<EOF
[cosmic-ray]
module-path = "packages/net_proto/net_proto/protocols/$S"
timeout = 10.0
test-command = "bash /tmp/cr_$S.sh"
[cosmic-ray.distributor]
name = "local"
EOF
find packages -name __pycache__ -type d -exec rm -rf {} +
bash /tmp/cr_$S.sh 2>&1 | tail -1                       # must be OK
rm -f /tmp/cr_$S.sqlite
PYTHONPATH=$(pwd) cosmic-ray init /tmp/cr_$S.toml /tmp/cr_$S.sqlite
PYTHONPATH=$(pwd) python3 -c "import sqlite3;d=sqlite3.connect('/tmp/cr_$S.sqlite');print('mutants',d.execute('select count(*) from mutation_specs').fetchone()[0],'in_tests',d.execute(\"select count(*) from mutation_specs where module_path like '%/tests/%'\").fetchone()[0])"
PYTHONPATH=$(pwd) nohup cosmic-ray exec /tmp/cr_$S.toml /tmp/cr_$S.sqlite > /tmp/cr_$S.log 2>&1 &
# watch: free -h; cr-report /tmp/cr_$S.sqlite | tail -3
```

Then triage per the skill §4–§7, close gaps tests-first, and move to
the next shard.
