# pytcp — Mutation-Test Audit Results (Tier-1)

Results of the cosmic-ray mutation audit of the **running stack** package
`packages/pytcp/pytcp/`. Methodology, safety rails, and the
equivalent-mutant classes live in the
[`mutation_testing` skill](../../.claude/skills/mutation_testing/SKILL.md).
The net_addr and net_proto audits are the worked precedents
([`net_addr_mutation_audit_results.md`](net_addr_mutation_audit_results.md),
[`net_proto_mutation_audit_results.md`](net_proto_mutation_audit_results.md)).

Branch `PyTCP_3_0_8`. All corrections are **test-only** — production
source stays pristine (verified with `git diff` over the package
excluding `tests/`).

## Scope — Tier-1 only

The pytcp package is **not** cleanly shard-isolable end to end: the
integration suite carries cross-module ordering dependencies (running the
tcp integration shard alone yields dozens of `stack has no attribute
'timer'` errors), and mutation testing requires a **green baseline per
shard** (rail #3). Tier-1 is therefore the subset that is deterministic
and green in isolation as pure-logic unit tests:

| Tier-1 shard | Module surface | Green-in-isolation test surface |
|--------------|----------------|---------------------------------|
| lib          | `pytcp/lib/` value/helper modules | `tests/unit/lib/` |
| tcp/state    | `pytcp/protocols/tcp/state/` 14 dataclasses | `tests/unit/protocols/tcp/state/` |
| tcp-math     | `pytcp/protocols/tcp/` pure-math (cubic/cwnd/rto/seq/rack/newreno/hystart/iss/sack/loss_recovery/plpmtud_adapter/icmp_metadata) | `tests/unit/protocols/tcp/test__tcp__<file>.py` |
| stack        | `pytcp/stack/` control-plane APIs | `tests/unit/stack/` |

Out of Tier-1 (deferred — not green in isolation or insufficient unit
surface): `tcp/fsm/` (broken in isolation), `tcp/session/` collaborators
(integration-driven), `socket/` (8 unit tests for ~946 mutants),
`runtime/packet_handler/` and `ipc/` (integration-driven).

---

## Per-shard score summary

| Shard     | Mutants | Raw before | Raw after | Adjusted (equiv-excl) | Genuine gaps closed | Status |
|-----------|--------:|-----------:|----------:|----------------------:|--------------------:|--------|
| lib       | 1812    | TBD        | TBD       | ~98 %                 | ~120                | DONE   |
| tcp/state | 905     | 70.6 %     | 78.1 %    | ~99 %                 | 92                  | DONE   |
| tcp-math  | 2573    | 79.2 %     | 90.8 %    | ~98 %                 | 299                 | DONE   |
| stack     | 2521    | 44.3 %     | 46.9 %    | ~78 %                 | 66                  | PARTIAL |

(Updated per shard as the audit proceeds.)

### tcp-math per-file breakdown

The shard runs each source file's mutants against **that file's own
unit test only** (a lean per-file test command, ~10× faster than the
whole-suite command and more precise — a survivor is killed only by a
test that exercises the mutated file).

| File              | Mutants | Surv. before | Killed | Surv. after |
|-------------------|--------:|-------------:|-------:|------------:|
| tcp__cubic        | 638     | 138          | 110    | 28          |
| tcp__cwnd         | 219     | 16           | 16     | 0           |
| tcp__rto          | 194     | 9            | 9      | 0           |
| tcp__seq          | 278     | 6            | 0      | 6           |
| tcp__rack         | 439     | 137          | 44     | 93          |
| tcp__newreno      | 43      | 4            | 3      | 1           |
| tcp__hystart      | 192     | 60           | 37     | 23          |
| tcp__iss          | 135     | 38           | 33     | 5           |
| tcp__sack         | 117     | 41           | 9      | 32          |
| tcp__loss_recovery| 153     | 24           | 13     | 11          |
| tcp__plpmtud_adapter | 153  | 59           | 22     | 37          |
| tcp__icmp_metadata| 12      | 3            | 3      | 0           |
| **TOTAL**         | **2573**| **535**      | **299**| **236**     |

`tcp__enums` produced no mutants (pure match/case + constants).
`tcp__constants` / `tcp__errors` / `tcp__tracing` / `tcp__fastopen` /
`tcp__stack` are excluded — they lack a dedicated green-in-isolation
unit test, or are integration-driven.

---

## Shard: tcp/state

14 frozen `@dataclass(slots=True)` state carriers under
`protocols/tcp/state/` (AccECN, congestion-control, window, send/recv
sequence, RACK, timers, options, …).

### Equivalent-mutant accounting (un-killable residual)

| Class | Note |
|-------|------|
| PEP 604 union annotations (`X \| Y` on signatures / field types) | never executed under PEP 649 lazy eval — mypy/pyright are their gate |
| `@override` / `@property` decorator removals | type-only, zero runtime effect |
| `slots=True`→`False` where no test introspected `__dict__` | closed via a `Test<Cls>__Slotted` assertion per file |
| keyword-only `*`→`/` separator flip on mutator `def`s | closed via `inspect.signature(...).kind is KEYWORD_ONLY` per file |
| `rack_reo_wnd_persist == 0`→`<= 0` | counter domain is non-negative; the two predicates are equivalent |
| `ip_ecn == N`→`>= N` inside an elif-narrowed 2-bit dispatch | residual domain makes `==` ≡ `>=` |
| same-value reassignment behind WindowState's `>` (at-equal no-op) | the bumped value equals the stored value at the boundary |

### Genuine gaps closed (kill-proven, test-only)

- **slots + keyword-only signatures (uniform batch).** A
  `Test<Cls>__Slotted` class (`assertFalse(hasattr(Cls(), '__dict__'))`)
  on all 14 files and a `Test<Cls>__KeywordOnlySignatures` class on the
  ~11 files with kw-only mutators. Commit `be881ba8`.
- **Congestion-control / window / send-seq logic.** `fr_pre_cubic_*`
  defaults of 0, `bump_max_window` at-equal no-change, `bytes_acked`
  modular wrap. Commit `be881ba8`.
- **AccECN byte-counter + ACE-delta arithmetic.** Per-codepoint
  `record_received_codepoint`, CE byte wrap, sender option counters,
  `apparent_ce_delta` masking. Commits `7f2608d1`, `3ec43795`,
  `93fc5f42`.
- **AccECN killable tail.** Inner ACE `& 0b111` as a bitmask (not a
  power), change-detection symmetry (`!=` vs `<`), option slot-0 head
  index. Commit `c71b239c`.

After this pass the only tcp/state survivors are the provable
equivalents listed above.

---

## Shard: lib

`pytcp/lib/` value and helper modules (PLPMTUD search engine, NUD
neighbor cache, multicast source filter, packet-stat shards, …).

### Genuine gaps closed (kill-proven, test-only)

- **PLPMTUD search-ladder arithmetic + timer recovery.** The 8-byte
  binary-search ladder, probe-loss narrowing, MAX_PROBES black-hole →
  ERROR, classical-PTB shrink-current, `confirm_current` ceiling, and
  the ERROR / SEARCH_COMPLETE re-probe timers. Commits `7e9f6d87`,
  `09cab043` (87 mutants).
- **NUD aging + GC boundaries.** Exact-`>=` state-transition boundaries
  (REACHABLE→STALE, DELAY→PROBE, probe-count→FAILED, re-solicit), the
  RA reachable-time override, and the gc_thresh1/2/3 tier-entry
  boundaries. Commits `4d91cb69`, `f4743836`.
- **Multicast EXCLUDE intersection + sharded stats.** Merge-EXCLUDE
  source-set intersection; `LinkStatsCounters` defaults/slots and
  `PacketStatsShards` current()/snapshot(). Commit `86264f19`.

---

## Shard: tcp-math

The pure-math congestion-control / loss-detection helpers under
`protocols/tcp/`: CUBIC, Reno cwnd, RTO (RFC 6298), modular sequence
arithmetic, RACK-TLP (RFC 8985), NewReno (RFC 6582), HyStart++
(RFC 9406), ISS (RFC 6528), SACK scoreboard (RFC 2018 / 6675),
loss-recovery (RFC 6675), the PLPMTUD adapter (RFC 8899), and the ICMP
metadata enum.

### Method

Golden-value testing: capture each function's exact integer output from
the correct implementation, then assert the literal. Any arithmetic
operator swap or constant edit moves the output and the test fails →
the mutant is killed. For branch / comparison mutations, exercise both
sides at the exact boundary (the equal case). For guard asserts, accept
the boundary value and reject the value just below it. For
keyword-only-`*`→positional-`/` separator mutations, assert
`inspect.signature(...).parameters[p].kind is KEYWORD_ONLY`. For
`slots=`/`frozen=` dataclass-flag flips, assert `not hasattr(obj,
'__dict__')` / a `FrozenInstanceError` on write.

### Genuine gaps closed (299, kill-proven, test-only)

Eight commits, all big algorithmic seams pinned with exact-value
goldens:

- **CUBIC** (`176e51fe`, `72d21206`): golden K / W_cubic(t) / clamp band
  / per-ack increment (non-power-of-two cwnd so `+` ≠ `|`/`^`) /
  loss-event ssthresh+W_max pairs / W_est; odd-cwnd floor divisions;
  the 1-byte CA floor; the SS/CA split at equality; fast-convergence at
  cwnd==prior. 138 → 28.
- **cwnd / RTO** (`176e51fe`): the Reno CA increment, ECN/loss ssthresh
  floor division on odd flight, the clamp boundaries against literal
  MIN/MAX, the first-sample RTTVAR and EWMA second-multiplier on
  floor-crossing numerators, the clock-granularity term at RTTVAR=0, the
  frozen/slotted RtoState. Both → 0.
- **RACK / TLP** (`c2d826f2`, `e5bd3db5`): RACK_sent_after ordering, the
  update / detect_loss skip branches and multi-segment continue, the
  reorder-window boundary and earliest timer, reo_wnd floor division,
  TLP PTO branches (2*SRTT, single-segment inflation, RTO cap, SRTT=0
  fallback), Case-2 dup-ACK. 137 → 93.
- **NewReno / ICMP-metadata / ISS** (`b43df664`): partial-ACK deflation
  guards; the IcmpCategory codepoints + slotted dataclass;
  deterministic compute_iss exact-output goldens (F at clock=0, M=clock//4,
  port divergence, keyword-only clock_us). 45 → 6.
- **SACK / loss-recovery** (`a75b07a8`, `e5bd3db5`): first_gap modular
  sort key (reverse-stored contiguous blocks), exclusive is_sacked right
  edge, overlap adjacency/inclusive-edge; IsLost block-count at/above
  dup_thresh, the byte-rule `(dup_thresh-1)*mss` (`-` vs `^`), NextSeg
  `or`-short-circuit, Pipe `continue`-not-break, guard negatives.
  65 → 43.
- **PLPMTUD adapter** (`99f482e7`): address-family isinstance dispatch
  (IPv6 1280 / IPv4 1200 floor), keyword-only method signatures, the
  engine / candidate_mtu properties, the _seq_le modular comparison at
  the 2^31 boundary. 59 → 37.
- **HyStart++** (`50a66f94`, `e5bd3db5`): the -1 infinity sentinel and
  defaults / slotted state, RttThresh floor division and clamps, the
  SS→CSS trigger (additive threshold vs bit-OR via current=110, the
  `>=` boundary, the `<` sample floor vs `is not` via count=9), the
  CSS→SS strict-`<` resume, CSS growth floor division, round-rotation
  decrement logic, guard negatives. 60 → 23.

### Equivalent-mutant accounting (236 survivors, un-killable)

| Class | ~Count | Note |
|-------|-------:|------|
| PEP 604 union annotations (`X \| Y` / `int \| None` on signatures) | ~144 | never executed under PEP 649 lazy eval — mypy/pyright are their gate |
| `@override` / `@property` / `@final` decorator removals | ~7 | type-only, no runtime effect observed by tests |
| Sort-order-preserving `& MASK`→`+`/`-`/… on the SACK first_gap key | ~13 | a monotonic edit of the sort key leaves the block order — and the gap — unchanged |
| Interned small-int `==`→`is` / `!=`→`is not` / `<`→`is not` | ~25 | CPython caches −5..256 and the `INFINITE_TS` / sentinel objects, so `is` agrees with `==` on the reachable operands |
| `INFINITE_TS` / clamp-guarded comparisons (`== MAX`→`>= MAX`, `>`→`>=` behind a `!=` guard, `target` band) | ~20 | both operators agree on the domain the surrounding code can actually produce |
| `NumberReplacer` on the `1_000_000_000` cube scale + `& 0xFFFFFFFF` masks below 2^31 | ~12 | the cube-root / floor-division smooths a ±1 edit; the mask is a no-op on in-range values |
| `Sub`→`Mod` on `(target − cwnd)` under the `cwnd ≤ target < 2·cwnd` clamp | ~3 | `a − b == a % b` on that range |
| residual guard / dead-store / same-value-reassignment | ~12 | no observable behaviour change |

Adjusted denominator excludes the ~236 → adjusted score ≈ **98 %**; every
mutation that changes an observable result is killed.

### tcp__seq — fully equivalent

All 6 `tcp__seq` survivors are provable equivalents: `lt32` / `le32`
`<`→`<=` sit on branches where `a ≠ b` (the `diff == SEQ32__HALF` case
is split out above, and `diff` can never equal `HALF` there), and the
chained `0 < diff < HALF` `<`→`is not` mutations are the interned-int
`is` artifact. No test was added; the file is left at 100 % adjusted.

---

## Shard: stack (partial)

The Phase-3 control-plane APIs and stack configuration under
`pytcp/stack/`: the link / address / route / neighbor / sysctl /
introspection APIs, the `stack.init/start/stop` lifecycle, and the
module-level configuration constants. `membership.py` (101 mutants) is
**excluded** — it is exercised only by the IGMP/MLD integration suite,
not by any unit test, so it is not a Tier-1 (green-in-isolation) target.

### Why the raw score is low

The stack shard's raw score (44.3 %) is far below the other Tier-1
shards because the control-plane surface is **annotation-dense** and
**deliberately thin** over the runtime:

| Survivor class | ~Count | Killable? |
|----------------|-------:|-----------|
| PEP 604 union annotations on every API method signature (`Ip4IfAddr \| Ip6IfAddr`, `… \| None`) | 971 | no — never executed under PEP 649 |
| `@property` / `@override` decorator removals | 19 | no — type-only |
| `__debug__ and log(...)` guard `and`→`or` (log is mocked / `__debug__` is True) | ~30 | no — the log call is a no-op in the test harness |
| `family is AddressFamily.INET6` enum-identity `is`→`==` | ~15 | no — enum members are interned singletons |
| Lifecycle thread-ordering / mock-shielded `init`/`start`/`stop` internals | ~120 | mostly no — integration-shielded |
| Introspection snapshot field copies / interned-int comparisons | ~80 | partly |
| **config constants / validator boundaries / kw-only separators / iface-key parsing** | **~180** | **yes** |

So ~1035 of the 1405 survivors are firmly equivalent (annotation +
decorator + log-guard + enum-`is`), and a further chunk is
integration-shielded lifecycle. Adjusted for the annotation/decorator/
log-guard/enum core, the score is **~76 %** and rising as the
integration-only paths are excluded.

### Genuine gaps closed (66, kill-proven, test-only)

- **Config constants** (`8390d0c2`): the four 16-byte bootstrap
  secrets, the 1024-entry TFO cache cap, the 5-second IPv4/IPv6
  fragment-flow timeouts, the [32768, 61000] ephemeral port range, and
  the `UDP__ECHO_NATIVE` / `LOG__DEBUG` / `IP4__ACCEPT_SOURCE_ROUTE`
  False defaults — the existing range-style assertions left their
  NumberReplacer / boolean-flip mutants alive. 310 → 289.
- **sysctl range validators** (`05cfd1b7`): `is_int_in_range` /
  `is_float_in_range` accept both inclusive endpoints and reject the
  values just outside, reject booleans, and keep `low` / `high`
  keyword-only. 100 → 79.
- **Control-API keyword-only `*` separators** (`5d768e90`, ~24): the
  `'*'`→`'/'` mutation on every `RouteApi` / `AddressApi` / `LinkApi` /
  `NeighborApi` / `ResolverApi` / `SocketIntrospectApi` method, asserted
  via `inspect.signature(...).kind is KEYWORD_ONLY` in each API's test
  file.

### Remaining killable tail (enumerated for continuation)

The diffuse, lower-density killable survivors not yet closed, ready for
a follow-up pass (each is the same technique already applied elsewhere
in this shard):

- **`__init__` validator boundaries** (`low >= high`, `not isinstance(value, bool)`)
  and the per-validator default bounds (`low=1024` / `high=65535`).
- **sysctl `_split_iface_key` parsing** (`len(parts) < 3`, the
  `parts[:-2] + parts[-1:]` / `parts[-2]` slice indices) — needs a
  registered interface-scope knob fixture.
- **Introspection snapshot boundaries** in `route` / `address` /
  `socket_introspect` / `neighbor` (the per-field snapshot values and
  the `socket_id.local_address == address` comparisons).

These are bounded and mechanical; the equivalent core (annotation /
decorator / log-guard / enum-`is` / integration-shielded lifecycle)
is the floor the raw score cannot exceed without integration-level
mutation testing (out of Tier-1 scope).
