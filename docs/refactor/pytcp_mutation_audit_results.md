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
| stack     | 2521    | 44.3 %     | 50.8 %    | ~83 %                 | 165                 | PARTIAL |
| ipc       | 1877    | 64.2 %     | 67.9 %    | ~98 %                 | 69                  | DONE   |
| session/fsm | ~5000 | 4.7 %†     | n/a       | n/a                   | 1 (demonstrator)    | AUDITED — see note |
| socket/dropin | 946 | 38.8 %   | 46.1 %    | ~85 %                 | 69                  | DONE   |
| packet_handler‡ | 685 | 58.0 % | n/a       | ~76 %                 | 1 (demonstrator)    | AUDITED — per-protocol |

(Updated per shard as the audit proceeds.)

† session/fsm raw is a baseline artifact — the per-collaborator parity
tests pin only the decomposition seam (3 tests for ack's 792 LOC). The
real baseline is the full 590-test TCP integration suite (33 s/mutant),
under which 33–73 % of parity-survivors die; the shard is
integration-saturated, not under-tested. Exhaustive closure is a ~46 h
low-ROI track. See "Shard: tcp/session + tcp/fsm" below.

‡ packet_handler is sampled, not exhaustive: the 685 mutants /
58.0 % raw are the arp (337) + udp (348) worked examples, both ~76 %
adjusted. The shard is auditable per-protocol (fast green integration
baselines) — unlike session/fsm — but a full 20-handler sweep is
low-yield. See "Shard: runtime/packet_handler" below.

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
decorator + log-guard + enum-`is`), and a further chunk (lifecycle's
431) is integration-shielded. After the closures below, adjusting for
the annotation/decorator/log-guard/enum core and the integration-only
lifecycle, the shard sits at **~83 %**; the raw ceiling cannot rise
further without integration-level mutation testing.

### Genuine gaps closed (165, kill-proven, test-only)

A clean exclusive re-scan (no concurrent formatter pass — see the note
below) confirms the per-file kills: socket_introspect 118→89 (29),
sysctl 100→56 (44), `__init__` 310→281 (29), resolver 38→13 (25), link
86→64 (22), plus the deterministic keyword-only kills on address (5),
neighbor (5), and route (6). `lifecycle.py` (431 survivors) is
untouched — its mutants are overwhelmingly annotation unions, thread
ordering, and mock-shielded `init`/`start`/`stop` internals that only
the integration suite exercises.

> **Re-scan hygiene note.** Survivor re-scans MUST run with nothing else
> touching the tree. `make lint` runs isort/black in **write mode**; a
> re-scan that overlaps it sees a half-rewritten file and reports
> spurious "kills" (one route re-scan showed an impossible 93/137 before
> this was caught). The numbers above come from a fully-isolated re-scan
> and are reproducible across runs.

The closures, by commit:


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
- **Introspection filter / queue accounting** (`33ebb49c`): the
  `build_socket_snapshots` listening filter excludes a connected
  datagram socket (`remote_port == 0` vs `>=`), the family/type filter
  `continue`s past a non-match (vs `break`), and the queue counts
  default to 0 when the status object has no buffer fields.
- **sysctl `_split_iface_key` parsing** (`33ebb49c`): a 3-segment
  `<ns>.<ifname>.<field>` key splits into `(base, ifname)` — pinning the
  `len(parts) < 3` boundary, the `parts[:-2] + parts[-1:]` base
  reconstruction, and the `parts[-2]` ifname slice — against the real
  registry's interface-scoped `ip4.accept_source_route` knob.
- **`__init__` registered-validator boundaries** (`33ebb49c`): the
  source-route bool validator rejects non-bools, the ephemeral-range
  validators pin their exact 1024 / 65535 bounds, and the cross-knob
  finalize rejects `low == high` (`low >= high` vs `>`).
- **resolver error aggregation** (`33ebb49c`): a NODATA all-empty result
  returns an empty tuple (`not addresses and errors` vs `or`), and a
  single-family failure raises `errors[0]` (vs an off-by-one index).
- **LinkApi packet-count sums** (`1c37c9d3`): rx/tx packet aggregation
  is additive (3 + 5 = 8, distinguished from `|`=7 / `^`=6) on both the
  L2 Ethernet/802.3 and L3 IPv4/IPv6 addends.

### Remaining survivors — overwhelmingly equivalent / integration-shielded

After the above, the residual 1240 survivors are dominated by the
un-killable core: ~971 PEP 604 annotation unions, ~19 decorator
removals, the `__debug__ and log(...)` guards (no-ops in the test
harness), enum-identity `is` on interned `AddressFamily` / `FsmState`
members, and — the largest single block — `lifecycle.py`'s 431
thread-ordering / mock-shielded `init` / `start` / `stop` mutants that
only the integration suite drives. Adjusting for that core puts the
shard at **~83 %**; the raw ceiling cannot rise further without
integration-level mutation testing, which is out of Tier-1 scope. The
only genuinely-killable unit-level residue is a thin tail of
interned-`is` address comparisons (`socket_id.local_address == address`
in the address ABORT loop) and the `_sum_drops` prefix/suffix filter
branches in `link`, both low-yield.

---

## Tier-2 — integration-driven shards

Tier-1 covered the green-in-isolation pure-logic shards. Tier-2 reaches
the shards Tier-1 excluded because their tests are integration-driven,
not unit-isolable. The baseline rule is unchanged — the per-file
test-command must be green on unmutated code and actually exercise the
mutated file — so a shard is in scope only when a viable green test
surface exists.

### Shard: ipc

The 3.0.8 daemon-IPC machinery (`pytcp/ipc/`). The 12 files with
dedicated unit tests are in scope (the wire codecs, bridges, mux client,
rpc, value codec); the 8 integration-only files (`client` / `control` /
`server` / `socket_session` / `stdlib_socket` / `remote_error` /
`enums` / `errors`) are excluded — only the daemon end-to-end
integration suite drives them.

**Baseline:** 1877 mutants, **64.2 % raw** (672 survivors). Per-file
character drove the strategy: well-tested codecs (`message` 92 %,
`packet_frame` 93 %, `values` 91 %) needed nothing; the bridges sat low
(`dgram_bridge` / `packet_bridge` ~28 %) because their pumps run over
healthy socketpairs that never raise the errors the loops guard.

**After:** 603 survivors, **67.9 % raw**, **69 kill-proven** across 7
commits.

| File | Killed | What the new tests pin |
|------|-------:|------------------------|
| dgram_frame | 25 | exact wire bytes (None / IPv4 / IPv6 / cmsg), multi-cmsg round-trip, unknown-tag + truncation rejection |
| socket_rpc | 19 | the fd-bearing `accept` decode over a mocked client — OK→(handle, peer, fd) in index order, OK-without-fd→error, ERROR→remote raise |
| frame | 12 | the 16-MiB max-payload constant, the exact 4-byte length prefix, clean-EOF→None, partial-prefix rejection, and the partial-recv accumulation loop (dribble socket) |
| dgram_bridge | 4 | RX pump survives a poll TimeoutError AND a transient OSError, then frames + delivers the datagram |
| packet_bridge | 4 | RX pump survives a poll TimeoutError AND a transient OSError, then frames + delivers the captured frame |
| fdpass | 3 | real SCM_RIGHTS round-trip (received fd live + distinct), no-fd→None, two-fd rejection |
| socket_bridge | 2 | RX pump survives a poll TimeoutError (continue, not teardown) |

#### The two highest-value findings were real gaps

1. **The IPC wire format was tested by round-trip only**, which leaves
   the bytes free — a tag value or field-length constant used
   symmetrically in encode + decode survives a round trip, so a
   client/server byte-drift would have passed. The datagram and frame
   formats are now byte-pinned.
2. **The fd-passing and passive-`accept` paths weren't unit-tested at
   all** — a real SCM_RIGHTS round-trip now verifies the received
   descriptor is a live, distinct fd, and the `accept` RPC decode is
   driven through OK / OK-without-fd / ERROR.

#### Irreducible residue (603 survivors, un-killable at unit level)

- **PEP 604 annotation unions + decorator removals** — the dominant
  class (`mux_client` alone is ~110 annotation mutants), never executed
  under PEP 649.
- **`except OSError: break` pump branches** — a `break`→`continue`
  mutant spins on the failing recv forever; the outcome is a hang, not
  an assertable result, so these are left untested by design.
- **Comparison-on-bounded-domain equivalents** — `<`≡`!=` on a length
  that is always `<` or `==` the bound; `% itemsize` on an fd array the
  kernel only ever delivers in whole-fd multiples; interned-enum `is`
  in the RPC response dispatch.
- **fd-leak-only / adversarial-cmsg** — mutations whose only observable
  difference is a leaked descriptor or that require a kernel-impossible
  cmsg shape.

The genuinely-killable-by-unit-test surface of the ipc shard is
exhausted; the raw ceiling cannot rise further without daemon
end-to-end integration mutation testing (out of Tier-2 scope).

---

## Shard: tcp/session + tcp/fsm — integration-saturated, baseline-bound

The TCP session collaborators (`protocols/tcp/session/`: `ack` 792 LOC,
`tx` 1226, `retransmit` 783, `validate` 471, `timers` 217, `info` 76,
plus the main `tcp__session.py` 2098) and the FSM dispatch
(`protocols/tcp/fsm/`, 12 files) are a **different shape** from every
Tier-1 shard and from ipc. They are not under-tested; they are
**integration-saturated** — their logic is driven almost entirely by
the 590-test TCP integration suite (handshake / data-transfer /
retransmit / SACK / RACK / ECN / AccECN / Fast-Open / F-RTO / CUBIC /
HyStart / RTO), not by isolated unit tests. The audit therefore became a
**baseline-economics** problem, and the conclusion is a recommendation,
not an exhaustive close-out.

### The baseline under-reports by ~15×

The per-collaborator parity tests (`test__tcp__session__<collab>.py`)
pin only the Phase-3 decomposition seam — e.g. `ack_processor` is 3
tests for 792 LOC. Run as a mutation baseline they give a meaningless
floor:

| Baseline for `tcp__session__ack.py`         | Kill rate          |
|---------------------------------------------|--------------------|
| collaborator-seam parity test (3 tests)     | 26/559 = **4.7%**  |
| broad data-transfer + retransmit (~5 s)     | +0 on a 40-survivor sample |
| **full TCP integration suite (590 t, 33 s)**| **33–73%** of the parity-survivors (sample-dependent) |

The "4.7%" is a baseline artifact, not a coverage gap. The correct
session baseline is the **full TCP integration suite at ~33 s/mutant**,
which makes an exhaustive run (≈5 000 mutants across the collaborators +
main + FSM) cost **~46 h of serial compute** — infeasible to grind, and
low-value because the suite already kills the bulk.

### Residue classification (survivors of the FULL suite)

Sampling ack's parity-survivors against the full suite and reading the
true survivors (mutations that survive even the 590-test suite) splits
them cleanly:

- **Equivalents** (~half) — idempotent re-assignment guards
  (`if snd_wnd != win << wsc:` whose body re-derives the same value),
  `__debug__ and log(...)` f-string operands (log mocked), unsigned
  `== 0`≡`<= 0` comparisons (`cubic_w_est`), and 32-bit modular masks
  (`& 0xFFFF_FFFF` on a `bytes_acked`/`flight_size`/`ts_rtt_ms` that
  never wraps in the tested range). None killable.
- **Genuine corner-case gaps** (~half) — operands and boundaries
  *within already-tested CC paths* that the existing assertions do not
  pin to exact value: the RFC 6937 PRR SSRB/CRB limit formulas
  (`max(prr_delivered - prr_out, bytes_acked) + snd_mss`), the
  `pipe > ssthresh` PRR-proper/CRB boundary, the `cwnd < ssthresh`
  slow-start/CA boundary (differs only at `cwnd == ssthresh`), and the
  RFC 6582 post-RTO recover-marker decay `and` gate.

The genuine gaps are real but **low-density and corner-case**: the main
CC paths are covered; what survives is the exact intermediate operand a
crafted data-in-flight + internal-CC-state scenario would pin.

### Demonstrated close (kill-proven, test-only)

To substantiate that the genuine residue is closable, one gap was closed
end-to-end — the RFC 6582 §3.2 post-RTO recover-marker decay
(`tcp__session__ack.py:244`), which survives both the parity baseline
and a full-suite re-scan:

- `test__tcp__session__recover_marker.py` — 3 tests over a session with
  400 B in flight and an RTO fired. Kill-proven: `and`→`or` on line 244
  clears `recover_seq` to 0 on the first advancing cum-ACK instead of
  holding it at SND.MAX; the partial-ACK test catches it.

### Recommendation

Mutation-testing payoff concentrates in **thin-unit shards** (lib,
tcp-math, tcp/state, ipc value codecs) where gaps are cheap to find and
cheap to close. For the **integration-saturated session/FSM code** the
integration suite is the correct coverage vehicle; exhaustive mutation
closure is a ~46 h / multi-week low-ROI track whose residue is half
equivalents and half corner-case operands. The genuine corner cases are
best treated as an **opportunistic backlog** — closed by adding
exact-value assertions to the existing CC test families (cubic /
hystart / cwnd / retransmit-dupack) as that code is touched — not as a
dedicated sweep. The recover-marker test is the worked example of that
pattern.

---

## Shard: socket drop-in (`pytcp.socket`, 3.0.8 daemon-backed)

`socket__dropin.py` (821 LOC) is the stdlib-shaped `Socket` wrapper +
`socket()` factory that fronts the daemon. Unlike the session/FSM code it
is a **thin-unit-testable** shard: most of its daemon-independent logic
(blocking-mode state, stream-only operation guards, `makefile` mode
parsing + shared-fd refcount, factory family/type/proto dispatch) runs
*before* any daemon I/O, so it is reachable by constructing the wrapper
over a `create_autospec` client shim — no live daemon.

### Score

| Metric                              | Value                |
|-------------------------------------|----------------------|
| Mutants                             | 946                  |
| Raw before                          | 38.8 % (367/946)     |
| Raw after batch                     | 46.1 % (436/946)     |
| Annotation/decorator survivors      | ~431 (un-killable)   |
| Adjusted (equiv-excl)               | ~85 % of the 515 executable-mutant surface |
| Genuine gaps closed (kill-proven)   | 69                   |

The dominant survivor class is the PEP 604 union-annotation mutant: the
three busiest survivor lines alone (`makefile` return-union, the
`underlying:` ctor union, the `_control_sock` return-union) carry 44 / 44
/ 33 annotation mutants each, never executed under PEP 649.

### Genuine gaps closed (69, kill-proven, test-only)

`test__socket__dropin__behaviour.py` — 13 fast no-daemon tests:

- **Blocking-mode state** — `setblocking`/`getblocking` round-trip pins
  `self._timeout != 0.0` (vs `==`) and the `None if flag else 0.0` set.
- **Stream-only guards** — `listen`/`accept`/`shutdown`/`dup` on a
  datagram socket must raise `OSError(EOPNOTSUPP)`; pins each
  `self._type is not SocketType.STREAM` guard against an `is` edit.
- **`makefile` mode parsing** — invalid-mode rejection (`set(mode) <=
  {r,w,b}`), the `reading = "r" in mode or not writing` parse (an `and`
  edit collapses `rwb` to write-only), unbuffered-non-binary rejection,
  and the shared-fd refcount (`close()` with an outstanding stream defers
  the real handle close until the stream decrefs).
- **`socket()` factory dispatch** — RAW forwards proto, plain DGRAM drops
  it to `None`, ICMP DGRAM forwards it (ping socket), `fileno=` raises.
- **Module surface** — `has_ipv6 is True`.

### Residue (79 non-annotation candidates left)

The 79 still-surviving non-annotation candidates need either a live
daemon round-trip to observe (the control-plane delegations:
`bind`/`connect`/`setsockopt` pass-throughs, `create_connection`
multi-address retry, the recv/send `EAGAIN` non-blocking arms) or are
equivalents (interned-enum `is`, bounded-domain comparisons). They sit in
the daemon-integration surface, not the fast unit surface, and are best
closed opportunistically as the 3.0.8 daemon harness grows.

---

## Shard: runtime/packet_handler (per-protocol RX/TX handlers)

The 20 RX/TX handler files under `runtime/packet_handler/` (~12.6k LOC
incl. the 3951-LOC `__init__.py` assembler) are the wire-level dispatch
plane. Crucially — and unlike session/fsm — they are **auditable**: each
protocol's integration suite is **green-in-isolation and fast** (arp /
udp ~3.6 s), so a handler file can be mutation-tested against its own
protocol's suite as a clean per-protocol baseline. This shard does *not*
hit the session/fsm baseline-economics wall.

### Worked examples

| Handler (rx+tx)        | Mutants | Raw    | Annotation+log equiv | Adjusted | Genuine gaps |
|------------------------|--------:|-------:|---------------------:|---------:|-------------:|
| arp (rx 288 + tx 241)  | 337     | 64.4 % | 53                   | ~76 %    | low-density  |
| udp (rx 309 + tx 177)  | 348     | 52.0 % | 109                  | ~76 %    | low-density  |

Both land at **~76 % adjusted**. The handlers are **integration-suite-
saturated**: the integration tests assert exact `packet_stats_rx/tx`
counters on every RX/TX branch, so the bulk of branch / counter / dispatch
mutations die. The raw-vs-adjusted gap is dominated by PEP 604 union-
annotation mutants (udp alone: 99 of 167 survivors are annotation, never
executed under PEP 649) and `__debug__ and log(...)` guard operands.

### Residue classification (survivors of the protocol suite)

- **Equivalents** — annotation unions (dominant), `__debug__ and log`
  f-string operands, **bounded-domain sysctl-mode comparisons** (e.g.
  `arp_ignore == 8`≡`>= 8` and `== 2`≡`>= 2` over the closed {0,1,2,8}
  mode set), keyword-only-`*`-separator AST no-ops, and defensively-
  unreachable `case _:` counters (the unknown-ARP-oper drop is rejected
  at the TX-strict parser before the handler's match-default, so its
  counter is dead via normal wire input).
- **Genuine, low-density gaps** — under-tested branches the protocol
  suite's topology does not reach: per-interface **sysctl modes**
  (arp.announce 1/2 subnet-match, run on a single-subnet topology),
  **multi-X scenarios** (the UDP socket-match loop `continue`, multi-
  socket fan-out), and **error-emit selection** paths (UDP
  no-socket-match ICMPv4-vs-ICMPv6 rate-limiter pick, the native-echo
  `UDP__ECHO_NATIVE` gate).

### Demonstrated close (kill-proven, test-only)

`test__arp__tx__announce_selection.py` — 2 tests over a two-subnet
interface pinning the Linux `arp_announce` SPA selection
(`packet_handler__arp__tx.py:75-80`), a genuine gap the single-subnet ARP
suite never exercised. Kill-proven: `arp__tpa in host.network`→`not in`
and the `in (1, 2)` mode gate→`(2,)` both fail the mode-1 test.

### Recommendation

The packet handlers are well-covered by their stat-counter-asserting
integration suites (~76 % adjusted on two worked examples). The genuine
residue is low-density under-tested edge branches — closed opportunistically
by adding a scenario test (a sysctl mode, a multi-socket/multi-subnet
topology, an error-emit path) as that handler is touched, exactly like the
arp.announce demonstrator. A full per-protocol sweep across all 20 handler
files is auditable but low-yield; the `__init__.py` assembler (3951 LOC)
would need the broad multi-protocol integration baseline and is the one
sub-surface that approaches the session/fsm economics.
