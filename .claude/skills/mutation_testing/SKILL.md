---
name: mutation_testing
description: Run a cosmic-ray mutation-testing audit of a PyTCP package (net_addr / net_proto / pytcp) to find untested behaviour, triage survivors into equivalent-vs-real-gap, and close the real gaps with kill-proven unit tests. Invoke when asked to "mutation test", "run cosmic-ray", measure/improve a package's test thoroughness beyond line coverage, or harden a value-type / wire-codec / pure-logic module. Periodic manual audit, never a make-lint gate.
---

# PyTCP Mutation-Testing Skill

This skill captures the full methodology and the hard-won
lessons for mutation-testing a PyTCP package with
**cosmic-ray**. Mutation testing mechanically breaks the
source in thousands of tiny ways (flip `<`→`<=`, `+`→`-`,
corrupt a bitmask, drop a decorator) and checks whether any
test notices. A break no test catches — a **surviving
mutant** — is a coverage blind spot that line coverage
cannot see.

The first worked example is the net_addr audit (2026-06-08,
a flat value-type library): **78.2 % → 80.5 % raw**,
**92.4 % → 95.2 % equivalent-adjusted**, 14 test-only
commits. Runbook + results:
`docs/refactor/net_addr_mutation_audit.md` and
`…_results.md`.

The at-scale example is the net_proto audit (2026-06-09, 20
protocols + shared `lib`, **27,007 mutants across 21
sharded runs**): **70 genuine gaps closed test-only**,
including **three whole-codec omissions** (an option, two
messages, with no test file at all). It is the precedent for
the dependency-scoped sharding (rail #2), the whole-file-gap
first-check (§6), and the result-preserving / base-coincidence
equivalent classes (§4). Results:
`docs/refactor/net_proto_mutation_audit_results.md` (the
plan/sharding doc is `…_mutation_audit.md`).

A **capstone re-validation** of that audit (2026-06-10,
full-from-scratch re-scan of all 9 changed shards) confirmed
every shard reproduced its recorded score — no ineffective
fixture — then the sharpened §4/§6 re-triage found **40 more
cheaply-killable survivors** the first pass had bucketed as
equivalent/seam. It is the precedent for **always running the
full-from-scratch capstone after the fixes land** (§8), and
for the **trailing-padding integrity bound** and one-sided
**dispatch-/`!=`-assert** classes (§6) — the two systematic
shapes that dominated the residual.

## When to invoke

- A user asks to "mutation test", "run cosmic-ray", or
  measure/improve a package's test thoroughness beyond line
  coverage.
- Hardening a value-type library (`net_addr`), a wire codec
  (`net_proto`), or any pure-logic module where correctness
  hinges on exact comparisons / boundaries / bit operations.
- Re-confirming a package after a round of test additions
  (use the fast survivor-only re-scan, §8).

**First, classify the shard's archetype (§6.5).** Thin-unit
shards (fast unit baseline) are high-ROI — run the full scan
and close gaps. Integration-saturated shards (session/fsm,
packet handlers) are audit-only — sample against the *real*
integration baseline, classify, close one demonstrator. Do
not grind an integration-saturated shard against a slow or a
seam-only baseline.

## When NOT to invoke

- As a `make lint` / CI gate. Mutation testing is a
  **periodic manual audit** — cosmic-ray stays out of
  `requirements_dev.txt` and the lint gate. It spawns one
  fresh interpreter per mutant and takes ~40–90 min for a
  small package; it is not a per-commit check.
- On heavily I/O- / thread- / time-driven runtime code
  (most of `pytcp/runtime`) without first making the test
  surface deterministic — non-deterministic tests produce
  meaningless survivor noise.

## The one-sentence mental model

A surviving mutant means **no test distinguishes the correct
code from a broken variant**. The code is already correct —
the gap is in *coverage*. So **every fix is a new unit test,
never a production-source change** (verify: `git diff` on
the package excluding `tests/` stays empty across the whole
audit).

---

## 1. Hard safety rails (each one cost a real failure)

Non-negotiable. Skipping any of these produced a wrong
result or a near-miss during the net_addr audit.

1. **Memory cap per worker — `ulimit -v 3145728` (3 GB) in
   the test-runner wrapper.** Arithmetic operators mutate
   `a - b` into `a ** b`; with 32-bit-ish operands that is a
   multi-GB integer that OOM-kills the host. Under the cap it
   dies fast as `MemoryError` (counted *killed*) instead.
   Monitor `free -h` during the run regardless.

2. **Test-command = the FULL consumer set of the mutated
   code, never UNDER that.** A test-command that omits any
   test which exercises the mutated module reports
   **false-positive survivors** — mutants a left-out test
   would kill. (The net_addr trial run scoped to one test
   file and "found" a survivor the sibling SACK tests already
   killed.) The danger is *under*-scoping below the real
   consumer set — NOT scoping to the exact consumers.
   **Refinement from the net_proto audit (4.5× scale):** for
   a package of *independent* modules (e.g. net_proto's 20
   protocols — a udp mutant can never be killed by a tcp
   test), the **correct** test scope is that module's own
   tests **plus the shared-dependency tests it transitively
   needs** (`tests/unit/lib`), and sharding per module that
   way is right — *not* the dangerous narrowing this rail
   warns about. It also runs ~3× faster and lets you
   prioritize / stop early. **The one exception is shared
   foundation code** (net_proto's `lib/`: `inet_cksum`,
   `int_checks`, `proto_*`) — that is consumed by every
   module, so its shard MUST run the **full** package suite.
   Rule of thumb: scope to *exactly the set of tests that can
   kill a mutant in this module*, computed from the
   dependency graph — full-suite when in doubt, dependency-
   scoped when the independence is provable.
   **Cross-module-constant blind spot:** a constant defined
   in module A but *consumed* by module B (net_proto's
   `IP6__MIN_MTU`, defined in ip6, used by icmp6 error
   messages) survives A's shard but is killed by B's tests.
   When a survivor is a bare constant with no in-module
   reader, check whether another module's suite kills it
   before calling it a gap — it is *cross-shard-covered*, not
   a real gap.

3. **Clear `__pycache__` before the run AND between EVERY
   manual mutate→revert.** A stale `.pyc` makes a later run
   execute the *previous* bytecode → false "OK"/"FAILED"
   readings. This gave wrong kill-proof results **three
   separate times** in one session. Always
   `find packages -name __pycache__ -type d -exec rm -rf {} +`
   between mutations, and never trust a kill-proof run that
   didn't clear it.

4. **`excluded-modules` is broken in cosmic-ray 8.4.6** — the
   `["*/tests/*"]` glob does not exclude test modules. After
   `init`, **delete the test-module jobs directly from the
   sqlite** (§3 step d). Verify the source-only mutant count
   matches expectation and `in_tests` is 0.

5. **Per-mutant timeout backstop — `timeout = 10.0`** — for
   the rare non-allocating infinite loop the `ulimit` would
   not catch.

6. **`git diff` after ANY interrupted cosmic-ray run.** A
   `pkill -9` mid-exec leaves a mutant applied on disk and
   never reverted (it happened: `ip6_ifaddr.py:205`
   `(1<<64)`→`(1<<65)` survived a killed survivor-scan).
   Catch it with `git status`, `git checkout` it, and
   re-confirm the suite is green on the clean source. If the
   stranded mutation sat in a module whose tests are exact
   (not structural-only), the run that ran against it is
   contaminated — re-run.

7. **No auto-fix, no commit, no push from the audit run
   itself.** The audit produces a *report with proposed
   corrections*; the human decides. (When the user has
   explicitly asked you to also close the gaps, that is the
   normal tests-first workflow afterward — but the cosmic-ray
   execution never mutates committed state.)

---

## 2. Setup files

### 2.1 Memory-capped runner — `/tmp/cr_runtests.sh`
```bash
#!/bin/bash
ulimit -v 3145728            # 3 GB virtual-memory cap per worker
cd /root/PyTCP
PYTHONPATH=/root/PyTCP exec python -m unittest \
  $(find packages/<PKG>/<PKG>/tests/unit -name 'test__*.py')
```
`chmod +x /tmp/cr_runtests.sh`. Replace `<PKG>` with
`net_addr` / `net_proto` / `pytcp`.

### 2.2 cosmic-ray config — `/tmp/cr.toml`
```toml
[cosmic-ray]
module-path = "packages/<PKG>/<PKG>"
timeout = 10.0
excluded-modules = ["*/tests/*"]   # broken in 8.4.6 — see rail #4
test-command = "bash /tmp/cr_runtests.sh"

[cosmic-ray.distributor]
name = "local"
```

`cosmic-ray` ≥ 8.4 is in the venv (`./venv/bin/cosmic-ray`,
`cr-report`). The `local` distributor runs **serially** — do
NOT run concurrent `cosmic-ray exec` on the same tree: they
share the one source checkout and cross-contaminate each
other's in-place mutations. Real parallelism needs per-worker
git worktrees (rarely worth it for a small package).

---

## 3. Full-scan workflow (authoritative)

```bash
cd /root/PyTCP && source venv/bin/activate

# (a) preconditions: package source clean, pycache clear
git status -s
find packages -name __pycache__ -type d -exec rm -rf {} +

# (b) write the §2 files

# (c) capped-baseline smoke: the suite must PASS under the cap, fast
bash /tmp/cr_runtests.sh 2>&1 | tail -3      # expect "OK"

# (d) enumerate mutants, then DELETE test-module jobs (rail #4)
rm -f /tmp/cr.sqlite
PYTHONPATH=$(pwd) cosmic-ray init /tmp/cr.toml /tmp/cr.sqlite
PYTHONPATH=$(pwd) python3 - <<'PY'
import sqlite3; d=sqlite3.connect("/tmp/cr.sqlite")
tj=[r[0] for r in d.execute("select job_id from mutation_specs where module_path like '%/tests/%'")]
d.executemany("delete from work_items where job_id=?",[(j,) for j in tj])
d.executemany("delete from mutation_specs where job_id=?",[(j,) for j in tj])
d.commit()
print("source-only mutants:", d.execute("select count(*) from mutation_specs").fetchone()[0])
print("in_tests (must be 0):", d.execute("select count(*) from mutation_specs where module_path like '%/tests/%'").fetchone()[0])
PY

# (e) EXECUTE — background, resumable. Re-run the same exec to continue.
PYTHONPATH=$(pwd) nohup cosmic-ray exec /tmp/cr.toml /tmp/cr.sqlite > /tmp/cr_exec.log 2>&1 &
```

Poll progress + memory while it runs (a background watcher
loop that exits when the exec process is gone is cleanest —
do NOT busy-poll harness-tracked work):
```bash
PYTHONPATH=$(pwd) python3 -c "import sqlite3;d=sqlite3.connect('/tmp/cr.sqlite');print('done',d.execute('select count(*) from work_results').fetchone()[0])"
free -m | awk 'NR==2{print "avail "$7" MB"}'   # if < ~2 GB: pkill -9 -f cr_runtests
```

When complete, the **raw score = killed / total**:
```bash
PYTHONPATH=$(pwd) python3 -c "import sqlite3;d=sqlite3.connect('/tmp/cr.sqlite');k=d.execute(\"select count(*) from work_results where test_outcome='KILLED'\").fetchone()[0];t=d.execute('select count(*) from work_results').fetchone()[0];print(f'{k}/{t} = {100*k/t:.1f}%')"
```

---

## 4. THE headline finding — always report the ADJUSTED score

On a Python 3.14, annotation-dense, typed codebase the **raw
score badly understates the suite** because a large fraction
of survivors are **equivalent mutants** that *no runtime test
can ever kill*. Report raw AND equivalent-adjusted; the
adjusted number is the honest one. (net_addr: 80.5 % raw but
**95.2 %** once equivalents are excluded. pytcp Tier-2: ipc
64→68 % raw / **~98 %** adjusted; socket drop-in 39 % raw /
**~85 %** adjusted — the annotation-mutant fraction climbs
even higher on the typed runtime, e.g. socket drop-in had
~431 of 579 survivors in PEP 604 unions.)

Classify survivors with the rule below. The first two classes
are mechanically detectable; the rest require reading the
mutated line.

### Equivalent-mutant classes (un-killable — NOT gaps)

1. **PEP 604 union annotations under PEP 649 lazy eval**
   (`X | Y` → `X ** Y` in a param / return / `type` alias).
   3.14 stores annotations as un-evaluated closures, so these
   never run at runtime — mypy/pyright are their gate. On
   net_addr this was **814 of 1161 survivors**. Detect:
   `ReplaceBinaryOperator_BitOr_*` whose source line is a
   `def(...)` signature, a `name: Type` annotation, or a
   `type X = ...` alias. WILL recur on net_proto / pytcp.
2. **Type-only decorators** — `RemoveDecorator` of
   `@override` / `@overload` (zero runtime effect) and
   `@abstractmethod` (class stays abstract via siblings).
3. **Disjoint-bitfield combiners** — `a | b` → `^` / `+`
   where `a` and `b` provably share no set bits (EUI-64 field
   assembly, `prefix | iid` with a masked prefix, network
   address `+ host_offset` where host bits are zero,
   MAC-prefix | low-bytes). `|` ≡ `^` ≡ `+` on disjoint
   operands.
4. **Max-value / non-negative-domain comparisons** —
   `x == MAX` → `>=` where `x` can't exceed `MAX` (broadcast
   `== 0xFFFFFFFF`, `& single_bit_mask == bit`,
   `& full_top_byte_mask == 0xff00`); and `x == 0` → `<=`
   where `x ≥ 0` always (`int.from_bytes` results, masked
   values). The two coincide for the whole reachable domain.
5. **Interned-identity comparisons** — `==` → `is` on
   single-char strings (`spec[-1:] is "s"`), small ints
   (≤ 256), and enum singletons (`self.version is
   other.version`). CPython interns them, so `is` ≡ `==`.
6. **Reflected-operator-compensated guards** — breaking a
   single rich-comparison guard
   (`if not isinstance(...): return NotImplemented` →
   `if isinstance(...)`). When `a.__le__(b)` returns
   `NotImplemented`, Python falls back to `b.__ge__(a)`,
   which still yields the right answer. Un-killable unless
   *both* operators' guards break together.
7. **Backstopped bounds** — an off-by-one on an inner bound
   (`0 <= mask <= MAX`) that a *later* validation
   (`_is_contiguous_mask`, a regex, a re-parse) rejects on
   the same inputs.
8. **Dead-store assignments** — a value computed but never
   read on that branch (`prefixlen_diff = new_prefix -
   prefixlen` inside the branch that uses `new_prefix`).
9. **Random-output generators** — `from_rfc8981_temp` and
   the like: tests can only assert structural invariants
   (length, set bits, range avoidance), so the arithmetic
   that picks *which* random value is un-pinnable. Only the
   deterministic predicates around it (`_is_reserved_iid`)
   are killable — and those are killable **directly**, by
   calling the helper with crafted inputs, NOT by coaxing
   the generator into producing them (see §6 lesson).
10. **Result-preserving optimizations** (net_proto) — an
    internal fast path whose output is identical regardless
    of how it chunks. `inet_cksum`'s 8-byte loop:
    `(remainder := buffer_len - offset) >= 8` and `q_count =
    remainder >> 3` — mutating the chunk threshold (`>= 8` →
    `>= 9`) or the chunk count (`>> 3` → `>> 4`) only shifts
    bytes between the fast path and the remainder loop; the
    one's-complement sum is associative, so the checksum is
    byte-identical. Verify by confirming the mutant survives
    *every* consumer's round-trip test, then it is equivalent.
11. **Base-coincidence arithmetic** (net_proto) — a constant
    whose specific value makes an operator mutation coincide
    with the original on the entire *reachable* domain.
    Examples: ARP `hrtype == 0x0001` has byte 0 = 0, so
    reading `frame[1:2]` classifies identically to
    `frame[0:2]`; routing-header `routing_type == RH0` where
    `RH0 = 0` makes `<= 0` ≡ `== 0` on the byte domain; a
    pointer check where `POINTER_BASE == SLOT_LEN == 4` makes
    `(p - 4) % 4` ≡ `(p + 4) % 4`; IGMP max-resp-`code == 128`
    where the linear value (128) equals the float decode
    `(0|0x10) << 3` (128). Generalizes class 4 (max-value /
    non-negative). Killable only by an input the realistic
    wire never carries — usually low-value; confirm the
    coincidence arithmetically before deferring.
12. **Bounded-domain enum/mode comparisons** (pytcp Tier-2) —
    a `==` against one value of a small *closed* set, where
    the other members make `==`≡`>=` or `==`≡`<=` over the
    whole reachable domain. The canonical case is a sysctl
    mode read: `arp_ignore == 8` → `>= 8` is equivalent
    because the mode is one of `{0,1,2,8}` and 8 is the max;
    `arp_ignore == 2` → `>= 2` is equivalent inside the
    `else` arm where the domain is already narrowed to
    `{0,1,2}`. Generalizes class 4 to enum-valued domains.
    Killable only by a mode value the validator forbids —
    low-value; confirm the domain before deferring.
13. **`__debug__ and log(...)` guard operands** (pytcp) — the
    pervasive `__debug__ and log("chan", f"...")` tracing
    idiom. Tests mock `log`, so mutating the `and` → `or`,
    the f-string interpolation (`<<` → `*` inside the
    message), or the guard is invisible: the log call's
    *effect* is never asserted. Any survivor whose source line
    is inside a `__debug__ and log(` argument is equivalent.
    Dominant alongside class 1 on the handler shards.
14. **Idempotent re-assignment guards** (pytcp) — a `if x !=
    computed_value: x = computed_value` shape where the guard
    only gates a (mocked) log + a re-derivation that lands on
    the *same* value. Mutating the guard comparison (`!=` →
    `==`, `<<` → `^` in the RHS) changes only whether the
    branch is *entered*; the branch body re-assigns the
    correctly-computed value either way, so end state is
    identical. The value-bearing assignment line (not the
    guard) is the killable one — and it is usually already
    killed. (ARP/UDP RX window-update; the `snd_wnd != win <<
    wsc` guard.)
15. **Defensively-unreachable `case _:` / parser-rejected
    branches** (pytcp) — a handler `match` default that bumps
    an `op_unknown__drop` counter, where the *parser* (e.g.
    TX-strict `from_int(...).is_unknown`) already rejects the
    bad value upstream, so the default is dead via any
    realistic wire input. The `+= 1` NumberReplacer survives
    because no frame reaches it. Distinguish from a real gap
    by tracing whether the wire value can reach the line at
    all (grep the parser's reject path first).
16. **Keyword-only `*`-separator AST no-ops** (pytcp) —
    cosmic-ray reports a `ReplaceBinaryOperator_Mul_Div` on a
    `def f(self, *, arg)` line (the `*` is the kw-only marker,
    not a binary op). The mutation either no-ops or turns
    `*` into `/` (positional-only), and every call site passes
    the arg *by keyword* anyway, so behaviour is unchanged.
    Killable in principle by `inspect.signature(...).kind is
    KEYWORD_ONLY` (see the tcp/state `KeywordOnlySignatures`
    batch), but for runtime handlers the kw-only contract is
    low-value ceremony — defer unless the signature is a
    public API surface.
17. **Never-wrapping modular masks** (pytcp) — `(a - b) &
    0xFFFF_FFFF` on a sequence-delta / flight-size / RTT that
    never actually wraps in the tested range, so dropping or
    altering the mask (`& 0xFFFF_FFFF` → `// 0xFFFF_FFFF`,
    `<<`) yields the same value. Killable only by a 32-bit-
    wrap scenario the suite does not drive; usually equivalent
    in practice. Class-4 cousin for explicit wrap masks.

The remainder are **genuine gaps**. Triage each by reading
the mutated line; propose the test that would catch it.

---

## 5. Kill-proof discipline (MANDATORY before claiming a gap closed)

A survivor is only *confirmed real* — and a fix only
*confirmed working* — by this exact procedure. Eyeballing one
input or trusting a single test file is how false claims ship.

1. **Pull the EXACT surviving operator + occurrence**, not a
   guess. A line often has several mutants; you must target
   the one that *survived* (`Eq_LtE`, say), not a sibling
   (`Eq_Lt`) that is already killed. (Cost of skipping: I
   "kill-proved" `__contains__` on the bare-`Address` branch,
   which was already tested — the real survivor was the
   `IfAddr` branch.)
2. **Apply that mutation to the source** with `sed`.
3. **Clear `__pycache__`** (rail #3).
4. **Run the FULL package suite** (not the one test file).
   - *Before* adding your test it must **stay green** (OK) —
     proving the mutant genuinely survives.
   - *After* adding your test it must **FAIL** — proving the
     test kills it.
5. **`git checkout` the source + clear `__pycache__` again.**
6. Verify `git diff` on the package is empty before moving on.

**The self-referential-constant trap (net_proto, hit twice).**
When the gap is a `NumberReplacer` on a *constant definition*
(`TCP__MIN_MSS = 536` → `537`, `IP6__DEFAULT_HOP_LIMIT = 64`
→ `65`), the killing test MUST assert against the **literal**
value (`assert x == 536`), NOT against the imported constant
(`assert x == TCP__MIN_MSS`). Asserting against the constant
makes the expectation move *with* the mutation — both sides
change to 537, the assert still passes, the mutant survives.
This passed my first kill-proof for MIN_MSS and hop=64 and
looked closed; only re-running the survivor scan exposed it.
Assert the literal; optionally add a second
`assert THE_CONSTANT == 536` line to pin the constant by name
too.

**Use a Python harness for batches, not a shell loop**
(net_proto). A `cp/sed/run` shell loop — especially with
`r=$(kp ...)` command substitution or a trailing `| sort` —
can have its **restore step (`cp bak file`) race or get its
stdout eaten**, leaving a **stranded mutation on disk** (it
happened: 10 dhcp4 option files left with `<=` applied, then
the next iteration found nothing to substitute). A small
Python driver (`subprocess.run` per mutant, `open(f,"w")`
restore, `shutil.rmtree` pycache between) is deterministic
and prints each result; it never strands. Always
`git diff --stat` the package after a batch regardless
(rail #6).

---

## 6. Common real-gap patterns (where survivors actually cluster)

- **Whole-file / whole-thing omissions — CHECK THIS FIRST**
  (net_proto). The highest-value finds are not arithmetic at
  all: an entire source file (an option, a message, a codec)
  with **no dedicated test**, where *every* mutant in it
  survives. Line coverage shows it "covered" because the
  dispatch *imports* it, but its logic is never asserted. The
  net_proto audit found three — TCP FastOpen option, ICMPv6
  Packet Too Big, MLDv2 Query (185 survivors). **Before
  triaging individual operators, bucket survivors by source
  file and compare the count against a `find … -name
  'test__*<file>*'`** — a file with ~80–185 survivors and no
  test file is a whole-thing gap. Close it with the full
  per-file test (the §8 test-matrix in `unit_testing.md`),
  not a one-off; it converts the most mutants per unit effort.
- **The trailing-padding integrity bound — THE most prolific
  class at scale** (net_proto capstone, ~26 of 40 gaps across
  udp, icmp4 ×5, tcp, ip4, icmp6 ×6). Every length-bearing
  parser guards a *chained* bound of the shape
  `<PROTO>__LEN <= <declared_len> <= len(frame)` (the
  `<declared_len>` is the IP/UDP-layer payload length: `plen`,
  `ip__payload_len`, `ip6__dlen`). The parser **deliberately
  tolerates trailing lower-layer padding** — the second `<=`
  accepts `declared_len < len(frame)`. But the test harness's
  IP stub almost always hard-codes
  `payload_len = len(frame)` (and the `minimum_length_accepted`
  boundary fixture uses an exact-fit frame), so **no test ever
  has `declared_len < len(frame)`** — and the second
  comparison's `LtE_Eq` (`<=`→`==`) and `LtE_GtE` (`<=`→`>=`)
  mutants survive on *every* such parser. Symptom in the
  survivor scan: paired `ReplaceComparisonOperator_LtE_Eq` +
  `LtE_GtE` at the same `col` of the `... <= len(frame)`
  bound line, recurring identically across sibling message/
  protocol files. **Detect it** by grepping the integrity
  test for the stub default (`payload_len=len(frame)` /
  `dlen=len(frame)`); if every fixture fits exactly, the
  tolerance is unpinned. **Close it** with ONE
  `trailing_bytes_accepted` boundary test per parser: a valid
  *minimum* message (valid checksum over its own bytes) **plus
  N padding bytes**, with the IP stub's `payload_len` set to
  the *un-padded* length (`< len(frame)`); assert it parses.
  That single frame also exercises the *first* `<=` at
  equality (`<PROTO>__LEN == declared_len`), so it kills the
  min-length `LtE_Lt` survivor for free, and — because it
  drives the full parser — it kills the same mutant on *both*
  the parser-level and per-message bound lines at once (cf.
  tcp L81 + L93). Watch for messages with **no parser test at
  all** (icmp6 Packet Too Big): there the whole bound is
  unpinned and you add a fresh integrity-boundary file. The
  one harness wrinkle: combined `*__parser.py` files often use
  a simpler `_packet_rx_with_ip*(frame)` helper with no
  `payload_len` kwarg — extend it to
  `(frame, *, payload_len=None)` before adding the test.
- **The dispatch-guaranteed assert, untested everywhere**
  (net_proto). The `buffer[0] == int(Type)` / `from_bytes(...)
  == int(Type)` kind-byte assert at the top of every option's
  `from_buffer` was untested across ~30 options in 4 protocols
  (ip4 / dhcp4 / dhcp6 / accecn). The container dispatch
  *guarantees* the byte, so the assert never fires in normal
  flow — but `== Type` → `<=` / `>=` survives with no
  wrong-type test. One cheap shared batch: a wrong-type-below
  (e.g. `0x00`) and wrong-type-above (`0xff` / `0xffff`)
  `from_buffer` over a valid frame, expecting `AssertionError`.
  Detect the gap quickly by scripting the `<=` mutation across
  every option and re-running just that option's suite.
  **Half-closed is the common partial state** (capstone
  re-validation): an earlier pass often pins only ONE side —
  dhcp6 had wrong-type-*below* but not *above* (6 options →
  `Eq_GtE` survives), tcp had *above* but not *below* (5
  options → `Eq_LtE` survives). For an option with code `c`,
  `Eq_GtE` dies only on a byte `> c`, `Eq_LtE` only on a byte
  `< c`; a code-0 kind-byte (`EOL`/`PAD`) makes the *below*
  side vacuously equivalent (no byte `< 0`). Always check
  *which* direction survives and add the missing one. The
  same one-sided shape appears on `!=` field guards
  (`hrlen != 6`, `magic_cookie != COOKIE`, `ver != 4`):
  tested only *above* the value, `NotEq_Gt` survives until you
  add a *below* case — see "One-sided length boundaries".
- **Degenerate / weak fixtures.** The single most common
  *arithmetic* gap. A test asserts the right output but for an
  input where many mutations coincide:
  - **empty-data / zero-value operands** — an `X + len(data)`
    `__len__` asserted only with `data=b""` (so `X+0 == X-0`,
    the `+` → `-` survives); a timestamp slice asserted only
    with a top-byte-zero value (so `[+4:+8]` → `[+5:+8]` reads
    the same int); a header flag round-trip with only `rd` set
    (every other bit position unexercised). Use non-empty
    data, a top-byte-set value, **all flags distinct**.
  - all-zero-byte operands (MAC `02:00:00:...` hides EUI-64
    field-placement bugs) → use a non-degenerate operand
    (`aa:bb:cc:dd:ee:ff`).
  - a prefix that sets only some of the masked bits (a
    `2001:db8::/64` golden vector misses netmask bits 16–63)
    → add an **all-ones** prefix (`ffff:ffff:ffff:ffff::/64`)
    that exercises every masked bit.
  - same-value comparison pairs (`a == b` test where
    `a.field == b.field`) → use a pair that differs in the
    *field the mutation touches*.
- **One-direction-only relations.** Ordering tests that
  assert `a < b` but never `b < a` is False, nor reflexivity
  (`a <= a` True, `a < a` False), nor the sibling operators
  (`<=`/`>`/`>=`). The fix is a `total_order_relations` test
  asserting **every operator in both directions and
  reflexively** on a tiebreak pair. Recurs on every value
  type (`IpNetwork`, `IfAddr`, `Address`).
- **Inclusive-boundary cases.** A range check `0 <= r <= MAX`
  tested only with out-of-range inputs, never with results
  landing *exactly* on `0` or `MAX` (both valid). Add the
  exact-endpoint cases to pin the `<=` and the `- 1` max
  constant.
- **One-sided length boundaries** (net_proto). A fixed-length
  check `buffer[1] != LEN` whose only wrong-length test uses
  an *under*-length value — `<` and `!=` agree below `LEN`, so
  the `!=` → `<` mutant survives; it dies only on an
  *over*-length frame (`LEN+1`). Likewise a version/type check
  tested only *below* the value (DNS `ver=5`, ARP `hrtype=0`,
  ip6 `ver=5`): `!=` → `<` survives until you add an *above*
  case (`ver=7`). Always test wrong-value on **both** sides of
  a `!=`.
- **One-sided predicate tests.** A prefix predicate
  (`& mask == prefix`) tested with a None-case on only one
  side of the prefix. The `==`→`<=` mutant needs a *below*-
  prefix None case; `==`→`>=` needs an *above*-prefix one.
- **Untested format / error branches.** A `__format__`
  width/spec branch (`spec[-1:] == "s"`) never exercised, or
  an unknown-spec raise tested only with a spec on one side
  of the boundary char (`"zz"` ends > `"s"`; add `"zq"` which
  ends ≤ `"s"` so the `==`→`<=` mutant mis-routes and leaks a
  `ValueError`).
- **Directly-testable private helpers.** Do NOT defer a
  predicate as "un-reachable" because the *caller* rarely
  hits it. A module-level `(x: int) -> bool` (e.g.
  `_is_reserved_iid`) is directly callable from a test with
  crafted boundary values — tests may reach private names.
  Conflating "make the caller produce the input" (hard) with
  "test the helper directly" (trivial) is a real mistake made
  this session.

---

## 6.5 Shard archetypes & baseline economics (pytcp Tier-2)

The pytcp audit split into two archetypes with **opposite
ROI**, and recognising which one you are in *before* spending
compute is the single biggest Tier-2 lesson. The
discriminator is the **test surface**, not the source.

### Archetype A — thin-unit shards (high ROI, close gaps)

`lib`, `tcp-math`, `tcp/state`, `ipc` value codecs, the
`socket` drop-in. Logic reachable by a **fast unit test**
(<1 s baseline) over a constructed object. Survivors are
cheap to find and cheap to close; this is where mutation
testing pays for itself (ipc closed 69 gaps, socket drop-in
69). Run the full-scan workflow (§3) and close real gaps.

**Mock-construct the wrapper to get a fast baseline.** A
daemon-/IO-backed wrapper whose logic runs *before* the IO
(the `socket` drop-in: type-guards, `makefile` mode parsing,
factory dispatch, blocking-mode state) is unit-testable by
constructing it over a `create_autospec(Collaborator,
spec_set=True)` and patching the lazy accessor
(`patch.object(mod, "_get_default_stack", ...)`). This turned
a 6.7 s daemon-integration baseline into a 0.4 s unit
baseline and let 69 gaps close fast. Always check whether the
"needs a daemon/socket" surface actually needs one for the
*branch under test*.

### Archetype B — integration-saturated shards (audit, don't grind)

`tcp/session`, `tcp/fsm`, `runtime/packet_handler`. Logic
driven only by the integration suite (FSM state, wire RX→TX,
stat counters). Two sub-cases:

- **Baseline-bound (session/fsm)** — the *only* test surface
  that exercises the logic is the slow whole-protocol suite
  (TCP: 590 tests / 33 s). A per-collaborator *seam* test
  (3 tests / 792 LOC) is **NOT a valid mutation baseline** —
  it under-reports ~15× (ack: **4.7 % seam vs 33–73 %
  full-suite** on the same survivors). Exhaustive closure is
  ~46 h of serial compute and mostly re-confirms saturation.
  **Audit, don't grind:** sample survivors against the *full*
  suite to get the true rate, classify the residue, close
  **one kill-proven demonstrator** (recover-marker decay),
  and document the recommendation (opportunistic backlog).
- **Per-protocol-auditable (packet_handler)** — each protocol
  *does* have a green-in-isolation, fast suite (arp/udp
  ~3.6 s), so a handler file mutation-tests cleanly against
  its own protocol's suite. Worked examples (arp, udp) both
  landed at **~76 % adjusted**: the suites assert exact
  `packet_stats` counters on every branch, so branch/counter
  mutations die. Residue is annotation (class 1) + log guards
  (class 13) + bounded-mode (class 12) + low-density genuine
  gaps on **under-tested branches the suite's topology never
  reaches** (a sysctl mode on a single-subnet topology, a
  multi-socket fan-out, an error-emit selection). Close those
  *opportunistically* with a scenario test; a full 20-handler
  sweep is auditable but low-yield.

### The baseline-choice rule

**Pick the smallest test surface that genuinely exercises the
mutated logic.** A seam/parity test that only pins the
*refactor boundary* (e.g. "the collaborator is wired in")
exercises ~5 % of the code and yields a meaningless 5 % score.
Before trusting a per-mutant number, sanity-check the baseline:
grep the candidate test for assertions on the *behaviour* the
mutated lines produce. If it only asserts wiring/identity,
escalate to the protocol's full integration suite — and if
*that* is the only adequate surface and it is slow, switch from
"close every gap" to "sample + classify + one demonstrator".

### Reporting integration-saturated shards

Put them in the per-shard table with the real (sampled)
adjusted rate, a `†`/`‡` footnote stating the baseline caveat
(seam-under-reports / sampled-not-exhaustive), and a status of
`AUDITED` rather than `DONE`. The honest deliverable is the
*finding* (this code is integration-saturated; here is the
true rate; here is one demonstrator; the rest is opportunistic)
— not a forced exhaustive grind.

---

## 7. Deliverable — the results document

Write `docs/refactor/<pkg>_mutation_audit_results.md`:

1. **Summary table** — total / killed / survived, **raw AND
   equivalent-adjusted** score, per-module score (surfaces
   the weakest files).
2. **Equivalent-class accounting** — quantify each §4 class
   (annotation-`|`, decorators, disjoint bitfields, …) so the
   raw-vs-adjusted gap is explained, not hand-waved.
3. **Survivor ledger** — for each genuine gap: `module:line`,
   operator, mutated diff, and the proposed test (mark
   "kill-proven" where §5 was run).
4. **Honest residual statement** — do NOT claim "all
   equivalent". List the genuinely-killable-but-deferred
   items (intricate / low-value) explicitly. The full re-scan
   *will* surface anything you waved off.

When the user asks to *close* the gaps too, each correction
is one tests-first change: kill-prove (§5) → add the test →
`make lint` + the §7.2 docstring audit + full `make test` →
commit (test-only; cite the mutation it kills). Commit
message convention: name the surviving mutation(s) the test
now pins.

---

## 8. Re-scan to verify (fast)

After adding tests, do NOT re-run all mutants — only the
*previously surviving* ones can change (added assertions can
only turn survivors into kills, never the reverse). Clone the
sqlite, delete the `SURVIVED` results to re-queue exactly
those jobs, and re-exec:
```bash
cp /tmp/cr.sqlite /tmp/cr2.sqlite
find packages -name __pycache__ -type d -exec rm -rf {} +
PYTHONPATH=$(pwd) python3 -c "import sqlite3;d=sqlite3.connect('/tmp/cr2.sqlite');d.execute(\"delete from work_results where test_outcome='SURVIVED'\");d.commit()"
PYTHONPATH=$(pwd) nohup cosmic-ray exec /tmp/cr.toml /tmp/cr2.sqlite > /tmp/cr2.log 2>&1 &
```
~10× faster than a full scan. Cross-reference baseline-vs-new
survivor sets to see exactly which mutants your tests newly
killed — and to catch fixtures that *didn't* kill what you
claimed (this caught two of my own ineffective fixtures).

Run a **full from-scratch scan** only for the final
authoritative number, and after it: re-check that every line
you targeted is cleared of its killable mutants, and
`git diff` the package for stranded mutations (rail #6).

---

## 9. Cleanup + completion criteria

```bash
find packages -name __pycache__ -type d -exec rm -rf {} +
git diff --stat -- packages/<PKG>/<PKG> ':(exclude)packages/<PKG>/<PKG>/tests/'   # MUST be empty
rm -f /tmp/cr*.toml /tmp/cr_runtests.sh /tmp/cr*.sqlite /tmp/cr*.log
```

**Done when:** results doc written, raw + adjusted score
reported, package *production* source pristine, full suite
green, every claimed gap kill-proven, residual honestly
characterised.

---

## 10. Self-verification checklist

- [ ] Test-command was the FULL package suite (not a subset).
- [ ] `ulimit -v` cap was in the runner; no OOM, no abnormal
      worker outcomes.
- [ ] Test-module jobs deleted; `in_tests` was 0.
- [ ] Every kill-proof ran the full suite with `__pycache__`
      cleared, targeting the EXACT surviving operator.
- [ ] Reported BOTH raw and equivalent-adjusted score.
- [ ] Equivalent classes quantified, not hand-waved.
- [ ] Residual survivors honestly listed (no "all
      equivalent" claim unless every one is verified).
- [ ] `git diff` on the package is empty (no stranded
      mutation, no production-source change).
- [ ] Each correction is a test, kill-proven, committed
      test-only.

## 11. Cross-references

- `docs/refactor/net_addr_mutation_audit.md` — the worked
  runbook this skill generalises.
- `docs/refactor/net_addr_mutation_audit_results.md` — the
  exemplar results document (per-module table, equivalent
  ledger, kill-proven corrections).
- `docs/refactor/net_proto_mutation_audit.md` /
  `…_results.md` — the at-scale precedent (21 sharded runs,
  dependency-scoped test-commands, whole-file gaps, the
  per-shard score table + deep-TLV follow-up seam).
- `docs/refactor/pytcp_mutation_audit_results.md` — the
  Tier-1/Tier-2 precedent for the §6.5 archetype split:
  thin-unit shards (lib / tcp-math / tcp-state / ipc / socket
  drop-in, gaps closed) vs integration-saturated shards
  (session/fsm baseline-bound + audited; packet_handler
  per-protocol-auditable at ~76 % adjusted). Worked examples
  of the mock-construct fast baseline and the seam-under-
  reports caveat.
- `.claude/rules/unit_testing.md` — test authoring (the
  corrections land as unit tests; §7.2 docstring audit, §6a
  mocking, tight assertions).
- `.claude/rules/feature_implementation.md` §2 — tests-first
  discipline the corrections follow.
- `.claude/rules/typing.md` §20 / `python_features.md` §17 —
  why PEP 649 lazy annotations make union-`|` mutants
  equivalent (the §4.1 class).
