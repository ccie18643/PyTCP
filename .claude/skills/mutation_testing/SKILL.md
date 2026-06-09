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

The canonical worked example is the net_addr audit
(2026-06-08): **78.2 % → 80.5 % raw**, **92.4 % → 95.2 %
equivalent-adjusted**, 14 test-only commits. The runbook
and results live at
`docs/refactor/net_addr_mutation_audit.md` and
`docs/refactor/net_addr_mutation_audit_results.md`.

## When to invoke

- A user asks to "mutation test", "run cosmic-ray", or
  measure/improve a package's test thoroughness beyond line
  coverage.
- Hardening a value-type library (`net_addr`), a wire codec
  (`net_proto`), or any pure-logic module where correctness
  hinges on exact comparisons / boundaries / bit operations.
- Re-confirming a package after a round of test additions
  (use the fast survivor-only re-scan, §8).

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

2. **Test-command = the FULL package unit suite, never a
   narrower scope.** A narrow test-command reports
   **false-positive survivors** — mutants the broader suite
   would kill. (The trial run scoped to one test file and
   "found" a survivor that the sibling SACK tests already
   killed.) Running the whole package suite per mutant means
   every survivor is a *genuine* gap no test anywhere
   catches.

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
**95.2 %** once equivalents are excluded.)

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

For a batch of kill-proofs, wrap each in a function that
clears pycache between iterations — a tight `cp/sed/run`
loop within the same filesystem-mtime second WILL reuse a
stale `.pyc` and lie to you.

---

## 6. Common real-gap patterns (where survivors actually cluster)

- **Degenerate / weak fixtures.** The single most common
  real gap. A test asserts the right output but for an input
  where many mutations coincide:
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
- `.claude/rules/unit_testing.md` — test authoring (the
  corrections land as unit tests; §7.2 docstring audit, §6a
  mocking, tight assertions).
- `.claude/rules/feature_implementation.md` §2 — tests-first
  discipline the corrections follow.
- `.claude/rules/typing.md` §20 / `python_features.md` §17 —
  why PEP 649 lazy annotations make union-`|` mutants
  equivalent (the §4.1 class).
