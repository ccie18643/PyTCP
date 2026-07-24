# net_addr — Full Mutation-Test Audit (runbook)

**Goal.** Run cosmic-ray mutation testing over the **entire `net_addr`
package** against the **full `net_addr` unit suite**, then report the
mutation score, the surviving mutants (triaged equivalent-vs-real-gap),
and **propose** concrete corrections for the real gaps. **Do not apply
fixes; do not commit; do not push.** Produce a results document and stop.

This runbook is self-contained and meant to be executed **unattended** —
kick off the run, monitor memory, wait for completion, then triage and
report. Only stop at the very end.

---

## 0. Measured baseline (from 2026-06-07, branch `PyTCP_3_0_8`)

| Fact | Value |
|---|---|
| net_addr non-test modules | 24 (4 894 lines) |
| net_addr unit suite | 2 617 tests, **~0.31 s** |
| cosmic-ray mutants (whole pkg) | 10 653 total |
| …in test modules (exclude) | 4 685 |
| **source-only mutants (the target)** | **5 968** |
| Est. runtime (sequential, capped) | **~30–60 min** (5 968 × ~0.31 s + hang penalties) |

cosmic-ray ≥ 8.4 is installed in the venv (`./venv/bin/cosmic-ray`,
`cr-report`). If missing: `pip install cosmic-ray`.

---

## 1. HARD SAFETY RAILS (each one is a lesson learned the hard way)

These are non-negotiable. Skipping any of them caused a real failure in
the trial run that produced this plan.

1. **Memory cap per worker (`ulimit -v`).** Arithmetic mutants can turn
   `a - b` into `a ** b` → a multi-GB integer that OOMs the host. The
   test-command runs under `ulimit -v 3145728` (3 GB) so such a mutant
   dies fast with `MemoryError` (counted as *killed*) instead of taking
   the machine down. **Monitor `free -h` during the run anyway.**
2. **Test scope = the FULL net_addr suite, not per-module tests.** A
   narrow test-command makes cosmic-ray report **false-positive
   survivors** (mutants the broader suite would kill). Running the whole
   net_addr unit suite per mutant means every surviving mutant is a
   *genuine* behavioural gap that **no net_addr test anywhere** catches.
3. **Clear `__pycache__` before the run AND after any manual mutation.**
   A stale `.pyc` left by an earlier mutate→revert cycle makes a later
   suite run execute the *old* bytecode → spurious failures. Always
   `find packages -name __pycache__ -type d -exec rm -rf {} +` before
   trusting a result.
4. **Per-mutant timeout backstop** (`timeout = 10.0`): for the rare
   non-allocating infinite loop the `ulimit` would not catch.
5. **Leave net_addr SOURCE pristine.** cosmic-ray mutates files in place
   and reverts each mutant, but a crash can leave a mutant on disk. At
   the end, `git diff --stat -- packages/net_addr` MUST be empty; if not,
   `git checkout -- packages/net_addr/net_addr`. ("Clean" means net_addr
   *source* is unmodified — the new `docs/refactor/*` artifacts are
   expected untracked files, that's fine.)
6. **No auto-fix, no commit, no push.** The deliverable is a *report with
   proposed corrections*. The human decides what to apply.

---

## 2. Setup (exact files)

### 2.1 Memory-capped runner — `/tmp/cr_na_runtests.sh`
```bash
#!/bin/bash
ulimit -v 3145728            # 3 GB virtual-memory cap per worker
cd /root/PyTCP
PYTHONPATH=/root/PyTCP exec python -m unittest \
  $(find packages/net_addr/net_addr/tests/unit -name 'test__*.py')
```
`chmod +x /tmp/cr_na_runtests.sh`

### 2.2 cosmic-ray config — `/tmp/cr_na.toml`
```toml
[cosmic-ray]
module-path = "packages/net_addr/net_addr"
timeout = 10.0
excluded-modules = ["*/tests/*"]
test-command = "bash /tmp/cr_na_runtests.sh"

[cosmic-ray.distributor]
name = "local"
```

> **Verify `excluded-modules` actually works** before the long run (the
> glob syntax matters). After `init` (step 3), the source-only mutant
> count must be **~5 968**, i.e. zero mutants whose `module_path LIKE
> '%/tests/%'`. If tests are NOT excluded, fix the pattern (try
> `["packages/net_addr/net_addr/tests/**"]` or
> `["*net_addr.tests*"]`) and re-init.

---

## 3. Runbook (execute top-to-bottom, unattended)

```bash
cd /root/PyTCP && source venv/bin/activate

# (a) preconditions
git status -s                       # net_addr source must be clean
find packages -name __pycache__ -type d -exec rm -rf {} +   # rail #3

# (b) write the two files from §2.1 / §2.2, chmod +x the runner

# (c) capped-baseline smoke: the suite must PASS under the 3 GB cap, fast
bash /tmp/cr_na_runtests.sh 2>&1 | tail -3      # expect "OK", ~0.3 s

# (d) enumerate mutants
rm -f /tmp/cr_na.sqlite
PYTHONPATH=$(pwd) cosmic-ray init /tmp/cr_na.toml /tmp/cr_na.sqlite
# verify scope: source-only count, zero test mutants
PYTHONPATH=$(pwd) python3 -c "import sqlite3;d=sqlite3.connect('/tmp/cr_na.sqlite');\
print('total',d.execute('select count(*) from mutation_specs').fetchone()[0],\
'in_tests',d.execute(\"select count(*) from mutation_specs where module_path like '%/tests/%'\").fetchone()[0])"
# EXPECT: total ~5968  in_tests 0   (if in_tests>0, fix excluded-modules + re-init)

# (e) EXECUTE — background. ~30–60 min. cosmic-ray is resumable: re-run
#     this same command if it is ever interrupted; it continues.
PYTHONPATH=$(pwd) cosmic-ray exec /tmp/cr_na.toml /tmp/cr_na.sqlite
```

While (e) runs: **poll every few minutes** —
```bash
free -h | awk 'NR==2{print "avail="$7}'                       # must stay healthy
PYTHONPATH=$(pwd) cr-report /tmp/cr_na.sqlite 2>&1 | tail -3   # complete % + survivors
ps aux --sort=-%mem | awk 'NR==2{print $4"% "$11}'            # no runaway > ~3 GB
```
If any process blows past ~3 GB (ulimit failure), kill it (`pkill -9 -f
cr_na_runtests`) and stop — do not let it OOM the host.

---

## 4. Collect + triage survivors

When `cr-report` shows `complete: 100%`:

```bash
PYTHONPATH=$(pwd) cr-report /tmp/cr_na.sqlite 2>&1 | tail -4   # score + survivor count
```

Pull every survivor with module / line / mutated diff:
```bash
PYTHONPATH=$(pwd) python3 - <<'PY'
import sqlite3
d=sqlite3.connect("/tmp/cr_na.sqlite"); d.row_factory=sqlite3.Row
q="""SELECT s.module_path, s.operator_name, s.start_pos_row, r.diff
     FROM mutation_specs s JOIN work_results r ON s.job_id=r.job_id
     WHERE r.test_outcome='SURVIVED' ORDER BY s.module_path, s.start_pos_row"""
for row in d.execute(q):
    op=row["operator_name"].split("/")[-1]
    print(f'{row["module_path"]}:{row["start_pos_row"]}  [{op}]')
    for l in (row["diff"] or "").splitlines():
        if l[:1] in "+-" and l[:3] not in ("+++","---"): print("   ",l.strip())
PY
```

**Triage each survivor into one of two buckets** (this is the manual,
reasoning-heavy part — the irreducible cost of mutation testing):

- **Equivalent mutant (noise — no correction).** The mutation changes
  the code but provably not the behaviour, so *no* test can kill it.
  Typical net_addr cases:
  - a comparison guarded by an earlier branch that makes the boundary
    unreachable (e.g. `< vs <=` after an `== HALF` early-return);
  - `& vs %` / `+ vs -` on a value whose domain makes them coincide;
  - a mutation inside an `assert` message / unreachable validation arm;
  - `__repr__`/`__str__` cosmetic text not asserted verbatim anywhere.
  Justify *why* it is equivalent in one line.
- **Real gap (propose a correction).** Two sub-kinds, both worth fixing:
  1. **Behavioural hole** — no net_addr test pins this behaviour at all.
     Propose the **specific unit test** (value-class parameterized case,
     per `unit_testing.md` §4) that would kill it.
  2. **Self-sufficiency hole** — the behaviour is correct but only a
     *sibling* module's tests cover it (a `net_addr.X` invariant pinned
     only by `net_addr.Y`'s tests). Propose adding the direct case to
     `X`'s own test file. (This is exactly the `in_range32`/SACK finding
     from the trial.)

For each proposed test, **prove it** the safe way: apply the mutation by
hand (`sed`), run the net_addr suite, confirm the new test FAILS, then
`git checkout` the source **and clear `__pycache__`** (rail #3 — the
revert leaves stale bytecode otherwise).

---

## 5. Deliverable — `docs/refactor/net_addr_mutation_audit_results.md`

Write a results doc containing:

1. **Summary table** — total mutants, killed, survived, **mutation score
   overall and per module** (a per-module score surfaces the weakest
   files). Query: group survivors/total by `module_path`.
2. **Survivor ledger** — one row per survivor: `module:line`, operator,
   mutated diff, **classification** (equivalent / behavioural-gap /
   self-sufficiency-gap), and a one-line justification.
3. **Proposed corrections** — for every real-gap survivor, the concrete
   test snippet (or, rarely, code fix) that closes it, ready to paste,
   ordered by module. Mark each "kill-proven" if §4 verification was run.
4. **Overall assessment** — net_addr's test-suite quality in plain terms,
   the count of genuine gaps vs equivalent noise, and a prioritized
   correction list.

---

## 6. Cleanup + completion criteria

```bash
find packages -name __pycache__ -type d -exec rm -rf {} +     # rail #3
git diff --stat -- packages/net_addr                          # MUST be empty
# if dirty: git checkout -- packages/net_addr/net_addr   (mutation leftover)
rm -f /tmp/cr_na.toml /tmp/cr_na_runtests.sh                  # keep /tmp/cr_na.sqlite for reference
PYTHONPATH=$(pwd) python -m unittest $(find packages/net_addr/net_addr/tests/unit -name 'test__*.py') 2>&1 | tail -2  # still green
```

**Done when:** results doc written, net_addr source pristine
(`git diff -- packages/net_addr` empty), net_addr suite green. Then
present a short summary (score, # real gaps, top proposed corrections)
and **stop** — no fixes applied, no commits, no push. The human reviews
the proposals and decides.

---

## 7. Notes

- cosmic-ray's `exec` is **resumable** — if the run dies, re-run the same
  `exec` command and it continues from the unfinished mutants.
- If runtime balloons past ~2 h (many hang-mutants), accelerate by
  splitting into per-module sessions run concurrently
  (`xargs -P $(($(nproc)-2))`), each with its own `module-path`, config,
  and sqlite, **all using the same full-suite runner** (rail #2). Not
  expected to be necessary at a 0.31 s suite.
- cosmic-ray stays out of `make lint` / `requirements_dev.txt` — mutation
  testing is a periodic manual audit, never a gate.
