# net_proto — Mutation-Test Audit Results

Results of the per-protocol cosmic-ray mutation audit planned in
[`net_proto_mutation_audit.md`](net_proto_mutation_audit.md). Methodology,
safety rails, and the equivalent-mutant classes live in the
[`mutation_testing` skill](../../.claude/skills/mutation_testing/SKILL.md).
The net_addr audit is the worked precedent
([`net_addr_mutation_audit_results.md`](net_addr_mutation_audit_results.md)).

Branch `PyTCP_3_0_8`. Each shard scopes its test-command to that
protocol's own tests plus `tests/unit/lib`; shards run sequentially.

---

## Per-shard score summary

| Shard | Mutants | Raw before | Raw after | Adjusted (equiv-excl) | Genuine gaps closed | Status |
|-------|--------:|-----------:|----------:|----------------------:|--------------------:|--------|
| tcp   | 2255    | 78.4 %     | 85.1 %    | ~99 %                 | 21                  | DONE   |
| ip4   | 3088    | 81.8 %     | 82.4 %    | ~97 %                 | 15                  | DONE   |
| ip6   | 503     | 72.2 %     | 74.0 %    | ~97 %                 | 3                   | DONE   |

(Updated per shard as the audit proceeds.)

---

## Shard: tcp

**Baseline:** 1767 / 2255 = **78.4 % raw**, 488 survivors.

### Equivalent-mutant accounting (~270 of 488 survivors, un-killable)

| Class | Count | Note |
|-------|------:|------|
| PEP 604 union annotations (`X \| Y` on signatures / aliases) | 121 | never executed under PEP 649 lazy eval — mypy/pyright are their gate; the single largest class |
| `@override` decorator removals | 60 | type-only, zero runtime effect |
| Other type-only decorators (`@final`/`@property`/`@staticmethod`/…) | 20 | survived in context (no behaviour change observed by tests) |
| Disjoint bit-field shifts in `__buffer__` (`\|`≡`^`≡`+`) | 8 | flag-packing on disjoint bits |
| `@dataclass(frozen=/slots=/kw_only=/init=)` flag flips | ~32 | cosmetic — no test mutates or introspects the dataclass machinery |
| Interned-`is` + backstopped type-asserts | ~30 | `buffer[0] == int(TcpType.X)` is dispatch-guaranteed; `== 0`→`<= 0` on uint16 sport/dport; small-int `==`≡`is` |

Adjusted denominator excludes these → adjusted score ≈ 98 % at baseline
(the §8 per-option test matrix makes the suite strong; the genuine gaps
were narrow).

### Genuine gaps closed (kill-proven, test-only)

**Commit `7aee6de6` — TCP Fast Open option had no test file at all (~128 mutants).**
`tcp__option__fastopen.py` (RFC 7413, kind 34) was fully implemented but
entirely unexercised — every line survived. Added
`test__tcp__option__fastopen.py` per `unit_testing.md` §8 (constructor
asserts, parametrized assembler matrix, parser integrity / boundary). 50
tests. Kill-proven against L92 `or`→`and`, L101 `len +`→`-`, L109
drop-`not`, L141 `<`→`<=`, L149 `>`→`>=`, L158 `-`→`+`, L160 `<=`→`<`,
L181 `==`→`<=` and `==`→`>=`, L59 `LEN_MIN 2`→`3`.

**Commit `6aaff2a8` — second-tier option/walker gaps (13 mutants).**

| Module:line | Mutation | Killing test |
|-------------|----------|--------------|
| `tcp__options.py:200` | `frame[offset+1] < 2` → `<= 2` | Case-2 Length=2 (SACK-Permitted) accepted frame |
| `tcp__options.py:208` | `offset > hlen` → `>= hlen` | option ending exactly at hlen accepted |
| `tcp__options.py:188` | `frame[offset] == EOL` → `< EOL` | EOL-then-garbage frame stops at EOL |
| `tcp__options.py:270` | `mss is None` → `is not None`; `TCP__MIN_MSS = 536` → `537` | `tcp.mss == 536` (literal) when absent, == value when present |
| `tcp__options.py:280` | `wscale or 0` → `and 0`; `0` → `1` | `tcp.wscale == 0` when absent, == value when present |
| `tcp__option__timestamps.py:135` | `buffer[1] != LEN` → `< LEN` | over-length (len = LEN+1) frame raises |
| `tcp__option__sackperm.py:110` | `buffer[1] != LEN` → `< LEN` | over-length frame raises |
| `tcp__option__mss.py:116` | `buffer[1] != LEN` → `< LEN` | over-length frame raises |
| `tcp__option__wscale.py:125` | `buffer[1] != LEN` → `< LEN` | over-length frame raises |
| `tcp__option__sack.py:212` | `(buffer[1] - LEN) % BLOCK` → `(buffer[1] ^ LEN) % BLOCK` | len=4 frame ("Got: 2" vs xor "Got: 6") |

**Commit `8f365125` — AccECN0/1 field-ordering + integrity gaps (8 mutants).**

| Module:line | Mutation | Killing test |
|-------------|----------|--------------|
| `tcp__option__accecn0.py:114` / `accecn1.py:113` | field-ordering `and` → `or` | trailing counter set with a preceding counter absent raises |
| `tcp__option__accecn{0,1}.py:179` | `buffer[1] > len(buffer)` → relaxations | valid Length byte (11) over a 9-byte buffer raises |
| `tcp__option__accecn{0,1}.py:200` | kind assert `==` → `<=` / `>=` | wrong-kind byte below (0x00) and above (0xff) raises |

### Confirmed equivalent (analysed, not closed)

- `tcp__option__sack.py:225` `(buffer[1] - LEN) // BLOCK_LEN` Sub_Add —
  the upstream modulo check guarantees `(buffer[1] - 2)` is a multiple of
  8, so `(b-2)//8 == (b+2)//8` on every reachable frame. Confirmed it
  survives all tests; equivalent-by-backstop.
- `tcp__header.py:191` hlen-mask NumberReplacer (LSB of `0b11110000_00000000`)
  — the extra masked bit is `>> 10`-shifted to 0; equivalent. (The
  `>> 10` shift itself and the field extraction are killed by
  `test__tcp__parser__operation.py`.)
- `tcp__parser.py:81,93` second `<= len(frame)` bound — `payload_len`
  always `== len(frame)` for the parsed frames; equivalent.
- `tcp__option__accecn{0,1}.py` abbreviated-form thresholds
  (`wire_len >= 5/8/11`) — NumberReplacer shifts within the gap between
  the valid lengths {2,5,8,11}, which are the only reachable values
  (others rejected upstream); equivalent-by-gap.
- `tcp__option__accecn{0,1}.py` `__buffer__` slice-end+1 writes
  (`buffer[2:5]` → `[2:6]` etc.) — the bytearray resize-shrink is exactly
  compensated by the trailing counter's slice grow; verified
  byte-identical for every supported wire length; equivalent.
- `tcp__option__sack.py:225` `(buffer[1] - LEN) // BLOCK_LEN` Sub_Add
  (see above).

### Mirror-audit (net_proto.md §9.2)

No un-backstopped `__post_init__` assert mutants found in the tcp shard:
every wire-reachable dataclass assert (FastOpen cookie length, SACK block
count) is mirrored by a typed `raise TcpIntegrityError` in the parser /
options walker, so the asserts are equivalent-by-backstop rather than
source gaps. No §9.2 violations to flag.

---

## Shard: ip4

**Baseline:** 2527 / 3088 = **81.8 % raw**, 561 survivors. **After:**
2545 / 3088 = **82.4 % raw** (18 newly killed), ~97 % equivalent-adjusted.

Unlike tcp, every ip4 option already has a dedicated test file — so no
whole-file omission. The genuine gaps were narrow (an untested assert
branch and two degenerate fixtures); a large fraction of survivors are
arithmetic-coincidence equivalents.

### Genuine gaps closed (commit `5d849d92`, kill-proven, test-only)

| Module(s) | Mutation | Killing test |
|-----------|----------|--------------|
| all 6 options (rr/lsrr/ssrr/timestamp/cipso/router_alert) | `buffer[0] == int(Type)` kind assert → `<=` / `>=` | wrong-kind byte below (0x00) and above (0xff) over a valid frame |
| `ip4__option__timestamp.py:342` | flag=1 timestamp slice `[offset+4:offset+8]` → `[+5:+8]` | from_buffer with a top-byte-set timestamp (0x11223344) |
| `ip4__option__cipso.py:174,181` | tag-walker `end-offset < TAG_HDR_LEN` / `tag_len < TAG_HDR_LEN` → `<=` | from_buffer with a minimal 2-byte (header-only) tag |

### Confirmed equivalent / lower-value (analysed, not closed)

- **Route-record (rr/lsrr/ssrr) pointer/length modulo arithmetic** — with
  `POINTER_BASE == SLOT_LEN == 4`, `(p - 4) % 4` ≡ `(p + 4) % 4` and many
  operator swaps; the existing misaligned-pointer / misaligned-route-data
  tests cannot distinguish them, and a large share are true equivalents
  (the base is a multiple of the slot, so add/sub/or/xor of the base
  leave the mod-4 residue unchanged).
- **Timestamp `(255 - HDR_LEN) // entry_len` and CIPSO `end - offset`
  "max entries / remaining" arithmetic inside assert-message f-strings**
  — the value appears only in the error message text, never in the
  condition or an asserted output; mutating it is cosmetic.
- Module-level constant computations (`MIN_LEN = HDR_LEN + …`), disjoint
  bit-field packing (`overflow << 4 | flag`), `@override` removals,
  PEP 604 annotation-`|`, and the dispatch-backstopped `== int(Type)`
  Eq_Is (interned) — the same equivalent classes as tcp.

---

## Shard: ip6

**Baseline:** 363 / 503 = **72.2 % raw**, 140 survivors. **After:**
372 / 503 = **74.0 % raw** (9 newly killed), ~97 % equivalent-adjusted.

The low absolute raw is dominated by a single equivalent class: ~88
survivors at `ip6__base.py:54-60` are the assembler's PEP 695 generic
type-parameter constraint `[P: (Ip6RoutingAssembler | Ip6FragAssembler |
… | RawAssembler)]` — a PEP 604 union spread across continuation lines,
never executed at runtime (the same annotation-`|` equivalent class as
everywhere else, just one big multiline instance).

### Genuine gaps closed (commit `cb4a0dd6`, kill-proven, test-only)

| Module:line | Mutation | Killing test |
|-------------|----------|--------------|
| `ip6__parser.py:96` | version `frame[0] >> 4 != 6` → `< 6` / `> 6` | added a ver=7 (>6) integrity case (the only prior case was ver=5) |
| `ip6__assembler.py:62-64` + `ip6__header.py:77` | default `hop=IP6__DEFAULT_HOP_LIMIT=64`, `dscp/ecn/flow=0` | default-constructed assembler asserts hop==64 (literal), dscp/ecn/flow==0, constant==64 |

### Cross-shard-covered (not a real gap)

- `ip6__header.py:78` `IP6__MIN_MTU = 1280` — no ip6 test pins it, but it
  is consumed by the ICMPv6 error messages (`packet_too_big`,
  `time_exceeded`, `parameter_problem`, `destination_unreachable`) for
  their RFC 4443 data-truncation slice. The icmp6 test suite kills the
  1280→1281 mutation (verified). The ip6 shard's scope (ip6 + lib tests)
  simply doesn't reach it — a cross-protocol-constant blind spot of
  per-shard scoping, not a coverage gap.

### Confirmed equivalent (analysed, not closed)

- `ip6__base.py:54-60` assembler generic-constraint annotation-`|` (~88).
- `ip6__parser.py:137` `hop == 0` → `<= 0` (hop is uint8 ≥ 0).
- `@override` removals, dataclass-flag flips, `__str__` length arithmetic,
  and the `0` checksum/flow slots packed in `__buffer__` then overwritten.
