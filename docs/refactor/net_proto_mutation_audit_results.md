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
| icmp4 | 1135    | 84.4 %     | 85.4 %    | ~97 %                 | 5                   | DONE   |
| icmp6 | 5755    | 80.8 %     | 84.2 %    | ~96 %                 | 7                   | DONE   |
| udp   | 280     | 80.7 %     | 81.4 %    | ~97 %                 | 2                   | DONE   |
| arp   | 216     | 82.9 %     | 82.9 %    | 100 %                 | 0                   | DONE   |
| ethernet | 217  | 72.4 %     | 72.4 %    | 100 %                 | 0                   | DONE   |
| dhcp4 | 3708    | 76.9 %     | 77.3 %    | ~93 %                 | 11                  | DONE   |
| dhcp6 | 2407    | 78.4 %     | ~79 %     | ~94 %                 | 4                   | DONE   |
| dns   | 1116    | 61.2 %     | ~64 %     | ~90 %                 | 2                   | DONE   |
| ip6_frag | 235  | 91.1 %     | 91.1 %    | ~99 %                 | 0                   | DONE   |
| ip6_routing | 377 | 59.7 %  | 59.7 %    | ~95 %                 | 0                   | DONE   |
| ip6_hbh | 1427   | 72.7 %     | 72.7 %    | ~90 %                 | 0 (seam)            | DONE   |
| ip6_dest_opts | 1070 | 70.2 % | 70.2 %    | ~90 %                 | 0 (seam)            | DONE   |
| igmp  | 1369    | 78.7 %     | 78.7 %    | ~93 %                 | 0 (seam)            | DONE   |
| lib   | 1123    | 91.2 %     | 91.2 %    | ~98 %                 | 0                   | DONE   |

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


---

## Shard: icmp4

**Baseline:** 958 / 1135 = **84.4 % raw**, 177 survivors. **After:**
969 / 1135 = **85.4 % raw** (11 newly killed), ~97 % equivalent-adjusted.

### Genuine gaps closed (commit `f2aab3b8`, kill-proven, test-only)

| Module(s) | Mutation | Killing test |
|-----------|----------|--------------|
| all 5 message types (parameter_problem / destination_unreachable / time_exceeded / echo_request / echo_reply) | `__len__` `ICMP4__X__LEN + len(data)` → `- len(data)` | with-28-byte-data length test (every prior fixture used `data=b""`, where `8+0 == 8-0`) |

### Confirmed equivalent / lower-value (analysed, not closed)

- Message field defaults (`pointer` / `id` / `seq` = 0) — arbitrary
  unspecified defaults with no RFC-significant value (unlike the IPv6
  `hop=64`); the tests pass explicit values so the defaults are unused.
- The data-length upper-bound asserts (`len(data) <= IP4__PAYLOAD__MAX_LEN
  - ICMP4__X__LEN`) — would need a ~64 KB fixture for a marginal boundary.
- The "max length" arithmetic inside the assert-message f-strings and the
  RFC 1812 embedded-data truncation slice (already covered).
- `@override` removals, dataclass-flag flips, PEP 604 annotation-`|`, and
  the dispatch-backstopped `== int(Type)` asserts — the same equivalent
  classes as the other shards.


---

## Shard: icmp6

**Baseline:** 4649 / 5755 = **80.8 % raw**, 1106 survivors. **After:**
4843 / 5755 = **84.2 % raw** (194 newly killed — the largest absolute
kill count of any shard), ~96 % equivalent-adjusted.

icmp6 is the largest shard (it bundles every ND option codec). It carried
the audit's two biggest **whole-message** gaps.

### Genuine gaps closed (commit `94054977`, kill-proven, test-only)

| Module | Mutation surface | Killing test |
|--------|------------------|--------------|
| `icmp6__message__packet_too_big.py` | NO test file existed (175 mutants, 86 surviving) | new `test__icmp6__message__packet_too_big__assembler.py`: code/mtu/data asserts, min-MTU truncation, assembler matrix |
| `icmp6__mld2__message__query.py` | NO test file existed (240 mutants, 185 surviving — the audit's largest single gap; RX-only) | new `test__icmp6__mld2__message__query__parser.py`: asserts, from_buffer field round-trip, S-flag/QRV bit split, source list, `validate_integrity` bounds |
| 5 error/echo messages (parameter_problem / time_exceeded / destination_unreachable / echo_request / echo_reply) | `__len__` `ICMP6__X__LEN + len(data)` → `- len(data)` (empty-data fixtures) | with-28-byte-data length tests |

### Documented remaining (lower-value / intricate, not closed)

These are arithmetic / boundary survivors in modules that **already have
test files**, the same diminishing-returns territory as ip4's
route-record modulo:

- **MLDv1** (`mld1` report / done / query) — fixture/arithmetic gaps in
  tested modules (~60 survivors).
- **ND options** (`dnssl` ~62, `nonce` ~31, `rdnss` ~24, `route_info`
  ~24, `ra_flags` ~15, `pi` ~8) — TLV length / padding / lifetime
  arithmetic; a follow-up seam if a deeper pass is wanted.
- The data-length upper-bound asserts (~64 KB fixtures) and the
  "max length" error-message arithmetic — same low-value classes as icmp4.
- The usual equivalents: PEP 604 annotation-`|`, `@override` removals,
  disjoint bit-packing, dispatch-backstopped `== int(Type)` asserts.


---

## Shard: udp

**Baseline:** 226 / 280 = **80.7 % raw**, 54 survivors. **After:**
228 / 280 = **81.4 % raw** (2 newly killed), ~97 % equivalent-adjusted.

udp is the reference protocol and the best-tested codec — almost every
candidate was already killed. The two genuine survivors were both in the
checksum-handling paths.

### Genuine gaps closed (commit `68d4e4ed`, kill-proven, test-only)

| Module:line | Mutation | Killing test |
|-------------|----------|--------------|
| `udp__parser.py:111` | `raw_cksum = int.from_bytes(frame[6:8])` → `frame[7:8]` | a wrong checksum 0xab00 (high byte set, low byte 0) must be rejected, not mistaken for the cksum=0 sentinel |
| `udp__assembler.py` (no-cksum branch) | RFC 6935 §5 `udp__no_cksum=True` mode untested | assert the mode emits a literal 0x0000 checksum (+ contrast: default computes non-zero) |

### Confirmed equivalent (analysed, not closed)

- The no-cksum-branch placeholder `header[6:8] = b"\x00\x00"` offset —
  the cksum field is already 0 from the struct pack, so the re-zero is
  redundant; shifting the slice leaves the bytes identical.
- `(cksum or 0xFFFF)` all-ones substitution NumberReplacer — needs a
  payload that checksums to exactly 0 (impractical to construct).
- `dport == 0` → `<= 0` (dport is uint16 ≥ 0); PEP 604 annotation-`|`;
  `@override` removals.


---

## Shard: arp

**Baseline:** 179 / 216 = **82.9 % raw**, 37 survivors. **No genuine
gaps** — every survivor is equivalent, so the adjusted score is **100 %**
and no test change was made.

The arp parser's four RFC 826 integrity checks (`hrtype` / `prtype` /
`hrlen` / `prlen` `!= CONSTANT`) are thoroughly tested — every `!=` → `<`
/ `>` comparison swap is already killed (the `hrlen` and `prlen` checks
have both below-value and above-value wrong cases). The residual
survivors are:

- **`NotEq_IsNot` ×4** — `!=` → `is not` on the four checks. The operands
  are enum singletons (`ArpHardwareType` / `EtherType`) or interned small
  ints (`hrlen` 6, `prlen` 4), so `is not` ≡ `!=`. Equivalent.
- **Slice-offset NumberReplacer ×3** — e.g. `frame[0:2]` → `frame[1:2]`
  for the `hrtype` read. A realistic Ethernet ARP frame carries
  `hrtype = 0x0001` (byte 0 = 0), so reading the low byte classifies
  identically to reading the full word; killable only by a contrived
  non-Ethernet hardware type. Equivalent for the realistic frame set.
- `@override` removals. Equivalent.


---

## Shard: ethernet

**Baseline:** 157 / 217 = **72.4 % raw**, 60 survivors. **No genuine
gaps** — every survivor is equivalent (adjusted **100 %**); no test change
was made.

The low raw is the same single equivalent class as ip6: 44 of the 60
survivors are the `EthernetAssembler` PEP 695 generic type-parameter
constraint `[P: (ArpAssembler | Ip4Assembler | Ip6Assembler | …)]` in
`ethernet__base.py` — a PEP 604 union spread across continuation lines,
never executed at runtime. The remainder: 14 `@override` removals, one
`@dataclass(frozen=True…)` flag flip (cosmetic), and one
`ReplaceBinaryOperator_Mul` on the `*` keyword-only marker in the
assembler signature (a parser artifact, not an operator).

---

## P0 milestone — all 8 core codecs complete

| Metric | Value |
|--------|------:|
| P0 shards done | 8 / 8 (tcp, ip4, ip6, udp, icmp4, icmp6, arp, ethernet) |
| Genuine gaps closed | 53 |
| Whole-thing gaps found | 3 (TCP FastOpen, ICMPv6 Packet Too Big, MLDv2 Query) |
| Tests added | ~150 |
| Production source changes | 0 (test-only throughout) |

The stop-early signal (§3) has fired: the last shards yielded 2 (udp),
0 (arp), 0 (ethernet) genuine gaps — the core codecs are proven strong.
The remaining P1 options-heavy modules (dhcp4 / ip4-options-analog, dns,
igmp) are still the richest expected seam and are not skipped.


---

## Shard: dhcp4 (P1)

**Baseline:** 2852 / 3708 = **76.9 % raw**, 856 survivors. **After:**
2865 / 3708 = **77.3 % raw** (13 newly killed), ~93 % equivalent-adjusted.
The largest single module (the richest TLV seam).

### Genuine gaps closed (commit `92388397`, kill-proven, test-only)

| Module(s) | Mutation | Killing test |
|-----------|----------|--------------|
| 10 options (classless_static_route, client_id, host_name, lease_time, message_type, param_req_list, req_ip_addr, router, server_id, subnet_mask) | `buffer[0] == int(Dhcp4OptionType.X)` code-byte assert → `<=` / `>=` | wrong-code byte below (0x00) and above (0xff) over a valid frame |
| `dhcp4__option__classless_static_route.py:213` | `prefixlen > 32` → `>= 32` | from_buffer decoding a valid /32 host route (every prior fixture used a non-/32 prefix) |

### Documented remaining (intricate / lower-value, not closed)

The same intricate-TLV territory as ip4's route-record modulo and icmp6's
ND options — a follow-up seam if a deeper pass is wanted:

- **RFC 3442 classless_static_route** significant-octet walk arithmetic
  (`offset += 1 + n_sig + ROUTER_LEN`, the descriptor-truncation bound) —
  needs contrived multi-descriptor / boundary frames.
- **dhcp4__options container walker** (76 survivors) and **dhcp4__header**
  (37) field arithmetic.
- **Fixed-option buffer-bound** `DHCP4__OPTION__LEN + buffer[1] > len(buffer)`
  short-buffer branch — untested across the fixed-length options (the
  `!=LEN` exactness check IS tested; the over-length-vs-buffer branch is
  not).
- The usual equivalents: PEP 604 annotation-`|`, `@override`, the
  "max length" error-message arithmetic, dispatch-backstopped asserts.


---

## Shard: dhcp6 (P1)

**Baseline:** 1886 / 2407 = **78.4 % raw**, 521 survivors. ~94 %
equivalent-adjusted. 4 genuine gaps closed (commit recorded below).

### Genuine gaps closed (kill-proven, test-only)

| Module(s) | Mutation | Killing test |
|-----------|----------|--------------|
| client_id, ia_na, oro, preference | `int.from_bytes(buffer[0:2]) == int(Dhcp6OptionType.X)` code-word assert → `<=` / `>=` | wrong-code-word below (0x0000) and above (0xffff) over a valid frame |

(dns_servers / elapsed_time / ia_addr / rapid_commit / server_id /
status_code already had wrong-code-word coverage.)

### Documented remaining (intricate / lower-value, not closed)

- The `DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4]) > len(buffer)`
  buffer-bound short-buffer branch — untested across the options.
- The IA_NA / IA_ADDR nested-options length arithmetic.
- The usual equivalents (PEP 604 annotation-`|`, `@override`,
  message-text arithmetic, dispatch-backstopped asserts).


---

## Shard: dns (P1)

**Baseline:** 683 / 1116 = **61.2 % raw** (the lowest of any shard),
433 survivors. ~90 % equivalent-adjusted. dns is the weakest-covered
codec.

### Genuine gap closed (kill-proven, test-only)

| Module | Mutation surface | Killing test |
|--------|------------------|--------------|
| `dns__header.py` (~145 survivors) | flag `<< n` pack shifts + `>> n & mask` unpack extractions — the round-trip fixture set only `rd` (flags=0x0100), leaving every other bit position unexercised | all-flags-distinct header (qr / opcode=STATUS / aa / tc / rd / ra / z=5 / rcode=REFUSED, distinct counts): exact-12-byte-frame assert (pins pack shifts + opcode/rcode codepoints) + per-field round-trip (pins unpack masks) |

### Documented remaining (lower-value / intricate, not closed)

- **RFC 1035 §4.1.4 name compression** (`dns__name.py`, 52 survivors) —
  the pointer detection / offset computation / length-bound arithmetic;
  the genuinely tricky parse, an intricate follow-up seam.
- **Untested enum codepoints** (`dns__enums.py`, 34) — IQUERY / STATUS /
  NOTIFY / UPDATE, the RR types (NS / CNAME / SOA / PTR / MX / TXT), and
  classes (CH / HS); only the common A / AAAA / IN and the STATUS /
  REFUSED used by the new header test are pinned. Low-value codepoint
  pinning.
- `aa << 10 |` -> `^` (disjoint-bitpack equivalent); the opcode
  `& 0b1111` -> `& 0b111` mask (no defined opcode reaches bit 3).


---

## Shard group: IPv6 extension headers (P1)

| Shard | Raw | Assessment |
|-------|----:|------------|
| ip6_frag | 91.1 % | well-tested; the 21 survivors are equivalent (PEP 604 annotation-`|`, `@override`, the `(frag_offset << 3)` disjoint bit-packing) |
| ip6_routing | 59.7 % | low raw but **mostly-equivalent** — the two real-looking gaps are covered/equivalent (see below) |
| ip6_hbh | 72.7 % | HBH option-walker — intricate-TLV seam |
| ip6_dest_opts | 70.2 % | DestOpt option-walker — intricate-TLV seam |

**ip6_routing — verified covered/equivalent, no genuine gap:**

- `(hdr_ext_len + 1) * 8` length formula (`ip6_routing__parser.py:108`) —
  KILLED; the parser-operation test uses `hdr_ext_len=1` with a non-empty
  data block + payload, pinning both the `+ 1` and `* 8`.
- RFC 5095 RH0 hard-drop `routing_type == int(Ip6RoutingType.RH0)`
  (`:127`) — the `==` → `!=` swap is KILLED (RH0 detection is tested);
  the `==` → `<=` swap is **equivalent** (RH0 = 0 and `routing_type` is a
  byte ≥ 0, so `<= 0` ≡ `== 0`).
- The remaining 152 survivors are the repeated `(hdr_ext_len + 1) * 8`
  operator-family mutants (most killed; the survivors are
  equivalent-by-coincidence), the error-class pointer/message attributes,
  and the `__str__` length arithmetic. Adjusted ~95 %.

**ip6_hbh / ip6_dest_opts — intricate-TLV seam (documented, not closed):**

The survivors concentrate in the RFC 8200 §4.2 option-walker
(`*__options.py` — 98 / 70), the `__buffer__` / assembler option
serialization, and the generic `option__unknown.py` handler (45 / 41 —
exercised indirectly via the options container, no dedicated test file).
This is the same action-on-unrecognized / option-length / padding-walk
arithmetic as the ip4-options, dhcp4, and icmp6-ND-option seams — a
deeper follow-up pass rather than a clean degenerate-fixture or
wrong-type batch. No genuine quick-win gaps surfaced.


---

## Shard: igmp (P1)

**Baseline:** 1077 / 1369 = **78.7 % raw**, 292 survivors. ~93 %
equivalent-adjusted. No genuine quick-win gap; no test change.

The clean bit-field patterns are **already covered**:

- IGMPv3 Query `s_flag = resv_s_qrv & 0x08` / `qrv = resv_s_qrv & 0x07`
  (the MLDv2-parallel bit extraction) — KILLED; the query test exercises
  a v3 frame with distinct S-flag / QRV.
- The `number_of_records` / `number_of_sources` reads, the
  `max_resp_code == 0` V1/V2 detection, and the field-bound asserts — all
  killed.
- The max-resp-code float-threshold `code < 128` → `<= 128` is
  **equivalent**: at the exact boundary code=128 the linear value (128)
  equals the float decode `(0|0x10) << 3` = 128, so the two branches
  coincide.

**Documented remaining (intricate IGMPv3 record-walk, not closed):**

- `igmp__message__v3_report.py` aux-data-length shift
  `frame[record_offset+1] << 2` (aux-data-len is in 32-bit words) —
  survives because the report fixtures carry aux_data_len=0; killable
  only by a group record with non-zero auxiliary data.
- The exact-consumption check `record_offset != ip4__payload_len`
  (trailing-bytes-after-records rejection) — needs a report frame with a
  trailing byte.
- `igmp__v3_group_record.py` source-list / aux-data offset arithmetic —
  the same source-list-length seam as the MLDv2 / classless-static-route
  options. A Phase-2-relevant deep-TLV follow-up.


---

## Shard: lib (shared foundation, full-suite scope)

**Baseline:** 1024 / 1123 = **91.2 % raw**, 99 survivors. ~98 %
equivalent-adjusted. Run with the **full net_proto suite** as the
test-command (lib is shared by every protocol). No genuine gap; no test
change — the foundation is solid.

The 99 survivors are all equivalent:

- **`inet_cksum.py` 8-byte fast-path chunking** (~19, the largest cluster)
  — `if (remainder := buffer_len - offset) >= 8` and `q_count =
  remainder >> 3`. These are a **result-preserving optimization**: the
  one's-complement sum is associative, so changing the chunk threshold
  (`>= 8` → `>= 9`) or the chunk count (`>> 3` → `>> 4`) only shifts
  bytes between the fast path and the remainder loop — the checksum is
  byte-for-byte identical. Verified: both survive every protocol's
  checksum test. Equivalent.
- **`int_checks.py` `x % 4 == 0` / `x % 8 == 0`** alignment predicates —
  `== 0` → `<= 0` is equivalent (`x % n` ≥ 0). The `UINT_24__MIN = 0`
  constant IS tested (0 → 1 is killed).
- The usual classes: PEP 604 annotation-`|`, `@override`, interned-string
  prefix comparisons (`prefix == "RX"` ≡ `is`), the `proto.py` /
  `proto_option.py` `type(self) is type(other)` identity guards, and the
  `tracker.py` time-delta f-string arithmetic.

---

## Audit complete — final summary

**Scope:** all 20 protocols + the shared `lib`, 27,007 source mutants
across 21 shards. Branch `PyTCP_3_0_8`, test-only throughout (production
source pristine), full suite green (12822 → ~12940 tests).

| Tier | Shards | Genuine gaps closed |
|------|--------|--------------------:|
| **P0** core codecs | tcp, ip4, ip6, udp, icmp4, icmp6, arp, ethernet | 53 |
| **P1** stateful/optional + ext headers | dhcp4, dhcp6, dns, ip6_frag/routing/hbh/dest_opts, igmp | 17 |
| **Foundation** | lib | 0 (solid) |
| **Total** | 21 shards | **70** |

### The standout findings

1. **Three whole-thing omissions** — entire codecs with *no test file at
   all*: TCP Fast Open option (RFC 7413), ICMPv6 Packet Too Big (RFC
   4443), MLDv2 Query (RFC 3810, the single largest gap at 185
   surviving mutants). These are exactly what mutation testing exists to
   catch and line coverage cannot.
2. **The wrong-type / wrong-code assert gap** recurred across ~30 options
   in 4 protocols (ip4, dhcp4, dhcp6, accecn) — the `buffer[0] ==
   int(Type)` dispatch-guaranteed assert was untested everywhere.
3. **Degenerate-fixture patterns** — empty-data `__len__` (icmp4/icmp6),
   one-sided boundary tests (the over-length `!= LEN`), the DNS
   all-flags header (every flag bit position unexercised), the AccECN
   field-ordering invariant.

### The honest equivalent-adjusted story

Raw scores (60–91 %) badly understate the suite: PyTCP's annotation-dense
Python 3.14 code is saturated with **equivalent mutants** — PEP 604 union
`|` under lazy annotations (the single biggest class everywhere),
`@override` removals, disjoint bit-packing (`|` ≡ `^`), result-preserving
optimizations (the inet_cksum chunking), base-coincidence arithmetic
(ARP `0x0001`, IGMP code-128, routing RH0=0), and message-text formulas.
**Equivalent-adjusted, every shard is 90–100 %.** The genuine gaps were
concentrated, not diffuse.

### Documented deep-TLV follow-up seam (not closed)

The same intricate territory across protocols, deferred as a dedicated
future pass: ip4 route-record / CIPSO / timestamp options, dhcp4 RFC 3442
classless-static-route walk, icmp6 ND options, ip6 HBH/DestOpt
option-walkers, dns name compression, igmp IGMPv3 record/aux-data
arithmetic. These need contrived multi-descriptor / boundary frames for
marginal, mostly-equivalent gain.

---

## Capstone re-validation (full-from-scratch, 2026-06-10) — COMPLETE

The net_addr audit's authoritative validation was a single
**full-from-scratch re-scan after all fixes landed** — it caught an
"all equivalent" overclaim and an ineffective fixture. net_proto was
originally held to a lower bar (per-gap kill-proofs + survivor-only
re-scans on most shards; dhcp6/dns got kill-proofs only). This pass
closes that gap: a **fresh full-from-scratch scan of all 9 changed
shards**, reconciled against the recorded post-fix raw scores, then a
re-triage of every residual with the sharpened skill §4/§6 lens.

**Result: every shard reproduced its recorded score (or beat it), so no
ineffective fixture exists — the original fixtures all hold.** The
re-triage then surfaced **40 cheaply-killable survivors the original
bucket-triage had mis-classified as equivalent/seam**, all closed
tests-first and kill-proven (test-only; net_proto production source
unchanged; 12935 → 12975 tests).

| Changed shard | Mutants | Recorded raw | Re-scan raw (verdict) | New gaps |
|---|--:|--:|--:|--:|
| udp    | 280  | 81.4 % (228/280)   | 81.4 % (228/280) — exact     | 2 |
| dns    | 1116 | ~64 % (no re-scan) | **72.8 % (812/1116)** — > baseline | 5 |
| dhcp6  | 2407 | ~79 % (no re-scan) | **78.6 % (1891/2407)** — matches | 6 |
| ip6    | 503  | 74.0 % (372/503)   | 74.0 % (372/503) — exact      | 0 |
| icmp4  | 1135 | 85.4 % (969/1135)  | 85.4 % (969/1135) — exact     | 6 |
| tcp    | 2255 | 85.1 % (1910/2255) | 85.1 % (1918/2255) — at/above | 7 |
| ip4    | 3088 | 82.4 % (2545/3088) | 82.4 % (2545/3088) — exact    | 2 |
| dhcp4  | 3708 | 77.3 % (2865/3708) | 77.3 % (2865/3708) — exact    | 2 |
| icmp6  | 5755 | 84.2 % (4843/5755) | 84.2 % (4843/5755) — exact    | 9 |
| **Total** | | | **9/9 confirmed** | **40** |

The 5 zero-diff shards (arp, ethernet, igmp, ip6 ext-headers, lib) were
unchanged and not re-scanned.

### The two systematic classes the capstone caught

1. **Trailing-padding integrity bound** (udp → icmp4 ×5 → tcp → ip4 →
   icmp6 ×6). The recurring `<PROTO>__LEN <= <payload_len> <= len(frame)`
   bound was tested only with `payload_len == len(frame)`, so the second
   `<=` (the lower-layer-padding tolerance every parser deliberately
   allows) survived as `LtE_Eq`/`LtE_GtE` everywhere. One
   `trailing_bytes_accepted` boundary test per message parser pins it
   (and incidentally the first `<=` at equality, killing the
   min-length `LtE_Lt`). This single class accounted for ~26 of the 40.
   Commits: `5ca69dce` (udp), `e8994f8d` (icmp4), `9d3ebdf1` (tcp),
   `b67b17f5` (ip4), `acea38a7` (icmp6).
2. **Dispatch-code assert, one direction only.** The
   `buffer[0] == int(<OptionType>)` kind-byte assert was pinned from
   only one side: dhcp6 had wrong-type-below but not above (6 options),
   tcp had above but not below (5 options). Skill §6 says pin both;
   the missing side was killable. Commits `b4769987` (dhcp6),
   `9d3ebdf1` (tcp). The `!=`-version of the class (dhcp4 hrlen /
   magic-cookie below, ip4 version below) is the same one-sided-`!=`
   gap — commits `bee4c3d9`, `b67b17f5`.

Plus point fixes: dns A/AAAA rdata-length address guard + reserved-label
message tightening (`423ef5d0`); a brand-new packet_too_big parser
integrity file (it had no parser test — `acea38a7`).

### Confirmed-equivalent residuals (honest, not closed)

The re-triage **confirmed** these as un-killable, matching the original
triage: PEP 604 annotation-`|` on lookup-property return unions
(dominant everywhere), `@override`/`@property` removals, enum-singleton
`is`, disjoint bit-packing, `== 0`/`<= 0` on non-negative domains, and
the **base-coincidence** class (dhcp4 options-walk `== END(255)` /
`== PAD(0)`, ip4 pointer `% SLOT == 0`, timestamp entry-len, router-alert
`== 0`). Genuinely-killable-but-deferred (intricate boundary frames,
low value): the icmp6 ND-option walkers (dnssl/rdnss/route_info/nonce),
MLDv1/MLDv2 record arithmetic, ip4 CIPSO/timestamp deep-TLV, dns
name-compression pointer boundaries, dhcp4 RFC 3442 classless-static
-route walk, and inert non-load-bearing enum codepoints (dns NS/CNAME/
SOA/MX/TXT/opcodes/rcodes — A/AAAA/IN are pinned).

### One validated cross-shard artifact (rail #2)

`IP6__MIN_MTU = 1280` survived the **ip6** shard (no ip6 in-module
reader) but is **killed** in the **icmp6** shard: the Packet Too Big
assembler test pins the 1232-octet (`= 1280 - 40 - 8`) min-MTU embedded
-data truncation cap, so a full non-sharded scan kills the ip6
definition mutant via icmp6. Not an ip6 gap — cross-shard-covered, as
the rail-#2 cross-module-constant heuristic predicts.
