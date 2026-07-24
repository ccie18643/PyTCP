# ARP → Linux-host Parity Audit & Punch List

> **Reconciled 2026-05-30:** the in-RX ARP conflict-detection
> model described below (`PacketHandler._handle_arp_conflict`,
> `_abandon_ipv4_address`, the RX probe-conflict machinery in
> `__phrx_arp__request`) was REMOVED in the sd-ipv4acd userspace
> migration. IPv4 ACD now runs entirely in userspace over
> per-address `Ip4Acd` AF_PACKET sockets
> (`protocols/ip4/acd/ip4_acd.py`:
> `probe`/`announce`/`claim`/`start_defense`/`poll_conflict`/`defend`/`release`);
> ARP RX (`packet_handler__arp__rx.py`) does NO conflict
> detection — it only answers Requests for owned IPs, learns the
> cache, and notes gratuitous ARPs. See `raw_link_socket.md` §10
> and `rfc3927_link_local_autoconfig.md`. The §1/§2/§13 in-RX
> designs below are archaeology.

This document captures the ARP-related work needed to bring
PyTCP's host-stack ARP behaviour to default-Linux parity. It
records what shipped, what's still open, and the implementation
detail needed to resume each remaining item without re-deriving
it from scratch.

The classification follows the project's North Star (`CLAUDE.md`):
Phase 1 covers default-Linux **host** behaviour; Phase 2 covers
router-grade work. Items below are marked Tier 1 (blocker), Tier 2
(RFC 5227 finish), Tier 3 (Linux-specific defaults), or Tier 4
(Phase 2 / deferred per North Star).

---

## §0 Status snapshot (2026-05-09)

### ✅ Shipped

| # | Item | Commit | RFC clause |
|---|---|---|---|
| 1 | RX-vs-DAD probe-conflict-set disconnect | `cffd4841` | 5227 §2.1.1 |
| 2 | DEFEND_INTERVAL rate-limit on conflict defense | `87851caa` | 5227 §2.4(c) |
| 3 | ARP-Request rate-limit + queued-packet flush | `628e724b` | 1122 §2.3.2.1 + §2.3.2.2 |
| — | Ethernet TX `enqueue_pending` wiring tests | `c716c35f` | (test-only) |
| — | Ethernet TX → ARP cache resolution flow integration | `8b4e321e` | (test-only) |
| 5 | ANNOUNCE_NUM = 2 (second Announcement after probe) | `3d7d276d` | 5227 §2.3 |
| 6 | ANNOUNCE_WAIT (2 s post-probe quiet period) | `01841e10` | 5227 §2.1.1 |
| 7 | PROBE_WAIT (initial 0–1 s random delay) + PROBE_NUM/MIN/MAX | `5777c00a` | 5227 §2.1.1 |
| 8 | Simultaneous-probe (peer's SPA = 0, TPA = candidate) detection | `3f051584` | 5227 §2.1.1 |
| 14 | Unicast cache-refresh probe (replaces broadcast) | `30aaa98a` | 1122 §2.3.2.1 IMPL (2) |
| 15 | Wall-clock → `time.monotonic` in cache aging | `1a46f28f` | (Linux parity) |
| 16 | Configurable cache timeout (`stack.init` kwargs) | `a25603cb` | 1122 §2.3.2.1 SHOULD |
| — | sysctl framework Phase 0 (registry) + Phase 1 (ARP package migration + #16 retrofit) | `8eb94ccb` + `586a693e` | (Linux parity) |
| 17 (partial) | `arp.accept` + `arp.ignore` modes 0-2 sysctls | (earlier commit) | Linux parity |
| 17 | `arp.announce` (0/1/2), `arp.filter` (0/1), `arp.ignore` mode 8 | (this commit) | Linux parity |
| — | Six RFC adherence audits (826/1027/1122/3927/5227/5494) | `03c0b678` | — |
| — | `ArpTestCase` harness + smoke / DAD / DEFEND_INTERVAL / resolution-flow integration tests | various | — |
| — | Code relocated from `packages/pytcp/pytcp/stack/` → `packages/pytcp/pytcp/protocols/arp/` | `e29e6b1e` | — |
| — | `test__arp__cache.py` import fixups (follow-up to relocation) | `24eaa44d` | — |
| — | `_ArpRxTestBase.setUp` `create=True` fix (unblock unit tests) | `f8cf5136` | — |

### 🔓 Remaining inventory

- **Tier 2 (RFC 5227 finish):** §2 (#9), §3 (#10) below.
- **Tier 3 (Linux defaults):** §4–§6, §10 below (#14, #15, #16 shipped).
- **Tier 4 (deferred):** §11 below.

---

## §1 — Tier 2 #8: simultaneous-probe detection (RFC 5227 §2.1.1)

> **SHIPPED (commit `3f051584`; reconciled 2026-05-25).** This section
> is delivered — the §0 status table records it. Simultaneous-probe
> detection (a peer's ARP Probe with SPA = 0 and TPA = our candidate)
> is detected during the ACD probe window and treated as a conflict.
> The prose below is the original gap analysis, kept as archaeology.

### What's missing

> "In addition, if during this period the host receives any ARP
> Probe where the packet's 'target IP address' is the address
> being probed for, and the packet's 'sender hardware address'
> is not the hardware address of any of the host's interfaces,
> then the host SHOULD similarly treat this as an address
> conflict and signal an error to the configuring agent as
> above."

This is the case where ANOTHER host is probing the SAME address
at the same time as us. The peer's frame has:
- `arp.spa = 0.0.0.0` (probe — peer's "I want this address")
- `arp.tpa = our candidate IP`
- `arp.sha != our MAC` (real foreign peer, not loopback)

PyTCP's existing probe-conflict detection branches at
`packet_handler__arp__rx.py:202,292,320` only fire when
`arp.spa in self._ip4_ifaddr_candidate` — that condition is FALSE
when SPA = 0. So the simultaneous-probe case is silently missed.

### Where to add the branch

`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py` —
inside `__phrx_arp__request`, after the existing loop-drop and
conflict-defend checks but before the gratuitous-Request
branch. Pseudocode:

```python
# RFC 5227 §2.1.1: another host is probing the same candidate
# (their SPA = 0, TPA = our candidate, SHA != our MAC).
if (
    packet_rx.arp.spa.is_unspecified
    and packet_rx.arp.tpa in {c.address for c in self._ip4_ifaddr_candidate}
    and packet_rx.arp.sha != self._mac_unicast
):
    self._packet_stats_rx.arp__op_request__simultaneous_probe += 1
    __debug__ and log(
        "arp",
        f"{packet_rx.tracker} - <WARN>Simultaneous-probe conflict "
        f"detected for candidate {packet_rx.arp.tpa} from peer "
        f"{packet_rx.arp.sha}</>",
    )
    self._arp_probe__unicast_conflict.add(packet_rx.arp.tpa)
    return
```

### Stats counter

Add `arp__op_request__simultaneous_probe: int = 0` to
`packages/pytcp/pytcp/lib/packet_stats.py::PacketStatsRx`. Field count goes
from current N → N+1.

### Tests-first

**Unit** — extend
`packages/pytcp/pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest`
with `test__stack__packet_handler__arp__rx__simultaneous_probe_conflict`:

```python
def test__stack__packet_handler__arp__rx__simultaneous_probe_conflict(self):
    """
    Ensure a peer's ARP Probe (SPA=0, TPA=our candidate, foreign
    SHA) registers as a probe-conflict on the per-instance set.

    Reference: RFC 5227 §2.1.1 (simultaneous-probe conflict).
    """
    frame = _arp_frame(
        oper=ArpOperation.REQUEST,
        sha=HOST_A__MAC,
        spa=IP4__UNSPEC,
        tha=MAC__UNSPEC,
        tpa=STACK__IP4_ADDRESS__CANDIDATE,
    )
    packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
    self._handler._phrx_arp(packet_rx)

    self.assertIn(
        STACK__IP4_ADDRESS__CANDIDATE,
        self._handler._arp_probe__unicast_conflict,
        msg="...",
    )
    self.assertEqual(
        self._handler._packet_stats_rx.arp__op_request__simultaneous_probe,
        1,
        msg="...",
    )
```

**Integration** — extend
`packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDad`
with `test__arp__dad__simultaneous_probe_aborts_claim`. Inject
the simultaneous-probe at idx 1 (during the first inter-probe
sleep) using the existing `_drive_dad(on_sleep=...)` harness.

### Effort

Small (~50 lines source + 30 lines tests). One commit.

### Reference

`docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` §2.1.1 calls out
this gap explicitly under "Simultaneous-probe (SPA = 0)
detection — not implemented."

---

## §2 — Tier 2 #9: abandon-after-second-conflict (RFC 5227 §2.4(b) MUST) ✅ shipped

Landed as Phase 6 of the NUD migration. The
`PacketHandler._handle_arp_conflict` helper tracks per-IP
last-conflict timestamps; a second conflict within
`DEFEND_INTERVAL` of the previous triggers
`_abandon_ipv4_address` which (a) ABORTs every TcpSession
bound to the address (`RFC 5227 §2.4-final` SHOULD), (b)
removes the address from `_ip4_ifaddr`, and (c) increments the
new `arp__conflict__abandon` PacketStatsRx counter.

Adherence reference: `docs/rfc/arp/rfc5227__ipv4_acd/adherence.md`
§2.4 / §2.4(b).

---

## §3 — Tier 2 #10: MAX_CONFLICTS / RATE_LIMIT_INTERVAL

### What's missing

> "A host implementing this specification MUST take precautions
> to limit the rate at which it probes for new candidate
> addresses: if the host experiences MAX_CONFLICTS or more
> address conflicts on a given interface, then the host MUST
> limit the rate at which it probes for new addresses on this
> interface to no more than one attempted new address per
> RATE_LIMIT_INTERVAL."

### Why dormant today

PyTCP's static-config + DHCP-only model has no automatic
candidate-rotation path. A claim either succeeds or fails;
PyTCP doesn't pick a different IP and try again. So
"rate-limit the retry" has nothing to rate-limit.

This MUST becomes live the moment any of:
- RFC 3927 link-local autoconfig is implemented (auto-pick
  another 169.254.x.x on conflict)
- DHCP DECLINE handling triggers asking for another lease
- Multi-candidate static config with fallback

### Action today

**None — defer until a candidate-rotation path lands.** When
that work happens, the implementing item will need to:

1. Track per-interface conflict count.
2. When count >= MAX_CONFLICTS (10), gate new candidate
   probes by RATE_LIMIT_INTERVAL (60 s).

Constants to add (pre-emptively, optional):
- `ARP__MAX_CONFLICTS = 10`
- `ARP__RATE_LIMIT_INTERVAL = 60`

### Reference

`docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` §2.1.1
"MAX_CONFLICTS / RATE_LIMIT_INTERVAL — not implemented (dormant
in static-config model)."

---

## §4 — Tier 3 #11: NUD state machine

The full design + per-phase migration plan now lives in a
dedicated document at
[`docs/refactor/nud_state_machine.md`](nud_state_machine.md).
Read that doc before starting any code; the resume prompt in
its §12 is the canonical entry point.

Summary for the punch list:

- **#11 NUD FSM** — six states (`INCOMPLETE` / `REACHABLE` /
  `STALE` / `DELAY` / `PROBE` / `FAILED`) per RFC 4861 §7.3.2,
  shared between ARP (IPv4) and ND (IPv6). The generic
  `NeighborCache[A]` lives at `packages/pytcp/pytcp/lib/neighbor.py`
  (Linux's `net/core/neighbour.c` factoring); per-protocol
  adapters supply the wire-level solicit hook. NUD timing
  constants register through the sysctl framework
  (`neighbor.reachable_time`, `neighbor.gc_thresh1` …)
  rather than as static `*__NUD__*` constants.
- **#12 reachability confirmation hook** — folds into #11
  Phase 4; TCP calls `NeighborCache.confirm_reachability` on
  in-window ACK to bypass the unicast probe.
- **#13 bounded cache + GC** — folds into #11 Phase 5.
- **#9 abandon-after-second-conflict** — folds into #11
  Phase 6; the FAILED state provides the "neighbour
  unreachable" signal the TcpSession ABORT path needs.

Effort: 1–2 weeks across 6 phases. One phase per session
recommended given the context budget; each phase is a
mechanically reversible green-test commit.

---

## §5 — Tier 3 #12: reachability confirmation hook

Absorbed into the NUD work — Phase 4 of
[`docs/refactor/nud_state_machine.md`](nud_state_machine.md).
TCP calls `NeighborCache.confirm_reachability` on in-window
ACK to bypass the unicast probe.

---

## §6 — Tier 3 #13: bounded cache + GC

Absorbed into the NUD work — Phase 5 of
[`docs/refactor/nud_state_machine.md`](nud_state_machine.md).
Three Linux-style thresholds (`gc_thresh1 = 128` /
`gc_thresh2 = 512` / `gc_thresh3 = 1024`) registered as
sysctls; eviction priority FAILED → STALE → LRU.

---

## §7 — Tier 3 #14: unicast cache-refresh probe

Currently `_subsystem_loop` calls
`stack.packet_handler.send_arp_request(arp__tpa=...)` which
sends a BROADCAST Request. Linux uses unicast for refresh
(RFC 1122 §2.3.2.1 IMPLEMENTATION (2)).

### Implementation

- New TX helper `_send_arp_unicast_probe(ip4_address, mac_address)`
  — sends Request with `ethernet__dst = mac_address` instead
  of broadcast.
- Refresh path in `_subsystem_loop` uses the unicast helper
  with the cached MAC.

### Effort

Small (~30 lines + tests). Standalone — doesn't require #11.

---

## §8 — Tier 3 #15: wall-clock → time.monotonic in cache aging

`arp__cache.py::_subsystem_loop` uses `int(time.time())`. NTP
jumps could mass-expire entries.

### Fix

Switch to `time.monotonic()`. `find_entry` and
`_maybe_send_arp_defense` are already monotonic (per the recent
refactor); only the loop's aging arithmetic is left.

### Effort

Tiny (~5 lines + 1 test). Standalone — doesn't require #11.

---

## §9 — Tier 3 #16: configurable cache timeout

Today the ARP cache timeouts (`ARP__CACHE__ENTRY_MAX_AGE`,
`ARP__CACHE__ENTRY_REFRESH_TIME`) are compile-time constants in
`packages/pytcp/pytcp/protocols/arp/arp__constants.py`.

### Possible approaches

1. **Sysctl-style mutable module attributes** — the constants
   become writable globals; tests already patch them this way.
   Lowest-friction.
2. **`stack.init(arp_cache_max_age=...)` kwarg** — surface the
   timeout in the stack-init API. Highest visibility for users.
3. **Per-interface configuration** — when multi-interface
   support lands (Phase 2).

### Effort

Small (~30 lines + tests).

---

## §10 — Tier 3 #17: Linux sysctl knobs

Default Linux exposes:
- `arp_accept` (0/1) — accept ARP for IPs not on local subnets — **shipped**.
- `arp_announce` (0/1/2) — restrict source IP in outbound ARP — **shipped**.
- `arp_ignore` (0..8) — controls when to reply to ARP requests —
  **modes 0/1/2/8 shipped**; mode 3 needs an address-scope
  concept PyTCP does not have today; modes 4-7 are Linux-
  reserved unused slots.
- `arp_filter` (0/1) — multi-interface ARP behaviour —
  **shipped** as a registered sysctl. Mode 1 is a Phase 2
  no-op today (single-interface PyTCP always passes the
  source-routing-filter check); the knob exists for parity
  and forward-compat with the eventual multi-interface work.

All four sysctls live in `packages/pytcp/pytcp/protocols/arp/arp__constants.py`
under the `arp.*` registry namespace and are operator-tunable
at boot via `stack.init(sysctls={...})` or at runtime via
`pytcp.stack.sysctl["arp.<knob>"] = N`. The runtime branches
that consume each knob are in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__{rx,tx}.py`.

### Effort

Shipped in three commits (arp.accept + arp.ignore modes 0-2
landed earlier; arp.announce + arp.filter + arp.ignore mode 8
in the current commit).

---

## §11 — Tier 4: Phase 2 deferred

These are explicitly out of scope per the project North Star.
**Do not implement** without revisiting the project Phase
classification.

- **RFC 1027 Proxy ARP** — router-grade. Audit at
  `docs/rfc/arp/rfc1027__proxy_arp/adherence.md`.
- **§2.6.2 / §2.7 LLA forwarding gate** — router-grade
  (forwarding plane); silent risk only. Audit at
  `docs/rfc/arp/rfc3927__ipv4_lla/adherence.md` §2.6.2.

> **RFC 3927 IPv4 link-local autoconfiguration itself has since
> SHIPPED** (Phases 0–5) — see
> `docs/refactor/rfc3927_link_local_autoconfig.md` and §3 above.
> Only the forwarding gate above remains Phase-2.

---

## §12 — Key file inventory

```
packages/pytcp/pytcp/protocols/arp/
├── arp__cache.py        # ArpCache subsystem; CacheEntry, _PendingResolution
└── arp__constants.py    # ARP__CACHE/DEFEND/REQUEST/PROBE/ANNOUNCE constants

packages/pytcp/pytcp/runtime/packet_handler/
├── __init__.py                          # PacketHandlerL2._create_stack_ip4_addressing (DAD flow)
├── packet_handler__arp__rx.py           # __phrx_arp__request, __phrx_arp__reply, _maybe_send_arp_defense
└── packet_handler__arp__tx.py           # _phtx_arp + helpers (_send_arp_probe, _send_arp_announcement, etc.)

packages/net_proto/net_proto/protocols/arp/
├── arp__assembler.py
├── arp__base.py
├── arp__enums.py        # ArpHardwareType, ArpOperation
├── arp__errors.py       # ArpIntegrityError, ArpSanityError
├── arp__header.py       # ArpHeader dataclass
└── arp__parser.py

packages/pytcp/pytcp/tests/lib/arp_testcase.py          # ArpTestCase harness

packages/pytcp/pytcp/tests/integration/protocols/arp/
├── test__arp__dad.py                    # DAD-flow integration
├── test__arp__defend_interval.py        # Conflict-defense rate-limit
├── test__arp__harness_smoke.py          # ArpTestCase smoke tests
├── test__arp__resolution_flow.py        # Outbound IPv4 → ARP miss → Reply → flush
├── test__arp__rx.py                     # Migrated RX wire-format matrix
└── test__arp__tx.py                     # Migrated TX wire-format matrix

packages/pytcp/pytcp/tests/unit/protocols/arp/
├── test__arp__cache.py                  # ArpCache unit tests (rate-limit, queue, aging)
└── test__arp__constants.py              # Constants pinned to RFC values

packages/pytcp/pytcp/tests/unit/stack/packet_handler/
├── test__stack__packet_handler__arp__rx.py
└── test__stack__packet_handler__arp__tx.py

docs/rfc/arp/
├── rfc826__arp/                         # Foundational ARP audit
├── rfc1027__proxy_arp/                  # Phase 2 deferred
├── rfc1122__host_requirements_arp/      # §2.3.2 host requirements audit
├── rfc3927__ipv4_lla/                   # Phase 2 deferred
├── rfc5227__ipv4_acd/                   # Probe / announce / defend audit
└── rfc5494__arp_iana/                   # IANA registry audit
```

### Constants currently in `packages/pytcp/pytcp/protocols/arp/arp__constants.py`

| Constant | Value | RFC clause |
|---|---|---|
| `ARP__CACHE__ENTRY_MAX_AGE` | 3600 (s) | host-side aging |
| `ARP__CACHE__ENTRY_REFRESH_TIME` | 300 (s) | host-side refresh window |
| `ARP__DEFEND_INTERVAL` | 10 (s) | RFC 5227 §1.1 |
| `ARP__REQUEST_RATE_LIMIT` | 1 (s) | RFC 1122 §2.3.2.1 |
| `ARP__PROBE_WAIT` | 1 (s) | RFC 5227 §1.1 |
| `ARP__PROBE_NUM` | 3 | RFC 5227 §1.1 |
| `ARP__PROBE_MIN` | 1 (s) | RFC 5227 §1.1 |
| `ARP__PROBE_MAX` | 2 (s) | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_WAIT` | 2 (s) | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_NUM` | 2 | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_INTERVAL` | 2 (s) | RFC 5227 §1.1 |

### `_create_stack_ip4_addressing` sleep order

The `ArpTestCase._dad_sleep_durations` list captures these in
order; tests reference them by index:

| Index | Constant | Purpose |
|---|---|---|
| 0 | PROBE_WAIT | Initial 0–1 s random delay (RFC §2.1.1) |
| 1–3 | PROBE_MIN..PROBE_MAX | Three inter-probe sleeps |
| 4 | ANNOUNCE_WAIT | Post-probe quiet period (RFC §2.1.1) |
| 5 | ANNOUNCE_INTERVAL | Between Announcement 1 and 2 (RFC §2.3) |

### `ArpTestCase._drive_dad` API

```python
def _drive_dad(
    self,
    *,
    on_sleep: Callable[[int], None] | None = None,
    num_sleep_callbacks: int = 3,
) -> None:
    """
    'on_sleep' fires with sleep index 0, 1, 2, ... up to
    'num_sleep_callbacks' total. Tests targeting post-probe
    sleeps (indexes 4, 5) pass higher counts.
    """
```

### Branch

`PyTCP_3_0__pre_release`

---

## §13 — Resume prompt

Paste this verbatim after `/compact` to resume the work in any
fresh session:

```
I'm resuming the PyTCP ARP→Linux-host parity work. Read
'docs/refactor/arp_linux_parity.md' first — it's the canonical
punch list with §0 status snapshot. Then read these in order
before any code:

  1. CLAUDE.md (Project North Star, Phase 1 vs Phase 2 split)
  2. .claude/rules/feature_implementation.md (tests-first MUST,
     §7.2 audit before commit, commit discipline)
  3. .claude/rules/unit_testing.md (test authoring conventions,
     §7.2 audit script)
  4. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` (source authoring;
     §6.1 sysctl pattern applies to NUD timing constants)
  5. .claude/skills/sysctl_knob/SKILL.md (workflow when
     adding a registered policy knob)
  6. docs/refactor/sysctl_framework.md (the runtime-tunable
     registry; Phase 0/1/2 shipped — see §8)
  7. docs/refactor/nud_state_machine.md — IF the next item
     is the NUD work (#11/#12/#13/#9). The dedicated doc
     has its own §12 resume prompt.
  8. The current state of packages/pytcp/pytcp/protocols/arp/ + the
     packet_handler__arp__{rx,tx}.py files — these are the
     ARP runtime today.

After reading, confirm you understand:

  - Tier 1 (#1, #2, #3) shipped. Tier 2 RFC 5227 items
    #5/#6/#7/#8 all shipped.
  - Tier 2 remaining: #9 abandon-after-second-conflict (gated
    on the NUD FAILED state — folds into the NUD plan as
    Phase 6). #10 MAX_CONFLICTS dormant (no candidate-rotation
    path).
  - Tier 3: #14 unicast refresh, #15 monotonic clock, #16
    configurable timeout, #17 partial (arp.accept +
    arp.ignore) all shipped. arp.announce / arp.filter
    deferred until multi-interface lands.
  - Sysctl framework Phase 0 (registry) + Phase 1 (ARP
    package migration + #16 retrofit) + Phase 2 (#17 partial)
    shipped. Phase 3+ migrations are per-package, driven by
    feature work.
  - The NUD state machine (#11 + #12 + #13 + #9) is the next
    big architectural piece. Its plan lives in
    'docs/refactor/nud_state_machine.md', split across 6
    phases, ~1 phase per session.
  - Tier 4 (RFC 1027 / RFC 3927) is deliberately deferred
    per the North Star.

Suggested resume order:

  1. NUD Phase 1 — generic 'NeighborCache[A]' module at
     'packages/pytcp/pytcp/lib/neighbor.py' + unit tests. ~80–120k tokens
     of work; one session.
  2. NUD Phase 2 — ArpCache adapter on top of NeighborCache.
  3. NUD Phase 3 — NdCache adapter + ND cache relocation
     ('packages/pytcp/pytcp/stack/nd_cache.py' → 'packages/pytcp/pytcp/protocols/icmp6/
     nd__cache.py').
  4. NUD Phase 4 — reachability hook from TCP (#12).
  5. NUD Phase 5 — bounded cache + GC (#13).
  6. NUD Phase 6 — abandon-after-second-conflict (#9).

Branch: PyTCP_3_0__pre_release.

Before any code, run 'git log --oneline -20' to confirm the
session-end state matches the §0 snapshot in this document.
Tests-first per CLAUDE.md MUST. Run 'make lint && make test'
before each commit; the §7.2 audit on docstrings is a blocker,
not a polish item.

Do NOT push without explicit user request. Commit after each
item; user pushes when ready. Then ask the user which item to
start with (default to "NUD Phase 1" if they say "go" or
"next").
```
