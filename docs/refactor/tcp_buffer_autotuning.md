# TCP buffer auto-tuning (Tier 3) — implementation plan

Status: **scoping** (no code yet). Track: the separately-split Tier-3
item of the host-refinements backlog
(`docs/refactor/host_refinements_backlog.md` "R-autotune"). The Tier-1
`SO_SNDBUF`/`SO_RCVBUF` accounting it builds on is complete
(`docs/refactor/tcp_buffer_accounting.md`). None of this blocks a 3.0.8
release.

## 1. Summary

Linux does **not** size a TCP socket's buffers statically. By default
(`net.ipv4.tcp_moderate_rcvbuf=1`) it grows the receive buffer to track
the connection's bandwidth-delay product — **Dynamic Right-Sizing (DRS)**,
`tcp_rcv_space_adjust` — and grows the send buffer with the congestion
window — `tcp_sndbuf_expand` / `sk_stream_moderate_sndbuf`. An explicit
`setsockopt(SO_RCVBUF/SO_SNDBUF)` sets `SOCK_RCVBUF_LOCK` /
`SOCK_SNDBUF_LOCK` and **disables auto-tuning for that direction** — the
option becomes a hard pin.

PyTCP after Tier-1 honours the *explicit* options but never auto-tunes:
an unset `SO_RCVBUF` advertises a fixed `rcv_wnd_max = 65535`, and an
unset `SO_SNDBUF` bounds the send buffer at the fixed 212992 default. On
a high-BDP path both under-serve throughput (small window, small queue),
and on many idle connections both waste memory. This item closes the
default-behaviour gap.

Two independent tracks, symmetric to Tier-1's A/B split:

| Track | Feature | Linux mechanism | Shape | Risk |
|---|---|---|---|---|
| **R** | receive-buffer DRS | `tcp_rcv_space_adjust` + `tcp_rcv_rtt_measure_ts` | new BDP estimator + grow policy | **large** (the meat) |
| **S** | send-buffer auto-tuning | `tcp_sndbuf_expand` | grow bound with cwnd | small–medium |

Both **actuators already exist** — Tier-1 built the grow-only
`rcv_wnd_max` mutator and the `SO_SNDBUF` gate reads the effective bound
on every iteration. Tier-3 supplies the *policy* that drives them. DRS is
the dominant cost because it needs a **receiver-side RTT estimator** that
PyTCP does not have today (the sender SRTT is unpopulated on a pure
receiver — see §4.1).

**Non-goal (unchanged):** global memory-pressure accounting (`tcp_mem`,
`sk_memory_allocated`, pressure states). That protects *kernel* memory,
which a userspace stack does not own; documented out of scope regardless
of phase.

## 2. The load-bearing decision: static defaults vs auto-tuning

Tier-1 deliberately chose **large static defaults** (`rcv_wnd_max=65535`,
`SO_SNDBUF` default 212992) so the wiring changed no behaviour for a
socket that never sets the option. Linux does the opposite: it starts
**small** (`tcp_rmem[1]`/`tcp_wmem[1]` ≈ 128 KiB / 16 KiB) and grows.
Auto-tuning is the mechanism that makes a small initial buffer safe.

This creates a coupling Tier-3 must resolve up front:

- **DRS is grow-only from the initial `rcv_wnd_max`.** With the current
  65535 initial cap, DRS grows *above* 64 KiB on high-BDP paths — the
  throughput win lands. Good.
- **Send auto-tuning is grow-only from the initial `SO_SNDBUF` default.**
  With the current **212992** (208 KiB) default, `tcp_sndbuf_expand`'s
  target `2 * cwnd * per_mss` only exceeds the default once cwnd
  ≳ 71 full segments (~100 KiB in flight). So send auto-tuning is
  **near-inert** against the large default — it only matters on very
  high-BDP paths, and it never reclaims the 208 KiB from idle
  connections.

**Locked decision (see §7):** Tier-3 lands *paired with* adopting
Linux-style **small initial defaults** for the auto-tuned direction — the
Tier-2 `tcp_rmem` / `tcp_wmem` triples become the source of the initial
value, and auto-tuning grows from `[1]` (default) toward `[2]` (max).
Without this pairing, send auto-tuning is cosmetic and the idle-memory
parity win is lost. The Tier-2 `tcp_rmem`/`tcp_wmem` sysctl work
(`tcp_buffer_accounting.md` §7) is therefore a **hard prerequisite** of
Track S and the clamp source for Track R.

## 3. Current-state map (load-bearing sites)

Receive side (Track R):
- **Actuator (exists):** `TcpSession.grow_rcv_wnd_max(new_max)` —
  `session/tcp__session.py:1020`; grow-only
  (`self._win.rcv_wnd_max = max(self._win.rcv_wnd_max, new_max)`, `:1034`),
  documented lockless (only the FSM thread reads `rcv_wnd_max`). This is
  exactly the DRS output actuator.
- **Advertised window (exists):** `_rcv_wnd` property
  (`tcp__session.py:1100`) = `max(0, rcv_wnd_max - len(_rx_buffer))`,
  advertised scaled by `rcv_wsc` at `tcp__session.py:1757`
  (`tcp__win = _rcv_wnd >> rcv_wsc`) and `session/tcp__session__tx.py:115`.
- **Window state:** `WindowState`
  (`state/tcp__state__window.py:40`): `rcv_wnd_max=65535` (`:88`),
  `rcv_wsc=7` (`:80`), `rcv_mss=0` (`:75`). `rcv_wnd_max` seeded from
  `SO_RCVBUF` at `tcp__session.py:176`.
- **Recv drain (the copied-bytes hook):** `TcpSession.receive`
  (`tcp__session.py`, the `del self._rx_buffer[:byte_count]` drain under
  `_lock__rx_buffer`). This is where Linux calls `tcp_rcv_space_adjust`
  — the natural DRS trigger point.
- **RX enqueue / RCV.NXT advance (the receiver-RTT hook):**
  `_enqueue_rx_buffer` (`tcp__session.py:1904`, append at `:1920`); the
  in-order segment handler advances `_rcv_seq.nxt` and enqueues at
  `session/tcp__session__ack.py:701-717`; the reassembly-flush enqueue is
  `session/tcp__session__validate.py:471`.
- **RFC 7323 timestamps (RTT source):** `TimestampsState`
  (`state/tcp__state__timestamps.py:40`): `send_ts` (bilateral-active),
  `ts_recent`. Inbound `tcp__tsecr` already read for the *sender* RTT
  sample at `ack.py:515-517` (`ts_rtt_ms = now_ms - tcp__tsecr`, guarded
  by `session._ts.send_ts`) — the same formula Track R reuses for the
  *receiver* estimator.
- **Sender RTT (not reusable directly):** `RtoState`
  (`tcp__rto.py:95`): `srtt_ms`/`rttvar_ms` (`None` until first sample),
  updated in `_phase3_harvest_rtt_samples` (`ack.py:483`). Populated only
  when our data is acked — unusable on a pure receiver (§4.1).

Send side (Track S):
- **Actuator (exists):** `_effective_sndbuf()`
  (`runtime/socket/__init__.py:1444`) = `_so_sndbuf if set else
  SOCKET__SO_SNDBUF__DEFAULT` (`:1453`); read every iteration of the
  Tier-1 gate `TcpSession._charge_tx_buffer` (`tcp__session.py:1198`,
  bound read at `:1236`). Raising an auto bound here immediately widens
  the gate.
- **cwnd (the growth driver):** `CcState` (`state/tcp__state__cc.py:70`):
  `cwnd` (`:82`), seeded `self._cc.cwnd = self._win.snd_mss` at connect
  (`tcp__session.py:408`); read as `self._cc.cwnd`. `snd_mss` on
  `WindowState`.
- **Send buffer:** `TxBufferState` (`state/tcp__state__tx_buffer.py:42`),
  `buffer: bytearray` (`:59`); occupancy is `len(_tx.buffer)`.
- **ACK-path trigger point:** the cum-ACK / cwnd-growth site in
  `session/tcp__session__ack.py` (same handler as the Tier-1 drain +
  `_wake_sndbuf_waiters()` call). `tcp_sndbuf_expand` fires here.

Sysctl framework:
- `register(*, key, module_name, attr, default, validator, description,
  interface_scope=False)` — `stack/sysctl.py:76`; per-interface knobs use
  `interface_scope=True` (dict backed by ifname, `sysctl_iface.get_for_iface`).
  Example TCP knob `tcp.rto.initial_ms` at `tcp__constants.py:211`;
  per-interface `tcp.base_mss` at `:291`. Cross-knob constraints via
  `register_finalize_validator` (`sysctl.py:110`). Add knobs with the
  `sysctl_knob` skill (`.claude/skills/sysctl_knob/SKILL.md`).
- **Mid-connection propagation pattern:** `TcpSocket.setsockopt` stores
  the socket field then guards `if self._tcp_session is not None:
  self._tcp_session.set_*(...)` — SO_RCVBUF example
  `runtime/socket/tcp__socket.py:379-387`, TCP_CONGESTION
  `:410-420`; `connect()`/`listen()` re-propagate at construction.

## 4. Track R — receive-buffer DRS

Linux `tcp_rcv_space_adjust` (net/ipv4/tcp_input.c), transcribed to
PyTCP terms:

```
once per receiver-RTT, when the app has just drained the rx buffer:
    copied  = bytes the app consumed since the last measurement
    if copied <= rcv_space.space:      # not growing → just re-measure
        rcv_space.space = copied; return
    if DRS enabled (tcp.moderate_rcvbuf) and SO_RCVBUF unset:
        rcvwin  = 2*copied + 16*advmss                 # BDP + slack
        grow    = rcvwin * (copied - rcv_space.space) / rcv_space.space
        rcvwin += 2*grow                               # sender-rate headroom
        target  = min( rcvwin_rounded_to_mss * per_mss , tcp.rmem.max )
        if target > rcv_wnd_max:
            grow_rcv_wnd_max(target)                   # existing actuator
    rcv_space.space = copied
```

`advmss` = our advertised MSS (`_win.rcv_mss`); `per_mss` ≈ `rcv_mss`
(PyTCP has no skb truesize overhead, so `per_mss = rcv_mss` — see §7).

### R1 — receiver-side RTT estimator (the prerequisite, medium)

**Why it's needed:** DRS gates its once-per-RTT cadence on a *receiver*
RTT. On a bulk download PyTCP only sends bare ACKs, so `_rto_state.srtt_ms`
never gets a sample (no acked data of ours) — it stays `None` and DRS
would never fire. Linux keeps a separate `rcv_rtt_est` fed by
`tcp_rcv_rtt_measure_ts`: when a **data** segment carries a TSecr echoing
a timestamp we sent, `rtt = now - TSecr` is one round trip, valid even
for a pure receiver.

- New `state/tcp__state__rcv_rtt.py` `@dataclass(slots=True)`
  `RcvRttState`: `rtt_ms: int | None = None` (EWMA, `None` until first
  sample), plus a coarse fallback anchor (`seq`, `time_ms`) for the
  no-timestamps path.
- Instantiate `self._rcv_rtt: RcvRttState = RcvRttState()` in
  `TcpSession.__init__` (import block `tcp__session.py:59-69`, mirror the
  `_ts` / `_rto_state` lines).
- **Hook:** in the in-order data-segment path (`ack.py`, near the
  `_enqueue_rx_buffer` at `:717`), when `session._ts.send_ts` and the
  segment carries data and a valid `tcp__tsecr`, sample
  `rtt = (now_ms - tcp__tsecr) & 0xFFFF_FFFF` and EWMA it into
  `_rcv_rtt.rtt_ms` (same shape as `tcp__rto.update`, `srtt_ms` EWMA at
  `tcp__rto.py:152`). Runs on the RX thread.
- **Fallback (timestamps off):** mirror `tcp_rcv_rtt_measure` — measure
  the wall time to receive one full `rcv_wnd`-worth of data. Coarser;
  land it only if a no-TS DRS test demands it, else document DRS as
  timestamps-gated for the first pass (Linux DRS is materially weaker
  without timestamps too).

### R2 — the `RcvSpaceState` struct (small)

- New `state/tcp__state__rcv_space.py` `@dataclass(slots=True)`
  `RcvSpaceState`: `space: int` (last measured per-RTT copied bytes,
  seed from the initial `rcv_wnd_max`), `copied_anchor: int` (value of
  the cumulative copied-bytes counter at last measure), `time_ms: int`
  (last-measure timestamp).
- Cumulative copied counter: add `self._rcv_copied_total: int = 0` and
  bump it by `byte_count` in `receive()` right after the
  `del self._rx_buffer[:byte_count]` drain. `copied` per measurement =
  `_rcv_copied_total - rcv_space.copied_anchor`.
- Seed `RcvSpaceState.space` from `rcv_wnd_max` at construction (mirror
  the `_win`/`_cc` post-init-from-derived-value pattern,
  `tcp__session.py:169`/`:408`).

### R3 — the measure/adjust trigger (small–medium)

- **Where:** inside `receive()`, after the drain + copied bump — the
  app-thread analogue of Linux calling `tcp_rcv_space_adjust` from
  `tcp_recvmsg`. Keeps the copied counter read on the same thread that
  writes it (no cross-thread on the measurement).
- **Cadence gate:** run the adjust only when
  `now_ms - rcv_space.time_ms >= (_rcv_rtt.rtt_ms or return)` — one
  receiver-RTT elapsed. `rtt_ms` is written by the RX thread, read here
  by the app thread (atomic int-object read; benign staleness — worst
  case one deferred adjust).
- On each run: compute `copied`, then either re-measure (`copied <=
  space`) or run R4's grow, then reset `space`/`copied_anchor`/`time_ms`.

### R4 — the DRS grow formula + clamp (medium, the policy)

- Implement the `rcvwin = 2*copied + 16*advmss`, `grow` sender-rate
  term, `min(..., tcp.rmem.max)` clamp exactly as §4's transcription.
  `advmss = _win.rcv_mss` (fall back to the base-MSS knob when 0).
- **Actuator:** call the existing `grow_rcv_wnd_max(target)` — grow-only,
  so a DRS estimate below the current cap is a no-op (identical contract
  to Tier-1 A3). No new mutator.
- **Lock disable:** run R3/R4 only when `self._socket._so_rcvbuf is None`
  — an explicit `SO_RCVBUF` is `SOCK_RCVBUF_LOCK`, pinning the window and
  disabling DRS. This makes DRS and the Tier-1 A3 mid-connection resize
  mutually exclusive writers of `rcv_wnd_max` (DRS on the app thread when
  unset; A3 on the setsockopt thread when set), preserving the
  single-writer invariant the grow-only mutator relies on
  (no-GIL note §8).

### R0 — WSCALE headroom (decision, likely no code)

DRS grows `rcv_wnd_max`, but the advertised window is
`rcv_wnd_max >> rcv_wsc` with `rcv_wsc` fixed at handshake (RFC 7323 — a
receiver cannot change its shift mid-connection). The current
`rcv_wsc=7` gives `0xFFFF << 7 ≈ 8 MiB` of scaling headroom, comfortably
above the Linux `tcp_rmem[2]` default (~6 MiB). **Decision:** keep
`rcv_wsc=7`; DRS clamps `target` at `min(tcp.rmem.max, 0xFFFF <<
rcv_wsc)` so it can never advertise past what the negotiated shift can
express. Only a `tcp.rmem.max > 8 MiB` operator override would need
`rcv_wsc` derived from `tcp.rmem.max` *at SYN* — a niche follow-on, noted
not built.

## 5. Track S — send-buffer auto-tuning

Linux `tcp_sndbuf_expand` (fired from `tcp_new_space` when
`tcp_should_expand_sndbuf`), transcribed:

```
on ACK processing, when SO_SNDBUF unset and cwnd is growing:
    per_mss = snd_mss (+ overhead; PyTCP has none → snd_mss)
    nr_segs = max(TCP_INIT_CWND, cwnd_in_segments, reordering+1)
    target  = 2 * nr_segs * per_mss              # 2 windows (fast-recovery slack)
    if target > sndbuf_auto:
        sndbuf_auto = min(target, tcp.wmem.max)  # grow-only
```

### S1 — the auto bound + `_effective_sndbuf` integration (small)

- Add `_sndbuf_auto: int = 0` on the socket base
  (`runtime/socket/__init__.py`, near `_so_sndbuf`), a grow-only value
  written by the RX/ACK thread and read by the app thread.
- `_effective_sndbuf()` becomes: `return self._so_sndbuf if self._so_sndbuf
  is not None else max(SOCKET__SO_SNDBUF__DEFAULT, self._sndbuf_auto)`.
  Because `_charge_tx_buffer` re-reads the bound every loop iteration and
  the ACK-drain already wakes blocked writers, a raised auto bound admits
  more data on the next wake with **zero** new wiring in the gate.

### S2 — the expand policy + trigger (small–medium, the meat)

- New `TcpSession._maybe_expand_sndbuf()`: implement §5's target; write
  `self._socket._sndbuf_auto = max(self._socket._sndbuf_auto,
  min(target, tcp.wmem.max))` when `self._socket._so_sndbuf is None`
  (else `SOCK_SNDBUF_LOCK` — no-op).
- **Trigger:** call it from the ACK handler
  (`session/tcp__session__ack.py`) right after cwnd is updated, alongside
  the existing Tier-1 drain / `_wake_sndbuf_waiters()`. Single-writer
  (RX thread) of `_sndbuf_auto`; the app thread only reads it — no lock,
  consistent with the grow-only mutators.
- No wake needed on grow: a writer parked in `_charge_tx_buffer` is woken
  by the same ACK's `_wake_sndbuf_waiters()`, then re-reads the widened
  `_effective_sndbuf()`.

### S3 — pairing with the small initial default (see §2 / §7)

Only meaningful once the Tier-2 `tcp.wmem` triple lands and the unset
send default drops to `tcp.wmem.default` (small). Until then S2 grows
only above 208 KiB (near-inert). Land S1/S2 behind the Tier-2 default
switch, or ship S with the default-switch in the same series so the
behaviour is observable.

## 6. Sysctl knobs (registered as part of this work)

Per the framework's one-attr-per-key model, the Linux triples become
three flat int knobs each (naming mirrors `tcp.rto.initial_ms`):

| Knob | Linux equiv | Consumed by | Notes |
|---|---|---|---|
| `tcp.moderate_rcvbuf` | `net.ipv4.tcp_moderate_rcvbuf` | R4 enable gate | default 1 (on) |
| `tcp.rmem.min` / `.default` / `.max` | `net.ipv4.tcp_rmem` | R4 clamp = `.max`; `.default` seeds unset `rcv_wnd_max` | Tier-2 overlap |
| `tcp.wmem.min` / `.default` / `.max` | `net.ipv4.tcp_wmem` | S2 clamp = `.max`; `.default` seeds unset send bound | Tier-2 overlap |

`register_finalize_validator` enforces `min <= default <= max` on each
triple (mirror `_finalize__persist_max_ge_rto_initial`,
`tcp__constants.py:343`). There is **no** separate `tcp_moderate_sndbuf`
knob in Linux — send auto-tuning is gated only by `SOCK_SNDBUF_LOCK` +
memory pressure; PyTCP gates on `_so_sndbuf is None` alone.

`tcp.rmem`/`tcp.wmem` are the Tier-2 deliverable; registering them here
means **Track R/S subsumes that slice of Tier-2**. Keep them flat (not
`interface_scope`) for the first pass; per-interface is a later refinement.

## 7. Decisions to lock

- **Pair Track S with the small-default switch (§2).** Send auto-tuning
  against the 208 KiB static default is cosmetic. Ship S2 together with
  adopting `tcp.wmem.default` as the unset send bound, or the track
  delivers no observable parity.
- **DRS is timestamps-gated for the first pass (R1).** The receiver RTT
  estimator uses the RFC 7323 TSecr echo. The no-timestamps
  `tcp_rcv_rtt_measure` fallback is a documented follow-on, not first-pass
  scope — Linux DRS is materially weaker without timestamps anyway.
- **`per_mss` = MSS, no truesize overhead.** Linux inflates every segment
  by `SKB_TRUESIZE(...)` to account for kernel skb bookkeeping; a
  userspace `bytearray` has no such overhead, so PyTCP uses the bare MSS.
  This is the same "no 2× doubling / no `tcp_adv_win_scale` reservation"
  deviation already locked for Tier-1 — auto-tuning inherits it. Document
  inline.
- **Auto-tuning ⇔ option-unset (`SOCK_*BUF_LOCK`).** An explicit
  `SO_RCVBUF`/`SO_SNDBUF` disables the corresponding track. This reuses
  the Tier-1 "explicit vs None" distinction as the lock, so no new
  `userlocks` bitfield is needed. A mid-connection `setsockopt` that pins
  the option immediately stops the track (the next trigger sees the
  non-`None` field and no-ops).
- **Grow-only, both directions.** DRS and send auto-tuning only ever
  raise their bound within a connection (Linux shrinks only under memory
  pressure — a non-goal). Identical contract to Tier-1 A3.
- **Keep `rcv_wsc=7` (R0).** Clamp DRS at `min(tcp.rmem.max, 0xFFFF <<
  rcv_wsc)`; SYN-time WSCALE derivation is a niche follow-on.

## 8. Threading / no-GIL

Per the free-threading north star (`no_gil_thread_safety_audit.md`),
every cross-thread field needs a defined single-writer or a lock:

- **`rcv_wnd_max`** — written by DRS on the **app thread** (in
  `receive()`) when `SO_RCVBUF` unset; written by Tier-1 A3 on the
  **setsockopt thread** when set. Mutually exclusive by the §7 lock, so
  still effectively single-writer; the `max()` RMW is safe because the
  two writers never both apply. Read by the FSM thread (`_rcv_wnd`). The
  set→unset transition (clearing `SO_RCVBUF` mid-connection is not a
  supported operation — Linux has no "unlock") keeps it clean.
- **`_rcv_rtt.rtt_ms`** — single-writer (RX thread, R1), read by the app
  thread (R3). Atomic int-object read; staleness is benign (one deferred
  adjust).
- **`_rcv_copied_total` / `RcvSpaceState`** — touched only on the app
  thread (`receive()`). No cross-thread.
- **`_sndbuf_auto`** — single-writer (RX/ACK thread, S2), read by the app
  thread (`_effective_sndbuf` under `_snd_buf_cond`). Grow-only int; no
  lock. The read already happens inside the condition the writer's
  companion `_wake_sndbuf_waiters()` notifies, so a grow is observed on
  the next wake.

No new lock is introduced; every added field is single-writer by
construction. Call this out in the commit bodies and add the audit-ledger
row.

## 9. Testing strategy

**Tests-first / RED discipline (mandatory,
`feature_implementation.md` §2).** Every numbered phase opens with the
failing test(s) that pin the behaviour, run BEFORE the implementation,
and **verified to fail for the predicted reason** — not merely to fail.
The predicted pre-implementation failure mode is stated per case below so
the RED step is auditable (mirroring Track B, where 4 of 6 cases were red
pre-impl for their predicted reasons). The two companion cases that pass
pre-impl (a getsockopt-parity read, an unset-default read) are noted as
such; a case that passes before the code exists is not pinning that
code and must be re-examined. Each test file passes the §7.2
docstring-audit; docstrings open `Ensure …` and carry the trailing
`Reference:` line (RFC 9293 §3.8.6 for the window envelope, plus a
`PyTCP test infrastructure (no RFC clause).` fallback where the behaviour
is a Linux-default with no RFC clause). Layer per
`feature_implementation.md` §2.1: R1's estimator EWMA is a candidate for
an added unit test on the pure update function; everything else is
integration (FSM + wire-level).

Integration (`TcpTestCase`), mirroring `test__tcp__session__so_rcvbuf.py`
/ `test__tcp__session__so_sndbuf.py`:

- **Track R:**
  - Receiver RTT estimator (R1): drive inbound data segments carrying
    TSecr echoing our TSval; assert `_rcv_rtt.rtt_ms` converges (EWMA) —
    pure state test, no wall clock (`FakeTimer` + injected `now_ms`).
    *RED:* pre-impl `_rcv_rtt` does not exist / `rtt_ms` stays `None`
    (`AttributeError` or unchanged-`None` assert).
  - DRS grow (R4): establish with timestamps, feed a full BDP of data +
    app drains, advance one receiver-RTT, assert `rcv_wnd_max` grew per
    the formula and the advertised window (`_rcv_wnd >> rcv_wsc`) widened.
    *RED:* pre-impl `rcv_wnd_max` stays at the 65535 seed (no grow policy
    wired) — the assert on the grown value fails.
  - Clamp: assert the grow saturates at `tcp.rmem.max`. *RED:* pre-impl
    no grow at all, so the saturation value is never reached.
  - Lock: set `SO_RCVBUF` explicitly, replay the same load, assert
    `rcv_wnd_max` does **not** move (DRS disabled). *Passes pre-impl*
    (nothing grows it yet) — a regression guard that only bites once R4
    lands, so it MUST be paired with the grow test in the same commit or
    it pins nothing.
  - Cadence: two adjusts within one RTT collapse to one measurement.
    *RED:* pre-impl there is no adjust to collapse — assert the single
    measurement fails once R3 exists but over-fires.
- **Track S:**
  - Expand (S2): drive ACKs that grow cwnd, assert `_effective_sndbuf()`
    rises to `2*cwnd*snd_mss` (with the small-default switch active) and
    saturates at `tcp.wmem.max`. *RED:* pre-impl `_effective_sndbuf()`
    returns the static default regardless of cwnd — the assert on the
    grown bound fails.
  - A blocked `_charge_tx_buffer` writer is admitted after an ACK both
    drains *and* expands the bound (compose with the Tier-1 wake test).
    *RED:* pre-impl the writer is admitted only by the drain, not the
    expand — assert it is admitted by the expand alone (buffer not yet
    drained) fails.
  - Lock: explicit `SO_SNDBUF` freezes the bound across cwnd growth.
    *Passes pre-impl* — regression guard, pair with the expand test.
- **Sysctl:** `tcp.moderate_rcvbuf=0` disables DRS entirely (*RED* once
  R4 exists: the grow that fires with the knob on must not fire with it
  off); the `min<=default<=max` finalize validator rejects a bad triple
  (*RED* pre-impl: no validator registered, the bad triple is accepted).

Every phase's RED run is captured in the commit body ("N red pre-impl for
<reason>, M companion guards green"), matching the Track B commit.

Adherence: refresh `docs/rfc/tcp/rfc9293__tcp/adherence.md` §3.8.6
(managing the window) and §3.10.2 (SEND) with the auto-tuning behaviour;
DRS has no single RFC clause (it is a Linux default) — cite RFC 9293
§3.8.6 for the window-management envelope and Linux
`tcp_rcv_space_adjust` / `tcp_sndbuf_expand` in the commit bodies per the
CLAUDE.md "Linux as tiebreaker" precedence.

## 10. Recommended ordering & risk

1. **Tier-2 `tcp.rmem` / `tcp.wmem` triples** (§6) — prerequisite clamp +
   default source. Small, no behaviour change if defaults match today's
   constants; the observable switch is step 5. **DONE** — registered
   `tcp.moderate_rcvbuf` (default 1) + the `tcp.rmem` / `tcp.wmem`
   min/default/max triples in `tcp__constants.py`, each with a
   per-value validator and a `min <= default <= max` finalize validator.
   `.default` entries keep today's effective values (rcv 65535,
   snd 212992); only `.max` clamps carry Linux-parity values. No runtime
   consumer yet. Tests: `test__tcp__constants.py`.
2. **S1 + S2** (send auto-tuning) — smaller track, exercises the sysctl
   clamp and the ACK-path trigger with low risk (grow-only widening of an
   existing gate).
3. **R1** (receiver RTT estimator) — the DRS prerequisite; self-contained,
   unit-testable in isolation.
4. **R2 + R3 + R4** (DRS struct, trigger, grow policy) — the large piece;
   lands on top of R1.
5. **The small-default switch** (§2 / §7) — flip the unset `SO_SNDBUF`
   (and optionally `rcv_wnd_max`) default to the Tier-2 `.default`,
   making auto-tuning observable. Behaviour-changing → its own deliberate
   commit with the test-churn it implies.
6. **R0 / no-TS fallback** — optional follow-ons, only if a consumer needs
   >8 MiB windows or DRS on non-timestamped connections.

Each numbered item is one tests-first commit (or a small pair), `make
lint` clean, §7.2 docstring-audit clean, adherence + this doc updated in
lockstep, full suite green before commit.

## 11. Rough size

DRS (Track R: R1–R4) is the 1–2-week core — the receiver RTT estimator
and the BDP grow policy are genuinely new machinery. Send auto-tuning
(Track S) is a few days once the Tier-2 triples exist. The whole Tier-3
item is the largest single host-refinement remaining; none of it blocks a
release, and the Tier-1 options already work without it.
