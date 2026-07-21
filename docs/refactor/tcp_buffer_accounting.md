# TCP `SO_SNDBUF` / `SO_RCVBUF` — buffer accounting scoping

Status: **scoping** (no code yet). Track: the last open item of the
host-refinements backlog (`docs/refactor/host_refinements_backlog.md`).
None of this blocks a 3.0.8 release.

## 1. Summary

Linux bounds a TCP socket's send buffer by `SO_SNDBUF` and derives the
advertised receive window from `SO_RCVBUF`. PyTCP stores both options
(`_so_sndbuf` / `_so_rcvbuf`, `runtime/socket/__init__.py:584-585`) but the
TCP path reads neither — `send()` buffers unboundedly and the advertised
window is capped by a hardcoded constant.

This is **two asymmetric sub-features**, best treated as two independent
tracks:

| Track | Feature | Shape | Risk |
|---|---|---|---|
| **A** | `SO_RCVBUF` → advertised receive window | mostly wiring an **existing** derivation | low–medium |
| **B** | `SO_SNDBUF` → send-buffer backpressure | **new** byte-stream flow control | medium |

Track A is smaller and should land first. Track B reuses the
already-built base-class send-buffer primitive but needs TCP-specific
byte-stream (partial-write) semantics.

**Not in scope for this item:** the datagram `SO_SNDBUF` accounting
(UDP/RAW/PING) — already shipped (R3). TCP has its own buffering model
(unacked data held for retransmission, released on ACK), which is why it
was correctly excluded from the datagram counter.

## 2. Current-state map (load-bearing sites)

Send side:
- `TcpSocket.send` — `runtime/socket/tcp__socket.py:871` → `TcpSession.send`.
- `TcpSession.send` — `protocols/tcp/session/tcp__session.py:1142`: appends
  `data` to `self._tx.buffer` under `_lock__tx_buffer` (`:1160`), kicks the
  pump, returns `len(data)`. **Unbounded, no backpressure.**
- Send buffer: `TxBufferState.buffer: bytearray` —
  `protocols/tcp/state/tcp__state__tx_buffer.py:59`. Unacked and unsent
  bytes share this one buffer; SND.UNA/SND.NXT index into it via
  `_tx_buffer_una` (`tcp__session.py:1104`) / `_tx_buffer_nxt` (`:1087`).
- **Release point** (ACK trims the buffer) — `tcp__session__ack.py:740`:
  `session._tx.drain(bytes_count=session._tx_buffer_una)`
  (`TxBufferState.drain`, `tx_buffer.py:77` = `del buffer[:n]` + `seq_mod`
  advance). `seq_mod` is also bumped for SYN/FIN, so `_tx_buffer_una`
  counts **payload bytes only** — charge/release units reconcile cleanly.
- TFO pre-load also writes the buffer: `preload_tx_buffer`
  (`tcp__session.py:1053`).

Receive side:
- Receive buffer: `TcpSession._rx_buffer: bytearray` (`tcp__session.py:142`);
  enqueue `_enqueue_rx_buffer` (`:1817`), drain in `receive` (`:1196`).
- **RCV.WND is already buffer-derived** — `_rcv_wnd` property
  (`tcp__session.py:1074`): `max(0, self._win.rcv_wnd_max - len(self._rx_buffer))`.
  Shrinks dynamically as the app falls behind.
- **The cap is a fixed constant**: `WindowState.rcv_wnd_max: int = 65535`
  (`tcp__state__window.py:88`) — the single field `SO_RCVBUF` must drive.
- On-wire advertisement: `tcp__session.py:1670`
  (`tcp__win = self._rcv_wnd >> self._win.rcv_wsc`) and `tcp__session__tx.py:115-127`
  (pre-handshake `min(_rcv_wnd, 0xFFFF)`; SWS zero-clamp; post-handshake
  `_rcv_wnd >> rcv_wsc`). WSCALE (RFC 7323) is fully present:
  `rcv_wsc = 7` default (`window.py:80`).

Reusable primitive (already built for R3 datagram sockets):
- `_snd_outstanding` counter + `_snd_buf_cond: threading.Condition`
  (`runtime/socket/__init__.py:592-593`), driven by `_charge_sndbuf`
  (`:1447`, blocks on the condition honouring `_blocking` / `_so_sndtimeo`,
  raises `BlockingIOError(EAGAIN)`) and `_release_sndbuf` (`:1476`,
  `notify_all`). `_effective_sndbuf` (`:1436`) → `SOCKET__SO_SNDBUF__DEFAULT`
  = 212992. Close-time wake at `:1906`.
- **Caveat:** `_charge_sndbuf` is all-or-nothing (a whole datagram fits or
  blocks). TCP `send()` is a byte stream with **partial-write** semantics —
  Track B needs its own gate over the same counter/condition, not a direct
  reuse.

Threading:
- FSM under `_lock__fsm: RLock` (`tcp__session.py:520`); buffer locks
  `_lock__tx_buffer` (`:526`) / `_lock__rx_buffer` (`:523`).
- **Documented lock order `_lock__fsm → _lock__tx_buffer`** (`:1162`).
- The cum-ACK drain (release point) runs on the RX/timer thread **holding
  `_lock__fsm`**. `_snd_buf_cond` is independent of both locks, so a release
  call from there is inversion-safe — but the session must reach its owning
  `TcpSocket` (the counter lives on the socket).

## 3. Track A — `SO_RCVBUF` → advertised receive window

Goal: `rcv_wnd_max` derives from the socket's `SO_RCVBUF` instead of the
fixed 65535, so a larger receive buffer advertises a larger window.

### A1 — `_effective_rcvbuf()` + getsockopt parity (small)
**DONE** (commit `c1c0d7bd`). Added `_effective_rcvbuf()` +
`SOCKET__SO_RCVBUF__DEFAULT = 65535` (mirrors `_effective_sndbuf`);
`getsockopt(SO_RCVBUF)` / `(SO_SNDBUF)` now report the effective value, not
`0`-when-unset. Datagram RX-drop still reads `_so_rcvbuf` directly (unset =
unbounded) — reconciling it to `_effective_rcvbuf()` is a Tier-2 item.

### A2 — drive `rcv_wnd_max` from `_effective_rcvbuf()` at SYN

**DONE** (commit pending). `TcpSession.__init__` sets
`self._win.rcv_wnd_max = self._socket._effective_rcvbuf()` right after the
`WindowState()` allocation, so the advertised window derives from
`SO_RCVBUF` (set before `connect()`/`listen()`); unset keeps 65535.

**A2a/A2b collapsed** — no separate WSCALE-derivation step was needed:
`rcv_wsc` already defaults to **7** (`tcp__state__window.py:80`), so
`rcv_wnd_max` up to `0xFFFF << 7 ≈ 8 MiB` is advertised correctly by the
existing `_rcv_wnd >> rcv_wsc` machinery. The pre-handshake SYN still clamps
to `min(_rcv_wnd, 0xFFFF)` (`tx.py:115`), so a large cap advertises ≤ 64 KiB
on the SYN then scales up post-handshake — exactly Linux behaviour. Only a
cap **> ~8 MiB** would need a larger `rcv_wsc` (a niche future refinement,
was the old "A2b"). Tests: `TestTcpSessionSoRcvbuf` (cap from SO_RCVBUF,
default unset, window shrinks with occupancy against the sized cap). Harness
`_make_active_session` gained a `so_rcvbuf=` param.

### A3 — mid-connection SO_RCVBUF change (harder / optional)
- RFC 9293 §3.8.6.2.1: a receiver **SHOULD NOT** shrink the window (retract
  the right edge). If SO_RCVBUF is *lowered* mid-connection, the cap must
  not instantly retract the advertised right edge — let it take effect only
  as the buffer drains ("cap grows freely; shrinks only via occupancy").
- **Recommendation:** land A1+A2 first with the documented limitation
  "`SO_RCVBUF` is honoured from the value set before `connect()`/`listen()`;
  a mid-connection change grows the window but never retracts it." Treat A3
  as an optional refinement.

## 4. Track B — `SO_SNDBUF` → send-buffer backpressure

Goal: bound `_tx.buffer` occupancy by `SO_SNDBUF`; a `send()` that would
overflow blocks (up to `SO_SNDTIMEO`) or does a partial / `EAGAIN` write.

### B1 — release wiring from the cum-ACK drain (small–medium)
- On the ACK drain (`ack.py:741`), after `self._tx.drain(...)`, release the
  drained payload byte count on the owning socket's send-buffer counter
  (`_release_sndbuf` / `_snd_buf_cond.notify_all`). Route session→socket via
  `session._socket`. Inversion-safe (condition independent of `_lock__fsm`).
- Charge counterpart lands in B2; B1 alone is inert (nothing charges yet),
  so B1+B2 are effectively one commit or B1 folds into B2.

### B2 — the send gate + partial-write semantics (medium, the meat)
- Gate `TcpSession.send` (or `TcpSocket.send`) by `_so_sndbuf` against
  current buffer occupancy (`len(self._tx.buffer)`), charging `len(data)`.
- **TCP byte-stream semantics differ from datagram all-or-nothing:**
  - Blocking socket, buffer full: block until room frees (woken by the
    ACK-drain release), up to `SO_SNDTIMEO` → then `EAGAIN`. Linux blocks
    until *at least some* room, then writes what fits.
  - Non-blocking socket: write as many bytes as fit, return that count;
    `EAGAIN` only if zero room.
  - This is **not** `_charge_sndbuf`'s all-or-nothing contract — write a
    TCP-specific `_charge_tx_sndbuf(data) -> accepted_len` over the same
    `_snd_buf_cond` / `_snd_outstanding` (or a TCP-local counter that simply
    reads `len(self._tx.buffer)` under `_lock__tx_buffer`, avoiding a
    second counter to keep in sync).
  - **Preference:** measure occupancy directly from `len(self._tx.buffer)`
    (the authoritative send-buffer size) rather than a parallel
    `_snd_outstanding` — no reconciliation risk, and the ACK drain already
    updates it. The condition/blocking machinery is the only reused part.
- `_lock__tx_buffer` ordering: the gate reads/extends the buffer under
  `_lock__tx_buffer`; the blocking wait must release that lock while waiting
  (use `_snd_buf_cond` wait, re-check occupancy on wake).
- getsockopt(SO_SNDBUF) effective value for TCP (mirror A1).
- Tests (integration, `TcpTestCase`): a blast > SO_SNDBUF blocks / partial-
  writes; an ACK that drains the buffer wakes the blocked writer; the
  non-blocking path returns a short count / `EAGAIN`; `close()` wakes a
  blocked writer.

### B3 — TFO pre-load reconciliation (small)
- `preload_tx_buffer` (`tcp__session.py:1053`) also fills the buffer; ensure
  its bytes are accounted the same way (charge on preload, released on the
  same ACK drain). Likely automatic if occupancy is measured from
  `len(self._tx.buffer)`.

## 5. Recommended ordering &amp; risk

1. **A1** (`_effective_rcvbuf` + getsockopt parity) — smallest, no
   behaviour change; unblocks A2.
2. **A2a** (`rcv_wnd_max` from rcvbuf, cap ≤ 64 KiB, fixed WSCALE) — the
   first behavioural `SO_RCVBUF` win, low risk.
3. **A2b** (WSCALE-derived cap > 64 KiB) — the harder receive-window piece;
   optional if 64 KiB is enough for now.
4. **B2** (send gate + partial-write) with **B1** release folded in — the
   send-backpressure feature; medium risk (touches `send()` + the ACK
   path). **B3** rides along.
5. **A3** (mid-connection rcvbuf shrink-safety) — optional refinement.

Each numbered item is one tests-first commit (or a small pair). Every phase
lands `make lint` clean, §7.2 docstring-audit clean on touched tests,
adherence docs (RFC 9293 §3.8.6 receive-window; RFC 7323 WSCALE) updated in
lockstep where a phase changes advertised-window behaviour, and the full
suite green before commit.

## 6. Decisions (locked)

- **A2b IS in scope (Linux parity).** Linux advertises WSCALE'd receive
  windows > 64 KiB by default; capping at 64 KiB would be a deviation. So
  the first pass derives `rcv_wsc` from the desired cap and advertises a
  genuinely scaled window (A2a → A2b).
- **Tier-1 default cap stays 65535** so the wiring phases change no
  behaviour for a socket that never sets `SO_RCVBUF`; only an explicit
  `setsockopt` alters the window. Adopting a **Linux-style larger static
  default** (~128 KiB, `tcp_rmem`-style) is a **Tier-2** step (§7) — it
  changes every connection's advertised window and carries test churn, so
  it lands as its own deliberate commit, not inside the wiring.
- **No Linux 2× doubling** of the requested `SO_SNDBUF`/`SO_RCVBUF`,
  consistent with the R3 datagram `SO_SNDBUF` deviation (documented). A
  strict-parity doubling + `tcp_adv_win_scale` overhead reservation is a
  **Tier-2** item.
- **B2 occupancy source: measure `len(self._tx.buffer)` directly** (single
  source of truth, already updated by the ACK drain) rather than a parallel
  `_snd_outstanding` counter — only `_snd_buf_cond`'s blocking/wake
  machinery is reused, not the counter.

## 7. Parity tiering (the full-Linux-parity ladder)

"Full Linux parity" for TCP buffering is a spectrum. **This backlog item is
Tiers 1–2.** Tier 3 is split into its own backlog entry; Tier 4 is a
non-goal.

- **Tier 1 — honour the options (this item).** `SO_RCVBUF` → scaled
  advertised window (Track A: A1, A2a, A2b); `SO_SNDBUF` → send-buffer
  backpressure with partial-write (Track B: B1+B2, B3). Reuses existing
  derivation + the R3 send-buffer condition. **Medium.**
- **Tier 2 — parity polish (this item, later phases).** Linux-style larger
  static defaults (`tcp_rmem` / `tcp_wmem`-ish); the 2× doubling +
  `tcp_adv_win_scale` overhead reservation; the sysctl set
  (`tcp_rmem`/`tcp_wmem`/`rmem_max`/`wmem_max`/`rmem_default`/`wmem_default`/
  `tcp_window_scaling`/`tcp_adv_win_scale` via the `sysctl_knob` skill);
  `SO_{SND,RCV}BUFFORCE`; `SOCK_{SND,RCV}BUF_LOCK` (an explicit `SO_*BUF`
  disables auto-tuning for that direction — only meaningful once Tier 3
  exists); `getsockopt` doubled-value parity. **Medium.**
- **Tier 3 — auto-tuning (SEPARATE backlog item, large).** Send-buffer
  autotuning (`sk_stream_moderate_sndbuf` / `tcp_sndbuf_expand` — grow
  `sndbuf` with cwnd) and, the dominant cost, receive-buffer **Dynamic
  Right-Sizing** (`tcp_moderate_rcvbuf` / `tcp_rcv_space_adjust` — BDP
  estimation via RTT + receive rate, an `rcv_space` struct, the grow
  algorithm). This is what Linux does *by default*, so strict host parity
  eventually needs it, but it is a genuine feature on its own (1–2+ weeks,
  DRS being most of it). Tracked separately in
  `host_refinements_backlog.md`. **Large.**
- **Tier 4 — global memory-pressure accounting (`tcp_mem`) — NON-GOAL.**
  Linux shrinks per-socket buffers under global TCP memory pressure
  (`sk_memory_allocated`, pressure states). This exists to protect *kernel*
  memory, which a userspace stack does not own the way the kernel does;
  documented as out of scope regardless of phase.
