# Host-stack refinements backlog (post-3.0.8 optional items)

| Field      | Value                                                                 |
|------------|-----------------------------------------------------------------------|
| Status     | **IN PROGRESS** — 2 of N shipped. Opened 2026-07-19 on `PyTCP_3_0_8`. |
| Branch     | `PyTCP_3_0_8`                                                          |
| Scope      | Optional host-scope refinements deferred out of the 3.0.8 cut. **None are host-conformance gaps** — 3.0.8 is host-feature-complete. These are polish / Linux-parity completeness. |
| Rule       | Every item is **tests-first (red tests before implementation)**, `make lint` clean, adherence + docs in lockstep. See `.claude/rules/feature_implementation.md`. |

This is the working backlog for the "do refinements one by one" track.
Items are ordered by ascending prerequisite-weight, not value. Pick the
next unchecked item, write the failing test(s) first, implement the
minimal change, verify, commit (one concern per commit), hold pushes
until the user says "push".

---

## Shipped (this track)

- [x] **UDP `SO_RCVBUF` enforcement** — commit `d51abda9`. `process_udp_packet`
  drops an inbound datagram whose payload would push the queued receive
  bytes past the cap (Linux `sk_rcvqueues_full`), enforced only when
  `SO_RCVBUF` is set; unset stays unbounded. 3 unit tests in
  `test__runtime__socket__udp__socket.py::TestUdpSocketReceive`.
- [x] **RAW `SO_RCVBUF` enforcement** — commit `a0140806`. Same guard in
  `process_raw_packet` (`raw__data`). 2 unit tests in
  `test__runtime__socket__raw__socket.py::TestRawSocketRcvbuf`.
- [x] **Ping `SO_RCVBUF` enforcement (R1)** — `PingSocket.setsockopt` now
  routes `SOL_SOCKET` options to the base `_sol_socket_setsockopt`, and
  `process_echo_reply` enforces the same guard (`icmp__data`). New unit-test
  file `test__runtime__socket__ping__socket.py::TestPingSocketRcvbuf`
  (setsockopt-sets-cap + over-cap-drop + unset-unbounded). Closes the
  SO_RCVBUF symmetry across all three datagram sockets.
- [x] **`pytcp address -j` JSON output (R5)** — new `format_addr_json`
  formatter (cli__format.py) mirroring the `ip -j addr show` object shape
  (`ifindex` / `ifname` / `flags` / `mtu` / `address` + per-address
  `addr_info` with `family` / `local` / `prefixlen`); `address` subcommand
  gained a `-j`/`--json` flag routed through `_cmd_address`. Unit tests:
  `test__cli__format.py::TestCliFormatInterfaces` (formatter shape + null
  MAC) + `test__cli__stack.py::TestCliAddressJson` (flag dispatch).
- [x] **`ss` / `route` / `neighbor` `-j` JSON output (R5 follow-on)** —
  `format_socket_table_json` / `format_route_table_json` /
  `format_neighbor_table_json` formatters (cli__format.py) mirroring the
  `ss -j` / `ip -j route` / `ip -j neighbor` object shapes; each command
  gained a `-j`/`--json` flag that gathers snapshots across the selected
  families into one flat JSON array (family inferred/carried per entry).
  Unit tests: `test__cli__format.py` (three formatter-shape tests) +
  `test__cli__stack.py::TestCliObservationJson` (flag dispatch for all
  three). Full JSON parity across the observation commands is now closed.
- [x] **`mld.version` force knob (R10, knob part)** — new
  `MLD__FORCE_VERSION` in `protocols/icmp6/mld__constants.py`, registered
  as the `mld.version` sysctl (range 0-2, 0 = auto fallback / 1 / 2 = pin
  MLDv1/MLDv2), consumed by `_mld_host_compatibility_mode` via qualified
  module access. The IPv6 analogue of the shipped `igmp.version` knob /
  Linux `force_igmp_version`. Integration tests:
  `test__icmp6__mld1_compat.py::TestIcmp6MldForcedVersion`. Adherence:
  `rfc2710__mld_v1`. (R10's RFC 2710 §4 Report-suppression part remains —
  optimization only.)
- [x] **RFC 6724 policy-table override (R11)** — `set_policy_table` /
  `reset_policy_table` / `get_policy_table` on
  `protocols/ip6/ip6__policy_table.py` — the PyTCP analogue of Linux
  `ip addrlabel` (a dedicated control API, not a scalar sysctl, since a
  whole table is not a scalar). `lookup` reads the active table live
  (copy-on-write reference swap, lock-free under free-threading) so the
  §5 rule-6 selector picks up an override without a restart;
  `set_policy_table` rejects a table with no ::/0 catch-all so `lookup`
  stays total. Unit tests:
  `test__ip6__policy_table.py::TestIp6PolicyTableOverride`. Adherence:
  `rfc6724__default_address_selection` (§2.1 / §10.3 flipped to met,
  stale `lib/` paths corrected). Phase-3 note: daemon-IPC exposure of
  this control surface is a follow-on (in-process only today).
- [x] **DF-guarded PLPMTUD probe (R7)** — turned out already-satisfied:
  the TCP probe reuses `_phtx_tcp`, which sets `ip4__flag_df=True`
  unconditionally, so the probe already carries DF=1 (RFC 8899 §3 #2).
  Added `test__tcp__plpmtud__probe_emit__sets_df_bit` to lock it in and
  flipped the stale "TCP probe path deferred (Phase 3c)" rows in
  `rfc8899__dplpmtud` + `rfc4821__plpmtud` adherence records to met. No
  production change required.
- [x] **IPv6 SSM handler core (R4 P3)** — the `mc6_*` reception-state
  machinery on the packet handler, a faithful mirror of the fully-evolved
  IGMPv3 v4 core: `_Ip6GroupMembership`, `_ip6_multicast_filters` (now the
  per-interface source of truth, with `_ip6_multicast` a derived read-only
  property), `_ip6_multicast_refs`, `_ip6_multicast_filter_for`, and
  `mc6_is_joined` / `_mc6_recompute` / `mc6_ref_acquire` / `mc6_ref_release`
  / `mc6_set_socket_filter` / `mc6_clear_socket_filter`. The IPv6 multicast
  reception state moved from `_lock__addr_config` to `_lock__multicast`
  (one lock domain, matching v4); `L2/L3.assign/remove_ip6_multicast`
  materialize the filter map there. Behaviour-preserving (every P3
  contributor is EXCLUDE{} any-source; the `_mc6_recompute` mid-delta
  branch is a `# P4:` placeholder). Tests-first:
  `test__icmp6__mld__source_filter_model.py` (7 wire-driven model tests) +
  harness / thread-safety / ND-seed updates. RFC 3810 §4.2/§5.2 adherence
  flip waits for P4/P5. See the R4 section for the remaining P4/P5 map.
- [x] **IPv6 SSM socket surface (R4 P2)** — the socket-side source-filter
  API, in two commits. `stack/membership6.py` (`Membership6Api`, the MLDv2
  analogue of `MembershipApi`) registered as `stack.membership6`;
  `IPV6_JOIN_GROUP` / `IPV6_LEAVE_GROUP` migrated onto it with per-socket
  `_ip6_source_filters` refcounting (fixes the leave-removes-for-all bug)
  + close-time release; and the protocol-independent
  `MCAST_JOIN_SOURCE_GROUP` / `MCAST_LEAVE_SOURCE_GROUP` /
  `MCAST_BLOCK_SOURCE` / `MCAST_UNBLOCK_SOURCE` family (`McastOption` enum +
  bare aliases, `group_source_req` parser, `_apply_ip6_source_op`). There
  is NO `IPV6_ADD_SOURCE_MEMBERSHIP` — Linux uses the `MCAST_*` family for
  IPv6 SSM. Tests: `test__socket__ipv6_source_membership.py` (11) +
  `test__icmp6__mld__membership6_api.py` (8) + the join_group refcount /
  close tests. P4 (MLDv2 source records on the wire) + P5 (RX source-
  delivery gate) remain before the §4.2/§5.2 adherence flip.
- [x] **IPv6 SSM state-change records (R4 P4a)** — MLDv2 source-bearing
  state-change Reports on TX. New `_send_mld_state_change` /
  `_mld_state_change_records` / `_emit_mld2_report` (the RFC 3810 §6.1
  difference table + MLDv1 coarse fallback), wired to the join / leave /
  mid-delta edges (a source-specific join now emits ALLOW_NEW_SOURCES /
  BLOCK_OLD_SOURCES / CHANGE_TO_* with the real source list instead of the
  coarse all-groups report); the dead coarse `_send_icmp6_mld_leave` was
  removed. Single immediate emission — the §6.1 robustness retransmit train
  is P4b. Tests: `test__icmp6__mld__source_state_change.py` (7). RFC 3810
  §4.2/§5.2 adherence flip waits for P4b + P5.
- [x] **IPv6 SSM robustness retransmit train (R4 P4b)** — the RFC 3810 §6.1
  state-change retransmit machine. `_send_mld_state_change` now schedules
  RV-1 retransmits (`_MldPendingChange` + `_mld_state_change__pending` +
  `_arm`/`_fire`/`_cancel_mld_state_change_retransmit(s)`, mirroring the v4
  IGMP train) at random(1, `mld.unsolicited_report_interval`] via
  `stack.timer`, re-arming per fire; a compat-mode change (MLDv1 Query)
  cancels the train. Added three MLD policy sysctls (`mld.robustness` /
  `mld.unsolicited_report_interval` / `mld.query_interval`), folding the
  hardcoded `MLD__ROBUSTNESS_VARIABLE` / `MLD__QUERY_INTERVAL__MS` locals
  in `packet_handler__icmp6__rx.py` into the sysctl-backed `mld__constants`
  (on-touch migration). Tests: 3 retransmit tests. P5 (RX source-delivery
  gate) is the last piece before the §4.2/§5.2 adherence flip.
- [x] **IPv6 SSM data-plane source gate (R4 P5) — R4 DONE** — the RFC 3810
  §4.1 receive-side source filter. `Socket.ip6_multicast_source_admits`
  (mirror of the v4 gate) + the shared UDP RX gate extended for IPv6 + the
  IPv6 RAW RX delivery gate; both bump the existing
  `udp/raw__multicast_source_filtered__drop` counters. Fixed a RawSocket
  `setsockopt` bug that gated IPPROTO_IPV6 dispatch on `isinstance(value,
  int)`, blocking the bytes-valued membership options. Tests:
  `test__icmp6__mld__source_data_filter{,__raw}.py` (6). RFC 3810
  §4.1/§4.2/§5.1/§6 adherence flipped to met in lockstep. **R4 (IPv6 SSM)
  is complete — full listener-role parity with the IGMPv3 track.**

**The canonical SO_RCVBUF guard pattern** (mirror for any new datagram socket):

```python
with self._lock__io:
    if self._closed:
        return
    if self._so_rcvbuf is not None:
        queued = sum(len(md.<data_attr>) for md in self._packet_rx_md)
        if queued + len(packet_rx_md.<data_attr>) > self._so_rcvbuf:
            __debug__ and log("socket", f"...Dropped: SO_RCVBUF {self._so_rcvbuf} exceeded")
            return
    self._packet_rx_md.append(packet_rx_md)
    self._packet_rx_md_ready.release()
self._signal_readable()
```

`_so_rcvbuf` lives on the base `socket` (runtime/socket/__init__.py, set by
`_sol_socket_setsockopt`). Enforce-only-when-set = zero regression risk.

---

## Remaining items

### R1 — Ping socket `SO_RCVBUF` — SHIPPED (see "Shipped" above)

### R2 — `setsockopt`-honored + errno-exactness sweep (medium, incremental)

- **Why:** several options are accepted-and-stored but not enforced, and
  some error paths don't match Linux errno exactly. This is the "make every
  setsockopt actually bite" item.
- **Approach:** audit each `case` in the setsockopt handlers in
  `runtime/socket/__init__.py` (`_sol_socket_setsockopt`,
  `_ipproto_ip_setsockopt`, `_ipproto_ipv6_setsockopt`) plus the per-flavour
  overrides (udp/raw/ping). For each option ask: is it read anywhere? If
  stored-only, either wire it or document why it's inert. Also verify
  `ENOPROTOOPT` / `EINVAL` / `ENOTCONN` are raised where Linux raises them.
- **Tests-first:** one red test per option-that-should-bite-but-doesn't,
  asserting the behavioural effect (not just the stored value). This is a
  series of small red-tests-first commits — good "one by one" cadence.
- **Known members of this bucket:** `SO_SNDBUF` (see R3), `SO_SNDTIMEO`
  (see R3), `X3` listen()-on-unbound (DONE — shipped as Linux-parity
  auto-bind, not the originally-planned `EINVAL`; see the R3 section).
- **Effort:** open-ended (do a few per session). **Risk:** low per fix.
- **Audit (done):** swept every stored setsockopt attribute for a data-path
  read. Result: almost everything is HONORED. The only strictly-DEAD
  accepted options are `SO_SNDBUF` / `SO_SNDTIMEO` (both deferred to R3 — they
  need the TX-completion signal). Partial-honor gaps noted for later: `SO_BROADCAST`
  gates only limited-broadcast on UDP (not directed/subnet, not RAW/PING);
  `SO_RCVBUF` unread on TCP; `IP_OPTIONS` emitted only on the UDP TX path.
  Multicast TX-shaping options (`IP_MULTICAST_TTL/LOOP/IF`,
  `IPV6_MULTICAST_HOPS/LOOP/IF`) are not accepted at all (ENOPROTOOPT) — a
  distinct "not-implemented" bucket, not "stored-and-ignored".
- **Shipped:** IPv6 outbound multicast default Hop-Limit was 64 (leaked past
  the local link) — asymmetric with the IPv4 side, which already defaults
  multicast to TTL=1. Fixed `packet_handler__ip6__tx.py` to default
  multicast destinations to Hop-Limit=1 (Linux `IPV6_DEFAULT_MCASTHOPS`),
  the None-hop path only; explicit `ip6__hop` still wins and ND/MLD/RA keep
  their protocol-mandated values. Tests: `TestIp6TxMulticastHopLimit` (3) in
  `test__ip6__tx.py`; the Ethernet-TX multicast golden updated 64→1.
- **Shipped:** the `SO_BROADCAST` gate on UDP only caught the limited
  broadcast `255.255.255.255`; Linux also requires the flag for a
  subnet-directed broadcast (`RTN_BROADCAST`). Added a read-only
  `stack.is_ip4_broadcast(dst)` introspection helper (limited broadcast +
  each interface's directed-broadcast set via the public `ip4_broadcast`
  accessor) and switched both UDP send/sendto gate sites to it, so a send
  to `10.0.1.255`-style directed broadcast without `SO_BROADCAST` now
  raises `EACCES`. Tests: `TestSocketSoBroadcastGateDirected` (3).
- **Shipped:** extended the same `SO_BROADCAST` gate to RAW sockets (Linux
  `raw_sendmsg` gates raw broadcast identically). Both RAW `send` / `sendto`
  consult `stack.is_ip4_broadcast(dst)` after the route check, so a RAW send
  to a limited or subnet-directed broadcast without `SO_BROADCAST` raises
  `EACCES`. Tests: `TestSocketSoBroadcastGateRaw` (4: limited-drop,
  directed-drop, with-flag-succeeds, unicast-regression).
- **Shipped:** extended the gate to PING (ICMP-Echo) sockets — a broadcast
  Echo Request is the classic amplification ('smurf') vector, so this is
  arguably the most important flavour to guard. `PingSocket._send_echo`
  (the shared `send`/`sendto` body) now consults
  `stack.is_ip4_broadcast(dst)` after the route check; a broadcast ping
  without `SO_BROADCAST` raises `EACCES`, matching the `ping -b` convention.
  Tests: `TestSocketSoBroadcastGatePing` (4). **The `SO_BROADCAST`
  broadcast-send gate is now uniform across all datagram flavours (UDP /
  RAW / PING).** TCP cannot send to a broadcast (connection-oriented), so
  the sweep is complete.
- **Shipped (multicast hop-count, part 1/2 — de-conflation):** `IP_TTL` /
  `IPV6_UNICAST_HOPS` were bleeding into multicast sends — a socket that set
  the unicast TTL override had it applied to multicast datagrams too, unlike
  Linux which keeps `inet->uc_ttl` / `np->hop_limit` (unicast) separate from
  `inet->mc_ttl` / `np->mcast_hops` (multicast). Made `_effective_ip_ttl`
  destination-aware: it returns the unicast override only for a unicast
  destination; a multicast destination falls to the handler's multicast
  default (Hop-Limit / TTL = 1). Threaded the destination through all seven
  call sites (UDP send/sendto, RAW send/sendto ×2 families, TCP TX — TCP is
  always unicast). Tests: `TestSocketUnicastHopDoesNotBleedIntoMulticast`
  (4). Part 2 adds the `IP_MULTICAST_TTL` / `IPV6_MULTICAST_HOPS` knobs so a
  sender can *raise* the multicast hop count.
- **Shipped (multicast hop-count, part 2/2 — the knobs):** added
  `IP_MULTICAST_TTL` (33) and `IPV6_MULTICAST_HOPS` (18) as accepted /
  stored / honored socket options (enum members + bare aliases + public
  re-exports). setsockopt accepts -1..255 (−1 resets to the default;
  out-of-range → `EINVAL`); getsockopt reports the value or the Linux
  default of 1. `_effective_ip_ttl` now returns the multicast override for
  a multicast destination, so a sender can raise the multicast Hop-Limit
  above 1 independently of the unicast knob. A value of 0 is RFC 1112 §6.1
  host scope — since PyTCP has no local multicast loopback, the send is
  accepted (byte count returned) but no frame is emitted, gated by a new
  `_multicast_send_suppressed` helper at the UDP / RAW send sites. Tests:
  `TestSocketMulticastHopOverride` (8). **The multicast hop-count item is
  complete.**
- **Shipped:** `IP_MULTICAST_LOOP` (34) / `IPV6_MULTICAST_LOOP` (19) now
  accepted + stored + getsockopt (default 1), rather than `ENOPROTOOPT`.
  Linux never rejects these, and portable multicast senders set them
  routinely; accepting closes that parity gap. Behaviourally a near-no-op:
  PyTCP has no local multicast loopback, so a sender never receives its own
  multicast — the common `LOOP=0` (do-not-echo) intent is honoured, `LOOP=1`
  is a documented no-op. Tests: `TestUdpSocketMulticastLoop` (5).
- **R2 close-out — remaining items scoped to their proper track (not R2
  sweep fixes):**
  - `IP_MULTICAST_IF` / `IPV6_MULTICAST_IF` — honouring these *is*
    multi-interface multicast egress selection, a **Phase-2** feature. On a
    single-homed Phase-1 host the sole interface is always the egress, so
    the option carries no Phase-1 semantics worth faking with an inert
    address/ifindex store. Deferred to Phase-2 (multicast egress-by-oif).
  - `SO_RCVBUF` on TCP — Linux derives the advertised receive window from
    it; that is receive-window / buffer-accounting work on the TCP path,
    tracked with **R3** (`SO_SNDBUF` / `SO_SNDTIMEO`), not a setsockopt
    sweep fix. Honoured today for UDP / RAW / PING RX drop-cap.
  - `IP_OPTIONS` on RAW TX — the last true "stored-but-not-honoured" R2 gap.
    **Fixed:** `send_ip4_packet` (and its base-handler delegator) gained an
    `ip4__options` parameter; RAW `send` / `sendto` now pass
    `_effective_ip4_options()`, so an IP_OPTIONS block set on a raw IPv4
    socket is emitted on the wire (hlen bumped, options round-trip),
    matching the UDP path. Tests: `TestSocketRawIpOptions` (2).
- **R2 STATUS — CLOSED.** Its last non-Phase-2 dependency, `SO_RCVBUF`
  on TCP, shipped with the 3.0.8 buffer-accounting work (`SO_RCVBUF`
  seeds `WindowState.rcv_wnd_max` and Dynamic Right-Sizing grows it), so
  nothing R2-scoped remains. Every accepted setsockopt option
  is now either honoured or documented-inert; the remaining true gaps are
  scoped to their proper track: `IP_MULTICAST_IF`/`_IF6` → Phase-2 (egress
  selection), `SO_RCVBUF`-on-TCP → R3 (receive-window), `SO_SNDBUF` /
  `SO_SNDTIMEO` → R3 (send buffer accounting; DONE), and `X3`
  listen()-on-unbound (DONE — Linux-parity auto-bind, see R3).

### R3 — `SO_SNDBUF` accounting + `SO_SNDTIMEO` (UDP) — DONE

- **Shipped:** per-socket UDP send-buffer accounting (Linux
  `sk_wmem_alloc`). Built the missing TX-completion signal: an
  `on_complete` callback threaded through `send_udp_packet` →
  `_marshal_tx_async` → `TxRing.dispatch_async` → `_TxRequest`, fired once
  in the request's `finally` (survives a raising pipeline, a queue-full
  frame drop, and the inline no-worker fallback). The socket charges
  `len(data)` to a `_snd_outstanding` counter before queueing and releases
  it from the hook; a `threading.Condition` guards the counter and wakes a
  blocked sender. `_charge_sndbuf` bounds the charge by `SO_SNDBUF`
  (`_effective_sndbuf`: the set value, else the
  `SOCKET__SO_SNDBUF__DEFAULT` = 212992 `net.core.wmem_default` stand-in;
  no Linux 2× doubling). Over-buffer behaviour: a single datagram always
  sends when nothing is outstanding; otherwise a non-blocking socket raises
  `EAGAIN`, a blocking socket waits on the condition up to `SO_SNDTIMEO`
  then raises `EAGAIN`. `close()` resets the counter and wakes waiters.
- **Tests:** `TestTxRingOnCompleteHook` (3 — hook fires once, on raise, on
  inline), `TestUdpSocketSoSndbuf` (5 — non-blocking EAGAIN, lone oversize
  allowed, completion-hook release, blocking SO_SNDTIMEO EAGAIN, default
  never blocks). Harness `dispatch_async` mock updated to fire `on_complete`
  (mirrors production).
- **Shipped (RAW / PING extension):** the same accounting now covers RAW
  and PING. RAW send is fire-and-forget like UDP, so `send_ip4_packet` /
  `send_ip6_packet` (+ their base delegators) gained the `on_complete`
  release hook and `RawSocket.send` / `sendto` charge / release exactly as
  UDP does. PING's ICMP send path is **synchronous** (blocking
  `_marshal_tx`), so `PingSocket._send_echo` charges before the send and
  releases in a `finally` — the charge is held only for the send's
  duration, so it never accumulates for a single sender and only bounds
  concurrent senders sharing one socket. `SO_SNDBUF` is now uniform across
  all three datagram flavours. Tests: `TestRawSocketSoSndbuf` (2 —
  non-blocking EAGAIN, completion-hook release), `TestPingSocketSoSndbuf`
  (1 — charged-during / released-after balance).
- **Shipped (sub-second timeout via setsockopt):** `SO_RCVTIMEO` /
  `SO_SNDTIMEO` now accept and report a sub-second **float** value via
  `setsockopt` / `getsockopt`, matching PyTCP's documented "float seconds"
  surface. Previously the SOL_SOCKET dispatch int-guard rejected a float
  and getsockopt `int()`-truncated the stored value. The setsockopt `value`
  widened to `int | float | bytes`; a float is routed first to
  `_sol_socket_setsockopt` (the only float-valid path) so the int / bytes
  option handlers never receive one; getsockopt returns the float verbatim.
  Tests: `TestUdpSocketTimeoutFloat` (3 — float `SO_RCVTIMEO` / `SO_SNDTIMEO`
  round-trip + integer-still-accepted regression). This makes the R3
  blocking-send `SO_SNDTIMEO` fully usable at sub-second granularity via
  the public API.
- **Shipped (X3 — listen() on an unbound socket):** the backlog originally
  planned `EINVAL` here, but that **contradicts Linux**, which auto-binds an
  unbound TCP socket to an ephemeral port on `listen()`
  (`inet_csk_listen_start` → `get_port`). Per the Linux-parity north star we
  shipped the auto-bind: `TcpSocket.listen()` on a socket with no prior
  `bind()` now picks an ephemeral port (`pick_local_port`) and registers the
  listener, instead of building the previously-broken port-0 listener. Not a
  breaking change (the examples already bind first), so no `examples/` update
  was needed. Tests: `test__tcp_socket__listen_unbound_autobinds_ephemeral_port`
  + `test__tcp_socket__listen_bound_keeps_port_and_does_not_repick`.
- **Tier-1 DONE — TCP `SO_SNDBUF` / `SO_RCVBUF` buffer accounting.** Scoped
  in `docs/refactor/tcp_buffer_accounting.md` (Tracks A / B, phased). TCP has
  its own buffering model — the send buffer is the retransmit queue (released
  on ACK, not wire-write), and `RCV.WND` is already buffer-derived — so this
  is a distinct feature from the datagram counter, not a fold-in. **Track A
  (SO_RCVBUF → advertised receive window, A1–A3) and Track B (SO_SNDBUF →
  send-buffer backpressure with partial-write, B1–B3) have shipped**
  (`test__tcp__session__so_rcvbuf.py`, `test__tcp__session__so_sndbuf.py`).
  **Tier-2** parity polish (Linux-style larger static defaults, 2× doubling,
  the `tcp_rmem`/`tcp_wmem` sysctl set, `SO_*BUFFORCE`) remains, per
  `tcp_buffer_accounting.md` §7.

### R-autotune — TCP send/receive buffer auto-tuning (Tier 3, large, separate)

- **Split out of the `SO_SNDBUF`/`SO_RCVBUF` item** (see
  `docs/refactor/tcp_buffer_accounting.md` §7). Linux auto-tunes both buffers
  by default: send-buffer autotuning (`sk_stream_moderate_sndbuf` /
  `tcp_sndbuf_expand`, grows `sndbuf` with cwnd) and receive-buffer **Dynamic
  Right-Sizing** (`tcp_moderate_rcvbuf` / `tcp_rcv_space_adjust` — BDP
  estimation via RTT + receive rate, an `rcv_space` struct, the grow
  algorithm). Strict host parity eventually needs it, but DRS alone is a
  genuine feature (1–2+ weeks). Deferred to its own track; not required for
  the `SO_*BUF` options to work. **Global memory-pressure accounting
  (`tcp_mem`) is a documented non-goal** (kernel-memory management a
  userspace stack does not own).
- **Full implementation plan scoped:** `docs/refactor/tcp_buffer_autotuning.md`
  — Track R (receive DRS: R1 receiver-RTT estimator → R2 `RcvSpaceState` →
  R3 trigger → R4 grow policy) and Track S (send auto-tuning: S1 auto bound →
  S2 expand policy), both actuators reusing the shipped Tier-1 primitives
  (`grow_rcv_wnd_max`, the `_effective_sndbuf()` gate). Registers the Tier-2
  `tcp.rmem`/`tcp.wmem` triples + `tcp.moderate_rcvbuf`; the load-bearing
  decision is pairing Track S with a small initial send default (§2/§7). No
  code yet.

### R4 — IPv6 per-socket source filters = MLDv2 SSM track — DONE (P1-P5 shipped)

- **Why:** IPv6 has only any-source `IPV6_JOIN_GROUP` / `IPV6_LEAVE_GROUP`
  (handled at runtime/socket/__init__.py ~1029). IPv4 has the full
  source-specific set. This is the **IPv6 analogue of the shipped IGMPv3
  SSM feature** — see `docs/refactor/igmp_source_specific_multicast.md`
  (Phases 1–5) as the exact template.
- **The IPv4 machinery to mirror:**
  - `packages/pytcp/pytcp/lib/ip4_multicast_filter.py` —
    `Ip4MulticastFilter` (INCLUDE/EXCLUDE mode + source set + `merge`).
  - `_ip4_multicast_filters: dict[Ip4Address, Ip4MulticastFilter]` on the
    packet handler (runtime/packet_handler/__init__.py ~324); the merged
    §3.2 reception filter via `_ip4_multicast_filter_for`.
  - setsockopt opts at runtime/socket/__init__.py ~783–957:
    `IP_ADD_SOURCE_MEMBERSHIP` / `IP_DROP_SOURCE_MEMBERSHIP` /
    `IP_BLOCK_SOURCE` / `IP_UNBLOCK_SOURCE`.
  - IGMPv3 state-change source records (ALLOW_NEW_SOURCES /
    BLOCK_OLD_SOURCES / the CHANGE_TO_* forms) in the IGMP TX handler.
  - RX source-delivery filter `ip_mc_sf_allow` (`Ip4MulticastFilter.allows`)
    gating per-socket delivery for **UDP and RAW** (RAW needed the
    `RawMetadata.socket_ids` wildcard-combo enumeration — mirror for v6).
- **The IPv6 side to build (Phases mirroring the IGMP track):**
  - **P1 — SHIPPED (commit `d2054fe8`):**
    `packages/pytcp/pytcp/lib/ip6_multicast_filter.py` (`Ip6MulticastFilter`
    + `Ip6MulticastFilterMode`, a straight `Ip6Address` copy of the v4
    value type: `has_reception`, `allows`, RFC 3810 §4.2 `merge`). 18 unit
    tests in `test__lib__ip6_multicast_filter.py`.
  - **Architectural note for P2-P3:** the existing `stack/membership.py`
    `MembershipApi` is entirely IPv4 (`Ip4Address` / `ip4_multicast` /
    `set_socket_filter` → the handler's `_ip4_multicast_filters`). The IPv6
    side needs a parallel v6 membership surface (mirror, not genericize —
    v4/v6 multicast are already separate paths in the handler and the
    MLD/IGMP TX). P3's `_ip6_multicast_filters` dict + merge live on the
    handler next to the v4 ones.
  - **P2 — SHIPPED:** the socket-side source-filter surface + IPv6
    membership API, in two commits. (1) `stack/membership6.py`
    (`Membership6Api`, the MLDv2 analogue of `MembershipApi`: join / leave
    / set_socket_filter / clear_socket_filter / list_memberships →
    `mc6_*`; ff02::1 leave-refusal; no group-count cap — Linux has no IPv6
    `igmp_max_memberships`), registered as `stack.membership6`. The
    `IPV6_JOIN_GROUP` / `IPV6_LEAVE_GROUP` path migrated onto it with
    per-socket `_ip6_source_filters` refcounting (EXCLUDE{} any-source),
    fixing the documented leave-removes-for-all bug; close/GC releases
    held memberships (`_release_ip6_memberships`). (2) the
    protocol-independent `MCAST_JOIN_SOURCE_GROUP` /
    `MCAST_LEAVE_SOURCE_GROUP` / `MCAST_BLOCK_SOURCE` /
    `MCAST_UNBLOCK_SOURCE` family as a `McastOption` IntEnum + bare aliases
    (enums.md §2.2; re-exported from `pytcp.socket`), with a
    `group_source_req` parser (`_parse_group_source_req`, ss_family ==
    AF_INET6 = 10) and `_apply_ip6_source_op` (the INCLUDE/EXCLUDE
    mode-conflict + EADDRNOTAVAIL errno surface mirroring the v4
    `_apply_source_op`). There is NO `IPV6_ADD_SOURCE_MEMBERSHIP` — Linux
    uses the protocol-independent `MCAST_*` family for IPv6 SSM.
    Tests-first: `test__socket__ipv6_source_membership.py` (11) +
    `test__icmp6__mld__membership6_api.py` (8) + the refcount / close tests
    in `test__socket__ipv6_join_group.py`.
  - **P3 — SHIPPED:** the handler `mc6_*` reception-state core, a
    faithful mirror of the fully-evolved v4 machinery. Added
    `_Ip6GroupMembership`, the `_ip6_multicast_filters` dict as the
    per-interface reception source of truth (with `_ip6_multicast` now a
    derived read-only property over its keys), `_ip6_multicast_refs`,
    `_ip6_multicast_filter_for`, and the six `mc6_*` methods
    (`mc6_is_joined` / `_mc6_recompute` / `mc6_ref_acquire` /
    `mc6_ref_release` / `mc6_set_socket_filter` /
    `mc6_clear_socket_filter`). The IPv6 multicast reception state moved
    from `_lock__addr_config` to `_lock__multicast` (matching v4, one lock
    domain), so `L2/L3.assign/remove_ip6_multicast` now materialize the
    filter map under `_lock__multicast` and the address-config callers
    take `_lock__addr_config` THEN `_lock__multicast`. Behaviour-preserving
    (every P3 contributor is still EXCLUDE{} any-source, so the same MLD
    Reports fire); the `_mc6_recompute` mid-membership filter-delta branch
    is a P4 placeholder (current-state Report, marked `# P4:`). Tests-first:
    `test__icmp6__mld__source_filter_model.py` (7 wire-driven model tests)
    + the harness / thread-safety / ND-seed test updates. The RFC 3810
    §4.2 / §5.2 source-record adherence flip waits for P4/P5 (as the v4
    §3.2 flip waited for Phase 5).
  - **P4a — SHIPPED:** MLDv2 source-bearing state-change records on TX.
    Added `_send_mld_state_change(group, old, new)` + `_mld_state_change_records`
    (the §6.1 difference table: mode change → CHANGE_TO_INCLUDE /
    CHANGE_TO_EXCLUDE with the new source list; within-mode source change →
    ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES) + `_emit_mld2_report`, with the
    MLDv1 coarse Report/Done fallback. Wired the three edges: the
    `assign_ip6_multicast` join edge (`old=NONMEMBER, new`), the
    `remove_ip6_multicast` leave edge (`old, new=NONMEMBER`), and the
    `_mc6_recompute` mid-delta (replacing the `# P4:` placeholder). The now-
    dead coarse `_send_icmp6_mld_leave` (single) was removed. Single
    immediate emission — the RFC 3810 §6.1 robustness retransmit train is
    **P4b** (mirror the v4 `_igmp_state_change__pending` /
    `_arm`/`_fire`/`_cancel` machinery). Tests-first:
    `test__icmp6__mld__source_state_change.py` (7) — ALLOW / BLOCK / TO_EX /
    TO_IN records with source lists, mirroring the v4 track.
  - **P4b — SHIPPED:** the §6.1 robustness retransmit-train state machine.
    Added `_MldPendingChange` + `_mld_state_change__pending` /
    `_mld_state_change__handle` on the ICMPv6 TX handler and
    `_arm`/`_fire`/`_cancel_mld_state_change_retransmit(s)` mirroring the v4
    IGMP machinery: `_send_mld_state_change` now schedules RV-1 retransmits
    at random(1, `mld.unsolicited_report_interval`] via `stack.timer`, the
    ticket re-arms per fire, and a compat-mode change (MLDv1 Query) cancels
    the train (wired into `_mld_arm_v1_compatibility`). Three new MLD
    policy sysctls (`mld.robustness` / `mld.unsolicited_report_interval` /
    `mld.query_interval`); the on-touch migration folded the hardcoded
    `MLD__ROBUSTNESS_VARIABLE` / `MLD__QUERY_INTERVAL__MS` locals out of
    `packet_handler__icmp6__rx.py` into the sysctl-backed `mld__constants`
    (qualified module access). Tests: 3 retransmit tests added to
    `test__icmp6__mld__source_state_change.py`.
  - **P5 — SHIPPED:** the §4.1 data-plane source-delivery gate. Added
    `Socket.ip6_multicast_source_admits` (reads `_ip6_source_filters`,
    mirror of `ip4_multicast_source_admits`), extended the shared UDP RX
    gate `__phrx_udp__multicast_source_allowed` for IPv6, and added the
    RAW gate to the IPv6 RX delivery loop
    (`packet_handler__ip6__rx.py`) — both bump the existing
    `udp/raw__multicast_source_filtered__drop` counters. Also fixed a
    RawSocket bug: `setsockopt` gated IPPROTO_IPV6 dispatch on
    `isinstance(value, int)`, blocking the bytes-valued membership
    options — removed (the IPPROTO_IP line had no such guard). Tests:
    `test__icmp6__mld__source_data_filter{,__raw}.py` (3 + 3). RFC 3810
    §4.1 / §4.2 / §5.1 / §6 adherence rows flipped to met in lockstep.
- **R4 — DONE** (P1-P5 shipped). Full IPv6 SSM listener parity with the
  IGMPv3 track.
- **Effort:** large (multi-phase, mirrors a whole shipped track). **Risk:**
  medium. **Value:** highest — real v4/v6 parity.

#### R4 — resumable implementation map (derived 2026-07-19 by reading the v4 machinery)

The v4 source-filter machinery to mirror, with exact locations, so P2-P5
can resume without re-deriving. **Status: P2 + P3 SHIPPED** — the handler
core (`_Ip6GroupMembership` / `_ip6_multicast_filters` / `_ip6_multicast_refs`
/ `mc6_*` / `_ip6_multicast_filter_for`, all under `_lock__multicast`) AND
the socket surface (`stack.membership6`, refcounted `IPV6_JOIN_GROUP`, the
`MCAST_*_SOURCE_*` family with `group_source_req`, per-socket
`_ip6_source_filters`, close-time release) are done. **P4a + P4b SHIPPED** — the
`_send_mld_state_change` source-bearing state-change records (ALLOW / BLOCK /
CHANGE_TO_*) fire on all three edges (join / leave / mid-delta) AND
retransmit RV-1 times per the §6.1 robustness train (`_MldPendingChange` +
`_arm`/`_fire`/`_cancel`, cancelled on a compat-mode change; three new
`mld.*` sysctls). **Remaining: P5** (RX `Ip6MulticastFilter.allows` source-
delivery gate for UDP + RAW). After P5 flip the RFC 3810 §4.2 / §5.2
adherence rows.

- **Handler (`runtime/packet_handler/__init__.py`) — the deep, no-GIL-locked
  core, duplicated across the L2 and L3 handler classes — SHIPPED (P3):**
  - `_Ip4GroupMembership` (line ~156): `operator: bool` + `socket_filters:
    dict[int, Ip4MulticastFilter]` + `contributors()`. Mirror as
    `_Ip6GroupMembership`.
  - handler attrs (line ~325/451): `_ip4_multicast_filters:
    dict[Ip4Address, Ip4MulticastFilter]` + `_ip4_multicast_refs:
    dict[Ip4Address, _Ip4GroupMembership]`. Mirror `_ip6_*`, init in the
    same `__init__`, snapshot/restore in the harness.
  - `mc_is_joined` / `_mc_recompute` / `mc_ref_acquire` / `mc_ref_release`
    / `mc_set_socket_filter` / `mc_clear_socket_filter` (lines ~863-980),
    all under `self._lock__multicast`. Mirror as `mc6_*`. `_mc_recompute`
    is the heart: merge contributors → reception edge calls
    `_assign_ip4_multicast` (join), loss calls `_remove_ip4_multicast`
    (leave), mid-membership filter delta calls `_send_igmp_state_change`.
  - `_ip4_multicast_filter_for` (line ~2586) + the filter-materializing
    `_assign_ip4_multicast` / `_remove_ip4_multicast` (L2 ~3785, L3 ~4014;
    note the v6 `assign_ip6_multicast`/`remove_ip6_multicast` at L2 ~3752 /
    L3 ~3976 are the ANY-SOURCE public path — the filtered path is a new
    private sibling). ff02::1 is the v6 permanent-group exemption (v4:
    224.0.0.1 `IP4__MULTICAST__ALL_SYSTEMS`).
- **Membership API (`stack/membership.py`, 232 lines, entirely v4):** build
  a parallel v6 surface (mirror, not genericize) — `join` / `leave` /
  `set_socket_filter` / `clear_socket_filter` / `list_memberships`
  delegating to the `mc6_*` handler methods. Cap via
  `igmp.max_memberships`'s v6 analogue (no separate MLD cap today — reuse
  or add `mld.max_memberships`).
- **Socket (`runtime/socket/__init__.py`):**
  - v4 opts at lines ~881-979 (`_ipproto_ip_source_membership` +
    `_apply_source_op`), 12-byte `ip_mreq_source`. For v6, Linux uses the
    **protocol-independent `MCAST_JOIN_SOURCE_GROUP`(46) /
    `MCAST_LEAVE_SOURCE_GROUP`(47) / `MCAST_BLOCK_SOURCE`(43) /
    `MCAST_UNBLOCK_SOURCE`(44)** at IPPROTO_IPV6 level with a
    `group_source_req` struct — there is NO `IPV6_ADD_SOURCE_MEMBERSHIP`.
    Add these as a `McastOption` IntEnum + bare aliases (enums.md §2.2).
  - `group_source_req` glibc layout (native): `gsr_interface` uint32 at
    offset 0; 4 bytes pad; `gsr_group` sockaddr_storage at offset 8
    (sockaddr_in6 → sin6_addr at +8, so group addr = bytes[16:32]);
    `gsr_source` sockaddr_storage at offset 136 (source addr =
    bytes[144:160]). Validate `ss_family == AF_INET6` (10 on Linux) in
    each sockaddr. Total 264 bytes.
  - Per-socket `_ip6_source_filters: dict[(ifindex, Ip6Address),
    Ip6MulticastFilter]` + a v6 `_apply_source_op` (mirror v4's INCLUDE/
    EXCLUDE mode-conflict + EADDRNOTAVAIL errno surface). Push to the v6
    membership API. Also migrate the existing simple `IPV6_JOIN_GROUP` /
    `IPV6_LEAVE_GROUP` path (line ~1029/1040, the non-refcounted
    `_ip6_memberships` set) onto the new API so per-socket refcounting is
    correct (the existing leave-removes-for-all bug the code comments flag).
  - Socket `close()` must `clear_socket_filter` every held v6 filter
    (mirror the v4 close path).
- **RX delivery (`Ip6MulticastFilter.allows`):** gate per-socket delivery
  in the IPv6 UDP + RAW RX paths (mirror the v4 `ip_mc_sf_allow` gate; RAW
  needed the `RawMetadata.socket_ids` wildcard-combo enumeration — check
  the v6 RAW metadata has the same).
- **Tests:** unit (value type — DONE P1; `_apply_source_op` v6 transitions;
  `group_source_req` parse) + integration (`tests/integration/protocols/
  icmp6/` — setsockopt drives the interface merge + emits the right MLDv2
  ALLOW/BLOCK/CHANGE_TO_* record on the wire; RX source-delivery gating for
  UDP + RAW). Mirror the shipped IGMP SSM tests under
  `tests/integration/protocols/igmp/`.
- **Safety note:** every `mc6_*` mutation runs under `_lock__multicast`
  (the no-GIL standing invariant); the L2/L3 duplication must stay in
  sync. This is the stack's most safety-critical machinery — do each phase
  tests-first and run the full multicast integration suite before commit.

### R5 — CLI polish: JSON output for `address` / `ss` / `route` / `neighbor` — SHIPPED (see "Shipped" above)

Full `-j`/`--json` parity across every observation command is now closed
(`address`, `ss`, `route`, `neighbor`). The mutation verbs and `sysctl`
stay text-only (Linux `sysctl` has no `-j` either).

### R6 — HyStart++ (RFC 9406) — SHIPPED (algorithm was already met; test surface strengthened)

- **Outcome:** the RFC 9406 §4.2/§4.3 algorithm was already fully
  implemented and met (per-round minRTT tracking, SS→CSS delay exit, CSS
  1/CSS_GROWTH_DIVISOR growth, CSS→SS resume, CSS_ROUNDS→CA exhaustion).
  The only non-met row is the §4.3 `L` parameter (n/a — PyTCP uses the
  standard L=1 slow-start cap). The adherence record's closing paragraph
  still read as if unimplemented (stale); it was corrected.
- **What shipped:** the integration-test surface was the real gap. Two of
  the five prior integration tests *cheated* — they pre-populated
  `hystart_state` and called `_hystart_check_phase_transition()` directly
  rather than driving real ACKs, and there was no wire-level test for CSS
  conservative growth or the CSS→CA exhaustion path. The rewritten
  `test__tcp__session__hystart.py` (7 tests) drives every transition
  **end-to-end through the wire ACK path**: fill the send pipe with real
  segments (TCP_NODELAY to defeat Nagle so the whole window goes out),
  stream RTT-bearing ACKs so each fold/transition runs through
  `_process_ack_packet`. New coverage: SS→CSS end-to-end, CSS
  conservative-growth rate comparison, CSS→CA exhaustion (ssthresh≤cwnd),
  CSS→SS resume (ssthresh unchanged). Adherence `rfc9406__hystart_pp`
  updated in lockstep.

### R7 — DF-guarded TCP PLPMTUD probe — SHIPPED (already-satisfied; test-locked)

- **Outcome:** the "residual" was documentation staleness, not a code gap.
  The probe is emitted through the same `_phtx_tcp` TX path as every other
  IPv4 TCP segment, which already sets `ip4__flag_df=True` unconditionally
  (RFC 1191 §3 / RFC 9293 §3.7.5) — so the probe already carries DF=1. IPv6
  probes carry no Fragment header (no source fragmentation on the TX path).
- **What shipped:** `test__tcp__plpmtud__probe_emit__sets_df_bit` locks in
  the DF=1 / MF=0 property on the emitted probe, and the stale
  "TCP probe path deferred (Phase 3c)" rows in
  `rfc8899__dplpmtud/adherence.md` + `rfc4821__plpmtud/adherence.md` were
  flipped to **met**. No production change was required.

### R8 — `IP_RECVERR` / `IPV6_RECVERR` error queue over the daemon boundary (medium)

- **Why:** the per-socket ICMP error queue + `recvmsg(MSG_ERRQUEUE)` works
  **in-process**, but the daemon data bridge does not pump the error queue
  across the AF_UNIX boundary, so a daemon-backed drop-in client cannot read
  ICMP errors via `MSG_ERRQUEUE`. Source: `kernel_userspace_separation.md`
  deferred list.
- **Scope:** extend the daemon IPC protocol so an `MSG_ERRQUEUE` `recvmsg`
  is serviced across the boundary (the in-process path already builds the
  `sock_extended_err` cmsg via `runtime/socket/error_queue.py`). Wire the
  error-queue drain into the daemon's per-socket bridge.
- **Tests-first:** integration test under `tests/integration/ipc/` driving
  an ICMP error to a daemon-backed UDP socket and asserting the client's
  `recvmsg(MSG_ERRQUEUE)` returns the `IP_RECVERR` cmsg.
- **Effort:** medium. **Risk:** medium (IPC protocol surface). **Value:**
  medium (completes the drop-in's error-reporting parity).

### R9 — Selectable / cancelable `accept` over the daemon (medium)

- **Why:** a client disconnecting mid-`accept` leaves the daemon dispatch
  thread polling until server stop (Phase-4 daemon limitation noted in
  `kernel_userspace_separation.md`).
- **Scope:** make the daemon-side accept wait cancelable (wake on client
  disconnect / a cancellation signal) so the dispatch thread doesn't spin.
- **Tests-first:** integration test — connect a client, issue accept, drop
  the client, assert the dispatch thread returns/cleans up promptly.
- **Effort:** medium. **Risk:** medium (threading/lifecycle). **Value:**
  medium (daemon robustness).

### R10 — MLDv1 Report suppression (small) — SHIPPED

- **`mld.version` force knob — SHIPPED (see "Shipped" above).** New
  `MLD__FORCE_VERSION` in `protocols/icmp6/mld__constants.py`, registered
  as the `mld.version` sysctl (range 0-2), consumed by
  `_mld_host_compatibility_mode`. Mirrors `igmp.version` /
  `IGMP__FORCE_VERSION`.
- **RFC 2710 §4 Report suppression — SHIPPED.** Inbound MLDv1 Reports
  (type 131) previously fell through to the unknown-type path; they now
  dispatch to `__phrx_icmp6__mld1_report`, which records the reported
  address in a per-interface `_mld1_report__suppressed` set when a Report
  of ours is pending in v1 compat mode. The emit path reads and clears
  that set under `_lock__multicast` (outside the TX call, per the
  membership-lock deadlock rule) and skips those groups. Scoped per
  address, per response window, and to MLDv1 mode only — MLDv2 removed
  suppression. New counters `icmp6__mld1_report` /
  `icmp6__mld1_report__suppressed`. Tests:
  `test__icmp6__mld1_report_suppression.py` (4). Adherence: RFC 2710 §4
  flipped deferred -> met.
- **R10 STATUS — CLOSED.**

### R11 — RFC 6724 policy-table override — SHIPPED (see "Shipped" above)

- Implemented as a small dedicated control API on
  `protocols/ip6/ip6__policy_table.py` (`set_policy_table` /
  `reset_policy_table` / `get_policy_table`) rather than a scalar sysctl —
  a whole precedence/label table is not a scalar, and Linux itself exposes
  it via `ip addrlabel` (netlink), not `/proc/sys`. Copy-on-write
  reference swap, read live by `lookup`.
- **Follow-on (deferred):** expose the control API over the daemon IPC
  boundary for Phase-3 (in-process only today), and the corresponding
  `pytcp` CLI verb. Low value; do on appetite.

### Ongoing hygiene (not a discrete scheduled item)

- **On-touch enum migrations** — bare `FOO: int = N` constants that represent
  one-of-a-set should become enum members on touch (see `.claude/rules/enums.md`
  §5). Not a dedicated commit; fix opportunistically when editing a file.

---

## Out of scope for this backlog (deliberately excluded)

These are **not** host-scope refinements and are tracked elsewhere; listed
so this backlog's boundary is explicit.

- **Consumer-blocked** (need a DNS resolver / DDNS / HTTP agent PyTCP does
  not have): RFC 4702 Client FQDN, RFC 3203 FORCERENEW, RFC 8910 Captive
  Portal (DHCPv4 Phase 9); RFC 6724 §6 destination-address selection;
  the RDNSS / DNSSL runtime consumer (wire codec is parse-ready).
- **Deliberate won't-do (scope decisions):** DCTCP (RFC 8257), L4S
  (RFC 9331 / 8311), TCP-AO (RFC 5925), Eifel (RFC 4015), CWV (RFC 7661),
  F-RTO (RFC 5682); `dup` / `dup2`, `socketpair`, hostname-in-`bind`/
  `connect`; RFC 4884 extended ICMP.
- **Phase-2 router track** (its own future major version): IP forwarding
  data path, ICMP Redirect emit, forward-path TTL-decrement + Time
  Exceeded, IGMPv3 / MLDv2 querier role, Proxy ARP, RH0 disable-knob,
  Router-Alert interception, PMTU-on-transit, RFC 1812 requirements, Link
  API `up()` / `down()` (needs multi-interface).

---

## Recommended ordering

**Shipped:** R1, R5 (+ follow-on), R6, R7, R10 (knob), R11, and **R4
(IPv6 SSM, P1-P5 — the big-value track, DONE)**. See the "Shipped" list
above for commits.

**Remaining (all optional; none block a 3.0.8 release):**

1. Small self-contained: **R2** (setsockopt-honored sweep — audit that
   every accepted socket option is actually consumed on the data path),
   **R10 §4** (MLDv1 Report suppression — marginal, an optimization).
2. Medium, as appetite allows: **R3** (SO_SNDBUF / SO_SNDTIMEO — needs a
   TX-completion signal), **R8** (IP_RECVERR error queue over the daemon
   IPC boundary), **R9** (cancelable / selectable accept over the daemon).

Suggested next: **R2** (small, closes a real correctness question) or
**R3** (the last commonly-used socket knob gap). Everything here can
equally slip to 3.0.9.

---

## Git state (2026-07-19)

- Branch `PyTCP_3_0_8`. Pushed through `b9794191` (UDP + RAW SO_RCVBUF +
  this backlog plan).
- Pushed through `c2a76a60` (R1 / R5 / R5-followon / R10 knob / R11).
- **Unpushed:** R7 DF-probe test-lock (`1793fb45`), R6 HyStart++ end-to-end
  tests (`6cc2702a`), R4 P1 `Ip6MulticastFilter` (`d2054fe8`) + its doc
  notes, and this resumable R4 P2-P5 map. Hold until the user says "push".
