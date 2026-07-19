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
  (see R3), `X3` listen()-on-unbound → `EINVAL` (breaks examples; land as
  an explicit breaking-change commit + update `examples/`).
- **Effort:** open-ended (do a few per session). **Risk:** low per fix.

### R3 — `SO_SNDBUF` accounting + `SO_SNDTIMEO` (medium-large, coupled)

- **Why deferred:** UDP `send` hands the datagram straight to the shared TX
  ring (`send_udp_packet`), with **no per-socket send buffer**. Linux
  `SO_SNDBUF` bounds `sk_wmem_alloc`; PyTCP has no such accounting.
- **Scope:** build a per-socket outstanding-send-bytes counter
  (increment on enqueue-to-TX, decrement on TX completion — needs a
  completion signal from the TX ring the socket can observe), bound it by
  `_so_sndbuf`, and on overflow either `EAGAIN` (non-blocking) or
  block up to `SO_SNDTIMEO`. `SO_SNDTIMEO` is only meaningful once this
  exists — do them together.
- **Tests-first:** red tests for over-SO_SNDBUF → EAGAIN, and blocking →
  timeout after SO_SNDTIMEO.
- **Effort:** medium-large (the TX-completion signal is the hard part).
  **Risk:** medium (touches the TX path). **Prereq:** understand how the
  TX ring signals completion; there may be no per-datagram completion today.

### R4 — IPv6 per-socket source filters = MLDv2 SSM track (large, highest value)

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
  - P1: `packages/pytcp/pytcp/lib/ip6_multicast_filter.py` (`Ip6MulticastFilter`,
    a straight `Ip6Address` copy of the v4 value type). Unit tests.
  - P2: new opts `IPV6_ADD_SOURCE_MEMBERSHIP` / `IPV6_DROP_SOURCE_MEMBERSHIP`
    (and/or the protocol-independent `MCAST_JOIN_SOURCE_GROUP` family) as
    `IpV6Option` enum members + bare aliases (see `.claude/rules/enums.md`
    §2.2). Wire the setsockopt cases.
  - P3: `_ip6_multicast_filters` dict on the handler + `_ip6_multicast_filter_for`.
  - P4: MLDv2 source records on TX — `Icmp6Mld2MulticastAddressRecordType`
    already has `ALLOW_NEW_SOURCES` (5) / `BLOCK_OLD_SOURCES` (6) /
    `CHANGE_TO_INCLUDE` (3) / `CHANGE_TO_EXCLUDE` (4). Emit the state-change
    source records on filter transitions (mirror `_send_igmp_state_change`;
    the MLDv2 leave path added in `de3d3213` is the sibling to extend).
  - P5: RX source-delivery filter for IPv6 UDP + RAW (`Ip6MulticastFilter.allows`).
  - Adherence: update `docs/rfc/icmp6/rfc3810__mld2/adherence.md` (§4.2.12 /
    §5.1 / §5.2 source records) + a socket-parity note, in lockstep.
- **Effort:** large (multi-phase, mirrors a whole shipped track). **Risk:**
  medium. **Value:** highest — real v4/v6 parity.

### R5 — CLI polish: JSON output for `address` / `ss` / `route` / `neighbor` — SHIPPED (see "Shipped" above)

Full `-j`/`--json` parity across every observation command is now closed
(`address`, `ss`, `route`, `neighbor`). The mutation verbs and `sysctl`
stay text-only (Linux `sysctl` has no `-j` either).

### R6 — HyStart++ (RFC 9406) remaining work

- **Scope:** the deferred pieces noted in the rfc9406 adherence record
  (~6–8 hrs estimated). Read `docs/rfc/tcp/rfc9406*/adherence.md` for the
  exact deferred rows before starting.
- **Effort:** medium. **Risk:** medium (CC path). **Value:** medium.

### R7 — DF-guarded TCP PLPMTUD probe (small, closes a "Phase 3c-min" residual)

- **Why:** the TCP probe-emit path (`session/tcp__session__tx.py`) ships
  probe-**sized** segments but does not set DF, so RFC 8899 §3 #2 (DF=1 on
  the probe) is still "Phase 3c" (honest note left in
  `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` and rfc4821). Set DF on the
  emitted probe segment so a black-hole is detected by loss rather than
  relying only on ack-feedback sizing.
- **Tests-first:** extend
  `test__tcp__session__plpmtud_probe_emit.py` to assert the probe segment
  carries DF=1 (IPv4) / is size-capped without fragmentation (IPv6).
- **Effort:** small–medium. **Risk:** medium (probe-loss interaction with
  RTO). **Value:** completes RFC 8899 §3 #2 / §4.1 fully.

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

### R10 — MLDv1 Report suppression (small) — knob part SHIPPED

- **`mld.version` force knob — SHIPPED (see "Shipped" above).** New
  `MLD__FORCE_VERSION` in `protocols/icmp6/mld__constants.py`, registered
  as the `mld.version` sysctl (range 0-2), consumed by
  `_mld_host_compatibility_mode`. Mirrors `igmp.version` /
  `IGMP__FORCE_VERSION`.
- **Remaining — RFC 2710 §4 Report suppression:** on RX of a peer MLDv1
  Report for a group in v1 compat mode, cancel this host's pending Report
  for that group. An optimization only (not done for MLDv2 either);
  marginal value. Tests-first in `tests/integration/protocols/icmp6/`.
- **Effort:** small. **Risk:** low. **Value:** marginal.

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

1. ~~**R1** (ping SO_RCVBUF)~~ — SHIPPED; the SO_RCVBUF symmetry is closed.
2. Small self-contained wins, any order: ~~**R5** (CLI JSON — all four
   observation commands)~~ SHIPPED, ~~**R10** mld.version knob~~ SHIPPED
   (R10 §4 suppression remains, marginal), ~~**R11** (RFC 6724 policy
   table)~~ SHIPPED, or dip into **R2** (setsockopt sweep).
3. **R4** (IPv6 SSM) — the big-value track; do it as its own phased effort.
4. Medium items as appetite allows: **R3** (SO_SNDBUF/SNDTIMEO), **R6**
   (HyStart++), **R7** (DF-guarded probe), **R8** (IP_RECVERR over daemon),
   **R9** (cancelable accept).

None block a 3.0.8 release. Everything here can equally slip to 3.0.9.

---

## Git state (2026-07-19)

- Branch `PyTCP_3_0_8`. Pushed through `b9794191` (UDP + RAW SO_RCVBUF +
  this backlog plan).
- **Unpushed:** `f5ecd901` (R1 ping SO_RCVBUF), `2750afb5` (R5 address
  JSON), `9b465047` (footer refresh), `2ecaf708` (ss/route/neighbor JSON),
  `3bf8315d` (R10 mld.version knob), + the R11 policy-table override
  commit. Hold until the user says "push".
