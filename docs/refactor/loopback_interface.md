# Loopback interface (`lo`) for the PyTCP stack

| Field             | Value                                                                                                                                                 |
|-------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status            | **SHIPPED** on `PyTCP_3_0_8` — all phases P0→P6 landed (`9efd9f7d` P0 InterfaceLayer.LOOPBACK + LinkFlag, `b3890ea8` P1 PacketHandlerLoopback + LoopbackRing, `b4d26586` P2+P3 lifecycle + harness, `6e30832b` P4 divert local IP TX onto the loopback ring, `5f335f7c` P5 accept local delivery of loopback + own-IP on `lo`, `f7e40612` P6 end-to-end TCP over loopback + own-IP). |
| Target branch     | `PyTCP_3_0_8`                                                                                                                                          |
| Linux analogue    | The `lo` loopback device — owns `127.0.0.0/8` + `::1`; any packet destined to a *local* address is delivered internally, never on the wire            |
| Motivation        | PyTCP has no intra-stack loopback: `connect(("127.0.0.1", port))` / `connect((own-ip, port))` hangs (SYN goes to the wire; nothing loops it back)      |
| North star        | CLAUDE.md host-stack parity — `lo` is a default Linux host interface                                                                                   |

This document mirrors the approved implementation plan for a
real, introspectable `lo` loopback interface. It is the durable
repo copy of `/root/.claude/plans/mutable-mixing-yeti.md`.

---

## 1. Context

PyTCP has **no intra-stack loopback**. A socket connecting to the stack's own IP
(or to `127.0.0.1` / `::1`) sends the SYN out the interface and nothing loops it
back, so it hangs — this is exactly what the two-stack async-FTP live test hit
(server + client on one stack could not talk; we needed two bridged stacks).
Under the hood, sending to the stack's own IP falls into the Ethernet TX handler's
connected-route path, ARP/ND-resolves *for itself*, misses the cache, and **drops**
(`DROPPED__ETHERNET__DST_ARP_CACHE_MISS`).

Linux ships a loopback device (`lo`) by default — `127.0.0.0/8` + `::1`, and any
packet destined to a *local* address is delivered via `lo` instead of the wire.
The chosen scope is **full `lo` parity**: a real loopback interface so
`connect(("127.0.0.1", port))` / `connect(("::1", port))` work AND connecting to
the stack's own configured routable IP loops internally.

**Outcome:** a real, introspectable `lo` interface (owns `127.0.0.0/8` + `::1`,
`LinkFlag.LOOPBACK`, MTU 65535); local-destined traffic delivered internally via a
queue+consumer (Linux `loopback_xmit → backlog → softirq` shape), never on the wire.

## 2. Design overview & key decisions

The delivery mechanism: at the **IP-TX layer** (`_phtx_ip4`/`_phtx_ip6`, after
dst-validation, before the L2/L3 `match` split — catches both TAP and TUN), detect a
local destination and **enqueue** the assembled IP packet onto `lo`'s input ring; a
separate consumer thread drains it into `_phrx_ip4/6`. Replies marshal normally to
the TX worker, which re-enters TX and enqueues again — two threads ping-pong via the
queue, **no deep nesting** (inline TX→RX→TX would nest an entire handshake/transfer
in one call stack and risk stack overflow — rejected).

Resolved decisions (cite in code):

- **(a) `lo` is a new `PacketHandlerLoopback` subclass + new `InterfaceLayer.LOOPBACK`**
  — not L3-in-loopback-mode. Keeps every `match _interface_layer` two-arm block
  intact (the diversion is *before* those matches) and gives `lo` its own
  MTU/flags/no-ARP/no-fd semantics cleanly.
- **(b) A new `LoopbackRing(Subsystem)`** (not a modified `RxRing`, which is
  fd/`select`-bound). Reuses the exact deque+eventfd pattern but its producer is a
  public `enqueue(packet_rx)`; its `_subsystem_loop` drains and dispatches by IP
  version to `interface._phrx_ip4/6`.
- **(c) ifindex:** keep the **physical/boot interface at ifindex 1** and register
  `lo` at the next index — 44 refs hardcode ifindex 1 for the physical interface;
  shifting them for Linux's `lo`=1 is churn out of proportion to a cosmetic numbering
  detail. Mark `# Phase 2: lo at ifindex 1 for strict Linux parity` and defer.
- **(d) Delivery decision is a membership test at the TX hook**
  (`dst.is_loopback or dst in stack.local_ip4_unicast()`), *not* a FIB lookup — the
  IP-TX layer deliberately doesn't do FIB today. Mark
  `# Phase 2: FIB HOST-scope local route supersedes this shortcut` (activates the dead
  `RouteScope.HOST`).
- **(e)/(f) Source/egress resolution comes for free** once `lo` is registered:
  `connected_ip{4,6}_networks()` already iterates **all** interfaces, so the
  `127.0.0.0/8→lo` and `::1→lo` connected routes are synthesized automatically →
  `has_route_to` / `egress_packet_handler` / `_select_ip*_source` (Rule 1) resolve
  loopback and own-IP correctly with **no change to source selection**. All local
  delivery routes through `lo`'s ring (Linux-faithful); `lo`'s RX acceptance covers
  the loopback range + all stack-local unicast.

Reused building blocks: `Ip4Address.is_loopback` (full `127.0.0.0/8`),
`Ip6Address.is_loopback` (`::1`); `stack.local_ip4_unicast()`/`local_ip6_unicast()`;
`connected_ip{4,6}_networks()`; the `RxRing` deque+eventfd pattern; the L3 no-DAD /
no-MAC-multicast handler overrides.

## 3. Implementation (tests-first; each phase = failing tests → impl → green)

**P0 — enum + flag (no behavior).** Add `InterfaceLayer.LOOPBACK`
(`lib/interface_layer.py`); map it in `_FLAGS_BY_LAYER` →
`frozenset({LinkFlag.LOOPBACK})` and refresh the "no consumer today" docstrings
(`stack/link.py`). Unit tests: member exists/distinct; `LinkApi.flags` for a
LOOPBACK handler.

**P1 — `PacketHandlerLoopback` + `LoopbackRing` (construction only).** New
`runtime/loopback_ring.py` (`LoopbackRing(Subsystem)`: `enqueue(packet_rx)`,
deque+eventfd, `_subsystem_loop` → `interface._phrx_ip4/6` by version, drop counter,
`_stop` closes eventfd). New `PacketHandlerLoopback(PacketHandler)`: `_interface_layer
= LOOPBACK`; assign `127.0.0.1/8` + `::1/128` (no DAD, no MAC-multicast); no
ARP/ND/DHCP/link-local; `mac_unicast` None; `attach_lo_ring`. Add
`INTERFACE__LOOPBACK__MTU = 65535` (`stack/__init__.py`). Unit tests: ring
enqueue→drain dispatches by version + queue-full drop + idempotent stop; handler
self-addresses (`ip4_unicast==[127.0.0.1]`, `ip6_unicast==[::1]`, layer LOOPBACK,
mac None).

**P2 — lifecycle: create/start/stop `lo`.** `stack/lifecycle.py`: `_add_loopback()`
builds the handler + ring and `interfaces.add()`s it (registered **after** the boot
interface so physical stays ifindex 1); call it from `init()` and (opt-in
`mock__loopback` kwarg) `mock__init()`; `_start_interface`/`_stop_interface` +
`start()`/`stop()` guard on the LOOPBACK layer (start/stop the `lo_ring`, skip
ARP/ND/TX-ring None asserts). Add `stack.loopback_handler()` accessor. Widen the
`LinkApi` handler typing to include `PacketHandlerLoopback`. Lifecycle test: after
`init`, a LOOPBACK interface exists owning `127.0.0.1`/`::1`; consumer thread
starts/stops with the stack.

**P3 — harness `lo` wiring + snapshot/restore.**
`tests/lib/network_testcase.py`: register a real `PacketHandlerLoopback` +
`LoopbackRing` in `setUp` (physical mock stays ifindex 1, lo next); add a
`drive_loopback()` helper that synchronously drains one queued packet (keeps
integration tests single-threaded/deterministic, matching the inline-TX harness).
`stack.interfaces` is already snapshot/cleared/restored so lo is covered; fix
suite-wide fallout from the registry gaining a `lo` entry (`len(interfaces)`,
`local_*_unicast()`, `connected_*_networks()`, introspection/cli tests). `TcpTestCase`
inherits; add a loopback-handshake helper.

**P4 — TX loopback diversion (`PASSED__*__LOOPBACK`).** Add
`PASSED__IP4__LOOPBACK`/`PASSED__IP6__LOOPBACK` (`lib/tx_status.py`; include in the
ip4 fragmentation severity list). In `_phtx_ip4` after `__validate_dst_ip4_address`,
before the MTU/fragment + `match`: `if ip4__dst.is_loopback or ip4__dst in
stack.local_ip4_unicast():` assemble the `Ip4Assembler`,
`stack.loopback_handler()._lo_ring.enqueue(PacketRx(bytes(pkt)))`, `return
PASSED__IP4__LOOPBACK`. Symmetric in `_phtx_ip6`. Integration tests (NetworkTestCase,
inline TX): send to `127.0.0.1` / `::1` / own-IP → returns `PASSED__*__LOOPBACK`,
`_frames_tx` empty, exactly one `PacketRx` enqueued on `lo`; assert the enqueue does
**not** synchronously call `_phrx_*` (no nesting); assert the ARP mock's `find_entry`
is never called for own-IP (the old bug path).

**P5 — `lo` RX acceptance.** Add an overridable `_accepts_local_dst_ip4/6(dst)` hook
on `PacketHandler` (default = current membership test); override on
`PacketHandlerLoopback` to also accept `dst.is_loopback or dst in
stack.local_ip4_unicast()`. Call it from `_forward_or_deliver_ip4/6` — keeps the
forward-vs-deliver seam intact. Integration: `lo._phrx_ip4` delivers dst=`127.0.0.1`
and dst=own-routable, drops dst=foreign; same for `::1`/own-GUA on `_phrx_ip6`;
physical-interface acceptance unchanged (regression).

**P6 — end-to-end (the two acceptance proofs).** TcpTestCase:
(1) listener on `("127.0.0.1", 80)`, client `connect(("127.0.0.1", …))`, drive the
loopback ring synchronously through the SYN→SYN-ACK→ACK ping-pong → both sessions
ESTABLISHED, `_frames_tx` empty, `send/recv` round-trips over `lo`. (2) same with
`connect(("10.0.1.7", 80))` (own IP): `has_route_to(10.0.1.7)` True, SYN's `_phtx_ip4`
returns `PASSED__IP4__LOOPBACK`, no wire frames, no
`DROPPED__ETHERNET__DST_ARP_CACHE_MISS`, handshake completes. Then `make validate`
clean.

Ordering: P0 → P1 → P2 → P3 → P4 → P5 → P6 (P2+P3 land together — they carry the
registry-gains-`lo` fixups).

## 4. Critical files

- `runtime/packet_handler/__init__.py` — `PacketHandlerLoopback` subclass;
  `_accepts_local_dst_ip4/6` hook.
- `runtime/loopback_ring.py` — **new** `LoopbackRing` queue+consumer.
- `runtime/packet_handler/packet_handler__ip4__tx.py` (+ `…ip6__tx.py`) — TX diversion.
- `runtime/packet_handler/packet_handler__ip4__rx.py` (+ `…ip6__rx.py`) — accept-hook call site.
- `stack/lifecycle.py` — `_add_loopback`, init/mock__init/start/stop wiring.
- `stack/__init__.py` — `loopback_handler()`, `INTERFACE__LOOPBACK__MTU`.
- `lib/interface_layer.py`, `stack/link.py`, `lib/tx_status.py` — enum/flag/status.
- `tests/lib/network_testcase.py` — harness `lo` + `drive_loopback` + suite fixups.

## 5. North-star guardrails (don't foreclose Phase 2/3)

- Keep `_accepts_local_dst_ip*` on the **deliver** side of `_forward_or_deliver`
  (never merged into parse/dispatch). Mark the TX membership shortcut
  `# Phase 2: FIB HOST-scope local route supersedes this` (uses the dead
  `RouteScope.HOST`).
- No new stack singleton: reach `lo` via `stack.interfaces` +
  `stack.loopback_handler()` and the Link/Address/Route APIs (so `lo` shows in
  `pytcp link`/`address`/`route`); don't expose `_lo_ring` to consumers.
- `lo` create/start/stop lives inside init/start/stop/mock__init (lifecycle boundary),
  not import-time state.

## 6. Verification

- `make lint` + `make test` clean throughout (mypy strict / pylint / pyright).
- The two P6 integration tests prove `connect(127.0.0.1)` and own-IP-loops-internally.
- Live re-confirmation (optional, mirrors §9 of the daemon doc): a single daemon on
  one TAP, run `ftp_server__async` + `ftp_client__async` both against it pointing at
  `127.0.0.1` (or the stack's own IP) — should now succeed on ONE stack (no bridge /
  second stack needed), closing the gap the two-stack test exposed.

## 7. Phase log

- **P0** `9efd9f7d` — `InterfaceLayer.LOOPBACK` enum member + Link API
  `_FLAGS_BY_LAYER` mapping to `{LinkFlag.LOOPBACK}`.
- **P1** `b3890ea8` — `LoopbackRing` (deque+eventfd queue) +
  `PacketHandlerLoopback` (subclasses `PacketHandlerL3` for zero
  union-type churn; owns 127.0.0.1/8 + ::1/128; `_subsystem_loop` drains
  the ring and dispatches by IP version). `INTERFACE__LOOPBACK__MTU`.
- **P2+P3** `b4d26586` — lifecycle wiring: `init()` always registers `lo`
  (after any boot interface); start/stop guards for the LOOPBACK layer;
  `stack.loopback_handler()`; opt-in `mock__loopback` +
  `NetworkTestCase._register_loopback` / `drive_loopback` harness
  helpers; `LoopbackRing.__del__` fd safety net.
- **P4** `6e30832b` — IP-TX loopback diversion: `_phtx_ip4/6` enqueue a
  locally-destined packet onto the ring and return
  `PASSED__IP{4,6}__LOOPBACK`; `_effective_ip6_hop_limit` override.
- **P5** `5f335f7c` — RX acceptance hook `_accepts_local_dst_ip4/6`
  (base = membership test; lo override accepts 127/8 · ::1 · own-IP),
  called from `_forward_or_deliver_ip4/6`.
- **P6** `f7e40612` — end-to-end TCP-over-loopback proofs (127.0.0.1 and own-IP
  handshakes complete, no wire frames). Prerequisites discovered and
  fixed: `PacketHandlerLoopback._marshal_tx` runs inline (lo has no TX
  ring), and a `PacketRx.from_loopback` flag lets the IPv4/IPv6 parsers
  skip the RFC 1122 §3.2.1.3(g) / RFC 4291 §2.5.3 loopback-source
  martian check for internally-looped traffic (a wire-ingress-only
  policy).
