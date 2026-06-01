# Daemon Socket Library (1:1 stdlib drop-in) + `pytcp` CLI Multitool

| Field      | Value                                                                 |
|------------|-----------------------------------------------------------------------|
| Status     | **IN PROGRESS — Track A starting. Phase 0 complete (3.0.7 released + frozen, 3.0.8 opened). Created 2026-05-31 on `PyTCP_3_0_8`.** |
| Branch     | `PyTCP_3_0_8`                                                          |
| Builds on  | The kernel/userspace separation track ([`kernel_userspace_separation.md`](kernel_userspace_separation.md)), shipped as `3.0.7`. |
| Motivation | Turn the daemon boundary into two user-facing layers: a 1:1 stdlib-`socket` drop-in client library, and a single `pytcp` CLI multitool that manages and drives the daemon. |

---

## 1. Context

The kernel/userspace separation track is **complete and shipping as
`3.0.7`**: a PyTCP daemon exposes an AF_UNIX control socket; out-of-process
clients open TCP/UDP/raw/AF_PACKET sockets (real SCM_RIGHTS-passed fds,
active connect + passive accept) and drive the six control APIs via
`pytcp.client`. The consumer model is now **daemon-only** — consumers talk
to the daemon, they do not run the stack in-process.

This track (versioned **`3.0.8`**) builds the two user-facing layers on top
of that boundary:

1. **A 1:1 stdlib-`socket`-compatible client library.** An off-the-shelf
   third-party app works against the daemon by changing **one import line**
   (`import socket` → `import pytcp.socket as socket`), monkeypatch-capable
   (`sys.modules['socket'] = pytcp.socket`). Full surface: blocking *and*
   non-blocking / `select` / `epoll`, `connect_ex`, faithful
   `errno` / exception reconstruction, DNS resolved *through* the daemon's
   stack, and many sockets per process fully independent.
2. **A unified `pytcp` CLI multitool** that both manages the daemon
   (`pytcp daemon start/stop`) and drives it with Linux-tool-lookalike,
   faithful-and-parseable subcommands (`pytcp ss / link / addr / route /
   neigh / sysctl`).

Build order: **socket library first** (with a real off-the-shelf app as the
proof point), then the CLI toolset.

## 2. Decisions (locked with the user)

| Topic        | Decision                                                                                           |
|--------------|----------------------------------------------------------------------------------------------------|
| Naming       | rename internal `pytcp.socket` → **`pytcp.runtime.socket`**; the freed **`pytcp.socket`** becomes the daemon-backed client drop-in |
| Drop-in depth| full 1:1, max stdlib surface, monkeypatch-capable (one-line import swap)                            |
| Async        | full non-blocking + `select` / `poll` / `epoll` / `selectors`, `connect_ex`, `EINPROGRESS` (daemon-side readiness) |
| DNS          | resolved **through the daemon's stack** (new `net_proto` DNS codec + daemon resolver + `resolve` control op) |
| Concurrency  | **multiplexed client** — one AF_UNIX control connection per process, background reader + `req_id` correlation |
| Errors       | full `errno` + exception-class reconstruction client-side                                          |
| CLI fidelity | **faithful + parseable** (match real `ss` / `ip` / `route` / `sysctl` layouts for common invocations) |
| CLI shape    | **one `pytcp` multitool**, argparse subparsers (zero-dep), incl. `daemon start` / `stop`           |
| Versioning   | kernel/userspace = `3.0.7`; this whole track = `3.0.8`                                              |

## 3. Phases

### Phase 0 — Release boundary (push 3.0.7, open 3.0.8) — **COMPLETE**

- 3.0.7 pushed, released to PyPI (3 dists via OIDC), frozen, master-synced.
- `PyTCP_3_0_8` cut; `__version__` bumped `3.0.7` → `3.0.8` + lockstep
  pyproject pins. New files from here use `ver 3.0.8`.

### Track A — the 1:1 socket library

**Reordered 2026-06-01 (decided with the user): the synchronous drop-in
lands first.** Blocking programs (`http.client` / `socketserver` / most
CLI network tools) need *none* of the non-blocking readiness machinery —
a blocking connect just blocks in the daemon RPC. So A4 (sync) + A5 (DNS)
ship first behind a real stdlib-program proof point, then the
non-blocking / asyncio readiness work (A3, now decomposed A3.0–A3.4)
layers on top and upgrades the drop-in to the mux client. The discussion
that drove this — why the writable-on-connect "filler" is a trick, what a
clean backpressure design is, and the honest limits of "100% asyncio /
100% sync compat" — is captured in §7.

| Phase | Title                                                       | Status |
|-------|-------------------------------------------------------------|--------|
| A0    | Rename `pytcp.socket` → `pytcp.runtime.socket` (mechanical) | **done** |
| A1    | Multiplexed IPC client (`MuxIpcClient`)                     | **done** |
| A2    | Faithful error wire format + client reconstruction         | **done** |
| A4    | The `pytcp.socket` synchronous drop-in module              | **done** |
| A5    | DNS resolved through the daemon                             | —      |
| P1    | Proof point — real stdlib program over the daemon          | **done (http.client, IP-literal)** |
| A3.0  | Feasibility: TcpSocket tx-writable signal + bridge pump (read-only) | **done** |
| A3.1  | Prototype the writable-on-connect edge (throwaway)         | —      |
| A3.2  | Backpressure bridge (honest data-phase writability)        | —      |
| A3.3  | Non-blocking connect (connect-as-window-0 + SO_ERROR)      | —      |
| A3.4  | Non-blocking accept (listener readiness + accept_take)     | —      |
| P2    | Proof point — real asyncio TCP client+server over the daemon | —    |

**A3.0 findings (read-only, 2026-06-01):** the existing `SocketBridge`
*already* does data-phase backpressure — its TX pump stops draining the
client's send buffer while `_send_all` is stuck feeding the stack socket,
so the client end goes non-writable when the TCP window closes (its own
docstring says so). So A3.2 is largely already true; the only hardening
candidate is a possible busy-loop in `_send_all` when `TcpSocket.send`
returns 0. The genuinely new work is confined to the connect-start edge
(A3.3, where there is no data yet to carry backpressure) and accept
readiness (A3.4) — neither of which blocking programs touch. This is the
fact base that justified landing the synchronous drop-in first.

**A0 — rename.** Move `packages/pytcp/pytcp/socket/` →
`packages/pytcp/pytcp/runtime/socket/`; rewrite every `pytcp.socket`
reference (imports, `patch` strings, module-docstring path footers, the
packaging-regression test's `"pytcp/socket/"` assertion) to
`pytcp.runtime.socket` / `pytcp/runtime/socket`. Relocate the **unit**
socket tests to `tests/unit/runtime/socket/` with the
`test__runtime__socket__` prefix (mirrors the `tx_ring` / `packet_handler`
relocations); the **integration** socket tests stay at
`tests/integration/socket/` (domain grouping, like
`tests/integration/packet_handler/`). One isolated commit gated by
`make lint` + the full suite. Frees the `pytcp.socket` name for A4.

**A1 — `MuxIpcClient`.** New `pytcp/ipc/ipc__mux_client.py` beside
`IpcClient` (control proxies keep the simple one). One AF_UNIX socket +
write-lock + monotonic `req_id` allocator + `dict[req_id, _PendingCall]` +
one background reader thread routing `(message, fd)` by `req_id`. API:
`call` (sync), `call_async` (register+send, no wait — basis for
`EINPROGRESS`), `cancel`, `close` (fail outstanding). Reader death fails all
pending → per-socket `OSError`, never a hang.

**A2 — error wire format.** Extend `encode_socket_error` to carry
`{error, message, module, errno, args, strerror}` + add
`encode_exception` (the daemon-side capture: `getattr` errno/strerror on
`OSError`, tagged-encode `args`); `raise_remote_error` rebuilds
`OSError(errno, strerror)` (Python auto-selects the errno subclass),
`socket.gaierror`/`herror` by name, non-OSError builtin `Exception`
subclasses from args, else `IpcRemoteError`. Decoder tolerates the old
`{error, message}`-only shape (→ `IpcRemoteError` fallback).
**Placement deviation from the plan:** `raise_remote_error` lives at
`pytcp/ipc/ipc__remote_error.py`, NOT `pytcp/client/client__errors.py` —
the socket-plane RPC helpers (`ipc__socket_rpc`) call it, and
`pytcp.client` already depends on `pytcp.ipc`, so a `client/` placement
would invert into an import cycle. It stays codec-core-clean
(`decode_value` + `IpcRemoteError` + stdlib only).

**A3 — non-blocking readiness (HIGHEST RISK).** The client data fd is an
AF_UNIX socketpair end (always writable), so "writable == connected" does
not fall out. Mechanism (prototype first): writability priming — the
client writes `SO_SNDBUF`-worth of sentinel filler into its own data fd so
it reads non-writable, issues `connect` via `call_async` (returns
`EINPROGRESS`); the daemon runs `TcpSocket.connect()` on a per-handle worker
thread, and on success the bridge TX pump drains the leading filler →
client send buffer frees → fd flips writable → `select`-for-writable wakes.
`SO_ERROR` read-once cache; `connect_ex`; accept readiness via listener
eventfd + watcher + `accept_take`. New JSON-body socket methods
(`connect_start`, `accept_take`), no new `IpcOp`. Fallback: two-fd model
(data fd + readiness eventfd). Raw `select` on bare-int writable fds during
connect is the one irreducible edge.

**A4 — `pytcp.socket` drop-in.** New `pytcp/socket/` package (the freed
name): a stdlib-shaped `socket(...)` factory wrapping the existing
`Client*Socket` machinery, re-exporting **all** constants/errors/pure
helpers from `pytcp.runtime.socket` under stdlib spellings. Data-path
methods delegate to the real socketpair fd; control methods marshal via the
mux client. Process-wide lazy `MuxIpcClient` singleton from
`$PYTCP_DAEMON_SOCKET`. Proof point: a real off-the-shelf socket program
(e.g. stdlib `http.client` / `socketserver`) over the daemon.

**A5 — DNS through the daemon.** New `net_proto` DNS codec
(`packages/net_proto/net_proto/protocols/dns/`, six-file pattern, A/AAAA over
UDP, name-compression isolated + loop-guarded); daemon resolver
(`pytcp/protocols/dns/dns__resolver.py`, in-process `pytcp.runtime.socket`
UDP, retry+timeout+TTL cache); `resolve` control op
(`pytcp/stack/resolver.py` + allowlist); client `getaddrinfo`/`gethostbyname`
consumed by the A4 module.

### Track B — the `pytcp` CLI multitool

| Phase | Title                                            | Status |
|-------|--------------------------------------------------|--------|
| B1    | Socket-list introspection API (`stack.ss`)       | —      |
| B2    | The unified `pytcp` argparse multitool           | —      |

**B1 — `stack.ss`.** `pytcp/stack/socket_introspect.py` — `SocketSnapshot`
(frozen, copy-by-value) + `SocketIntrospectApi.list_sockets(*, family,
socket_type, listening_only)` walking `stack.sockets` (+ `packet_sockets`),
deterministically sorted. Register `SocketSnapshot` in
`ipc__values._DATACLASS_TYPES` and **add `FsmState` to `_ENUM_TYPES`**;
allowlist + client mirror.

**B2 — `pytcp` multitool.** New `pytcp/cli/` (zero-dep argparse subparsers):
`__main__.py` dispatcher + `cli__daemon/ss/link/route/neigh/sysctl.py` +
`cli__format.py` (pure `snapshot → str`, golden-tested without a daemon).
`[project.scripts]`: add `pytcp = "pytcp.cli.__main__:main"`, retain
`pytcpd`. `daemon stop` via pidfile + SIGTERM. Faithful parseable layouts.

## 4. Verification

- Per phase: `make lint` clean (mypy strict; argparse-not-click in `pytcp`,
  six-file `net_proto` pattern, snapshot copy-by-value), §7.2 docstring audit
  on touched test files, full `make test` green (~12.5k existing tests stay
  green — A0 is the only churn-heavy phase, gated by them).
- Socket-lib proof point: a real off-the-shelf socket program runs over the
  daemon via the one-line import swap + `sys.modules` monkeypatch path.
- CLI proof point: `pytcp daemon start` then `pytcp ss -tuln` / `pytcp addr`
  / `pytcp route` produce faithful, parseable output against the live daemon.
- No push unless explicitly asked. Commit trailer:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## 5. Key risks / flagged unknowns

1. **Non-blocking connect readiness (A3)** — the filler/`SO_SNDBUF`
   writability trick is the highest-risk mechanism; prototype first, with
   the two-fd readiness-eventfd fallback documented.
2. **A0 rename churn** — ~382 imports / ~157 files; mechanical but large.
   One isolated commit, tests as the gate.
3. **Two connections per process** — control `IpcClient` + socket
   `MuxIpcClient` coexist (default); unifying is a later cleanup.
4. **DNS name compression** — the one genuinely tricky parse; isolate + test
   (pointer-loop guard).
5. **`getaddrinfo` through the daemon** — IP-literal fast-path bypasses the
   resolver.
6. **`dup`/`makefile`/`fromfd` handle-vs-fd ownership** — data fd shared,
   daemon handle not; cover explicitly.

## 6. Phase log

- **2026-05-31** — Phase 0 complete (3.0.7 released/frozen, 3.0.8 opened).
  Ledger created. Track A starting.
- **2026-05-31** — A0 complete (commit `c23677df`): `pytcp.socket` →
  `pytcp.runtime.socket` mechanical rename, 178 files, 34 renames; unit
  tests relocated to `tests/unit/runtime/socket/`; lint clean, 12534
  passing. `pytcp.socket` name now free for the A4 drop-in.
- **2026-05-31** — A1 complete: `pytcp/ipc/ipc__mux_client.py`
  (`MuxIpcClient` + `PendingCall`) — one AF_UNIX socket, write-lock +
  monotonic req_id allocator + pending registry + background reader
  routing `(message, fd)` by req_id; `call` / `call_async` / `wait` /
  `cancel` / `close`, fd-ownership handled on every path (deliver /
  timeout-race / cancel / fail-all). 9 unit tests over a fake-daemon
  AF_UNIX listener. lint clean, 12543 passing.
- **2026-05-31** — A2 complete: faithful error wire format. Extended
  `encode_socket_error` + new `encode_exception` (daemon capture) +
  `ipc/ipc__remote_error.py::raise_remote_error` (errno→OSError subclass,
  gaierror/herror by name, builtin Exception subclasses from args, else
  IpcRemoteError fallback). Socket-plane `raise_socket_error` routes
  through it; control plane keeps `IpcRemoteError`. `raise_remote_error`
  placed in `ipc/` (not `client/`) to avoid the client→ipc cycle. Close
  test updated (now surfaces the faithfully-reconstructed daemon
  `KeyError`). 7 new unit tests. lint clean, 12550 passing. Follow-up
  (A4): the daemon's unknown-handle `KeyError` is itself a candidate for
  EBADF translation so the drop-in matches stdlib on a closed socket.
- **2026-06-01** — A3.0 feasibility (read-only) + Track A **reordered**:
  synchronous drop-in (A4 + A5 + proof point P1) now lands before the
  non-blocking / asyncio readiness work (A3.1–A3.4 + P2). Design
  discussion captured in §7. Findings recorded in the A3.0 box above.
- **2026-06-01** — A4 core complete: `pytcp/socket/` drop-in package —
  `socket__dropin.py` (`Socket` wrapper + `socket()` factory + lazy
  `$PYTCP_DAEMON_SOCKET` `ClientStack` singleton + `_reset_default_stack`
  test hook) + `__init__.py` re-exporting the ~90-name stdlib constant /
  enum / error / DNS-helper surface (no `__all__` on the source, so an
  explicit list) with `error=OSError` / `timeout=TimeoutError` /
  `has_ipv6`. `pytcp/__init__.py` flipped back to `from pytcp import
  socket, stack` (the real drop-in subpackage replaces the A0 runtime
  alias). The drop-in imports `pytcp.client` **lazily** (TYPE_CHECKING +
  string-`cast` + in-function import) to dodge the genuine
  import-pytcp-time `ipc → neighbor ↔ stack` cycle the eager import
  exposed. Covers SOCK_STREAM + SOCK_DGRAM blocking; `Socket` adds
  `sendall` / `recv_into` / `gettimeout` / `getblocking` / context-manager
  / `family`/`type`/`proto`. Proof point: a full blocking TCP echo
  (`recv` + `sendall`) driven entirely through `pytcp.socket` over the
  live daemon. 4 unit + 3 integration tests. lint clean, 12557 passing.
  Deferred to a follow-on increment: `makefile` / `dup` / `detach`,
  RAW/AF_PACKET in the factory, a UDP-echo proof, and the
  daemon-unknown-handle `KeyError`→`EBADF` faithfulness fix.
- **2026-06-01** — A4.1 (makefile) complete: `Socket.makefile(mode,
  buffering, *, encoding, errors, newline)` mirroring stdlib — a
  `_SocketIO(io.RawIOBase)` over the wrapper's `recv_into` / `send`,
  wrapped in `BufferedReader` / `BufferedWriter` / `BufferedRWPair` /
  `TextIOWrapper` per mode. `Socket.close()` is now io-ref-aware
  (`_io_refs` / `_closed` / `_real_closed` + `_decref_socketio`): the
  daemon handle + data channel are held open until both the socket and
  every `makefile` stream made from it close — the stdlib shared-fd
  ownership contract. The `TextIOWrapper(buffer)` wrap needs one §17
  string-`cast` to `_WrappedBuffer` (typeshed's protocol demands both
  `read` and `write`; the runtime wrap only exercises the matching half).
  This is the gating piece for stdlib `http.client`. 2 integration tests
  (buffered-reader line read + buffered-writer to the wire). lint clean,
  12559 passing.
- **2026-06-01** — A4.2 (dup/detach) complete: `Socket.dup()` duplicates
  the data channel via `os.dup` into a `_DupDataChannel`-backed `Socket`
  (stream only) — a `dup(2)` of the socketpair end reaches the same
  daemon socket, so the byte stream is shared, but the duplicate carries
  no daemon control handle, so a new `_control_sock()` guard raises
  `OSError(EOPNOTSUPP)` for any control op on it (all control methods now
  route through `_control_sock()`). `Socket.detach()` returns the live
  data-channel fd and neutralizes the wrapper (`close` releases nothing,
  `fileno` → -1); the daemon handle is left to be reaped on disconnect.
  Both client shims (`ClientTcpSocket`, `_ClientDatagramBase`) gain a
  `detach()` that detaches their `_data_socket` fd. The ownership split is
  pinned by tests: a duplicate reads peer data off the shared connection
  and survives the other's close; a duplicate's control op fails; a
  detached fd, salvaged into a stdlib socket, still receives peer data. 3
  integration tests. lint clean, 12562 passing.
- **2026-06-01** — A4.3 (UDP proof) complete: a new
  `test__ipc__socket_dropin_udp.py` (over `UdpTestCase` + a live
  `IpcServer` + the `$PYTCP_DAEMON_SOCKET` singleton wiring) drives a
  datagram round trip entirely through `pytcp.socket` — the SOCK_DGRAM
  factory + the wrapper's `recvfrom` / `sendto`. Proves the datagram data
  plane (control RPC + SCM_RIGHTS data channel + datagram bridge + per-
  datagram address framing) end to end through the drop-in: a peer
  datagram is delivered with its sender address via `recvfrom`, and a
  `sendto` reaches the wire addressed to the peer. No production change —
  the factory + `sendto`/`recvfrom` already existed; this is the proof.
  2 integration tests. lint clean, 12564 passing.
- **2026-06-01** — A4.4 (EBADF faithfulness) complete, **closing A4**:
  `SocketSession._invoke` now raises `OSError(errno.EBADF, "Bad file
  descriptor")` for an unknown handle instead of `KeyError`, so a call
  over a released daemon handle reconstructs client-side as
  `OSError(EBADF)` — the same error the stdlib reports for a call on a
  closed descriptor (the A2 error wire already carries the errno). The
  `test__ipc__client_tcp_socket` close test now asserts `OSError(EBADF)`;
  the generic-builtin-`KeyError`-reconstruction unit test keeps its
  coverage but drops the now-stale "Unknown socket handle" example
  string. lint clean, 12564 passing. **A4 (the synchronous drop-in) is
  complete**: factory + `Socket` wrapper + makefile + dup/detach + faithful
  errors, proven end to end for TCP and UDP through `pytcp.socket`.
- **2026-06-01** — P1 (synchronous milestone) **done**: a real stdlib
  `http.client.HTTPConnection` completes a GET request / response over a
  drop-in socket, driven on a background thread while the test plays the
  HTTP server on the wire. It exercises http.client's actual request
  serialization (`sendall`), response parsing, and `makefile("rb")` body
  read against the daemon-backed data channel — proving real off-the-shelf
  stdlib protocol code runs unmodified over `pytcp.socket`. The socket is
  opened via `pytcp.socket.socket()` and driven to ESTABLISHED through the
  drop-in's blocking `connect`; the connection is assigned to the
  `HTTPConnection`, so the full create_connection/getaddrinfo plumbing is
  the only thing bypassed (an IP-literal `create_connection` is trivially
  addable; name-based resolution awaits A5's getaddrinfo-through-daemon).
  1 integration test, added to `test__ipc__socket_dropin.py`. lint clean,
  12565 passing. **The synchronous drop-in is proven against real stdlib
  protocol code.**

## 7. Design discussion — readiness, the "trick", and compat limits

Captured from the 2026-06-01 discussion so the rationale is durable.

**Why writable-on-connect needs a "trick".** A real kernel socket *is*
the connection, so `select`-for-writable flips the instant the handshake
completes. In the daemon model the client's data fd is one end of an
AF_UNIX socketpair — **always writable the moment it exists**, so a
non-blocking `connect` + `select([],[fd],[])` would return writable
before anything happened. The plan's mechanism fills the client's send
buffer with sentinel filler (so the fd reads *not*-writable), runs the
real connect on a daemon worker thread, and drains the filler on success
so the fd flips writable. It is a "trick" because it manufactures
artificial backpressure and releases it to *simulate* the kernel's
writable-on-connect edge — indirect, `SO_SNDBUF`-accounting-dependent,
and fragile (the bridge must strip exactly the filler before real data).

**The irreducible truth.** PyTCP sockets are userspace objects, not
kernel fds, so *no* fd has kernel-native readiness equal to a PyTCP
connection's state — something in the daemon must actively drive a passed
fd's readiness. Every userspace-stack-as-a-server (gVisor sentry,
libslirp) does the same. "No driven readiness at all" is not achievable.

**The clean reframe.** Done with proper flow control, the socketpair
bridge gives honest readiness with no fake bytes: readable = real
inbound data; writable = the daemon is willing to drain the client's send
buffer = the real `TcpSocket` can accept more (gate client→daemon
pumping on the stack socket's send-window). The data-phase already works
this way (A3.0 finding). The genuinely awkward case is only the
*connect-start* edge — there is no data yet to carry backpressure, so an
empty buffer reads writable. Modeled honestly this is "the send window is
zero until connected", realized by a *bounded* buffer occupation (small
`SO_SNDBUF` + write-until-EAGAIN prime, drained on connect-success) —
the same flow-control state, not a separate hack. Accept readiness is
clean (listener readable = a child is queued).

**Honest compatibility limits.** Neither "100% asyncio" nor "100% of
every synchronous socket program" is a claim worth making — the surface
includes TLS, datagram endpoints, `sendfile`, `sendmsg`/`recvmsg` cmsg,
every `setsockopt` *honored* (not merely accepted), errno-exactness, and
irreducible userspace-stack gaps (options with no faithful TAP/TUN
meaning). The measurable bar is **CPython's `Lib/test/test_socket.py`**
(Arch pkg `python-tests`) — but it assumes the kernel, tests much that is
out of scope, and its in-process client/server harness fights the daemon
boundary, so realistically a *relevant subset* (INET/INET6 TCP+UDP
client/server + timeouts + common options) is the honest yardstick, not a
turnkey gate. Deliverables are therefore framed as **proof points**
(real stdlib program over the daemon = P1; real asyncio client+server =
P2), with TLS / datagram / long-tail tracked as explicit follow-ups.

**Why synchronous first.** Blocking programs use *none* of the readiness
machinery — a blocking connect just blocks in the daemon RPC. So A4(sync)
+ A5 deliver a provable "real programs run over pytcp" milestone (P1)
with zero A3 risk on the critical path; the non-blocking / asyncio
readiness (A3.1–A3.4, P2) layers on top afterward.
