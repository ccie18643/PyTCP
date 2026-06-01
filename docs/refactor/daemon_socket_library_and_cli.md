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

| Phase | Title                                                       | Status |
|-------|-------------------------------------------------------------|--------|
| A0    | Rename `pytcp.socket` → `pytcp.runtime.socket` (mechanical) | **done** |
| A1    | Multiplexed IPC client (`MuxIpcClient`)                     | **done** |
| A2    | Faithful error wire format + client reconstruction         | —      |
| A3    | Non-blocking connect/accept daemon-side readiness ⚠         | —      |
| A4    | The `pytcp.socket` drop-in module                          | —      |
| A5    | DNS resolved through the daemon                             | —      |

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
`{error, module, errno, args, message, strerror}`; new
`pytcp/client/client__errors.py::raise_remote_error` rebuilds
`OSError(errno, strerror)` (Python auto-selects the errno subclass),
`gaierror`/`herror`, non-OSError builtins, else `IpcRemoteError`. Decoder
tolerates the old `{error_type, message}` shape.

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
