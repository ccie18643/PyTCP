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
| A5    | DNS resolved through the daemon                             | **done** |
| P1    | Proof point — real stdlib program over the daemon          | **done (http.client, IP-literal)** |
| A3.0  | Feasibility: TcpSocket tx-writable signal + bridge pump (read-only) | **done** |
| A3.1  | Prototype the writable-on-connect edge (throwaway)         | **done (validated)** |
| A3.2  | Backpressure bridge + non-blocking data-phase readiness baseline | **done** |
| A3.3  | Non-blocking connect (connect-as-window-0 + SO_ERROR)      | **done** |
| A3.4  | Non-blocking accept (listener readiness + accept_take)     | **done** |
| P2    | Proof point — real asyncio TCP client+server over the daemon | **done** |

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
| B1    | Socket-list introspection API (`stack.ss`)       | **done** |
| B2    | The unified `pytcp` argparse multitool           | **done** |

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
- **2026-06-01** — A5.1 (DNS codec core) started: new
  `net_proto/protocols/dns/` package — `dns__errors` (Integrity/Sanity),
  `dns__enums` (`DnsOpcode` / `DnsResponseCode` / `DnsRecordType` A=1
  AAAA=28 / `DnsRecordClass` IN=1), `dns__header` (the 12-octet RFC 1035
  §4.1.1 `DnsHeader` ProtoStruct + properties mixin, flag-word pack /
  unpack with tolerant `from_int`), and `dns__name` — the RFC 1035 §4.1.4
  domain-name codec: `encode_name` (uncompressed wire form, label/name
  length asserts) + `decode_name` (compression-pointer following with a
  `seen`-offset cycle guard, reserved-bits / truncation / over-255
  rejection raising `DnsIntegrityError`). 25 unit tests (14 name codec:
  encode/decode/nested-pointer/loop-guard/truncation/reserved-bits/
  round-trip; 11 header: accepted + buffer round trip + a 9-case rejection
  matrix). lint clean, 12590 passing. Next (A5.2): question / RR
  dataclasses + parser + assembler (full query build / response parse).
- **2026-06-01** — A5.2 (DNS message codec) complete: `dns__question`
  (`DnsQuestion`), `dns__resource_record` (`DnsResourceRecord` with an
  `address` property extracting the A / AAAA `Ip4Address`/`Ip6Address`),
  `dns__base` (the `Dns` Proto base over header + questions + answers,
  serializing the uncompressed canonical form), `dns__parser` (`DnsParser`
  — three-phase: integrity = 12-octet floor, parse = header + qd/an
  questions/answers + walk-and-discard authority/additional, sanity = no
  trailing octets; variable-section integrity raised by
  `decode_name`/`from_frame` per the net_proto §7 from_buffer-can-raise
  pattern), and `dns__assembler` (`DnsAssembler` — builds a standard
  recursive query, `assemble()` NotImplemented as an L7 protocol).
  Exported from `net_proto/__init__.py`. 15 unit tests (assembler:
  query bytes / RD-clear / AAAA / empty-reject; parser: A + AAAA response
  with compressed answer names, address extraction, 4-case integrity
  matrix + boundary, trailing-octet sanity). Verified end to end: a built
  query's bytes are exact and a crafted compressed A/AAAA response parses
  to the right address. lint clean, 12605 passing. Next (A5.3): the
  daemon-side resolver (in-process `pytcp.runtime.socket` UDP client to an
  upstream, retry + timeout + TTL cache).
- **2026-06-01** — A5.3 (daemon resolver) complete: new
  `pytcp/protocols/dns/dns__resolver.py` — `DnsResolver` answers A / AAAA
  lookups by sending a recursive query to a configured upstream over an
  in-stack UDP socket, matching the response by transaction id, extracting
  the addresses, and caching them for the answer TTL (a lock-guarded
  `dict` per the free-threading north star). Retries on timeout / id
  mismatch / non-NOERROR; raises `DnsResolverError(name_error=True)` on
  NXDOMAIN. The UDP socket (`ResolverSocket` protocol — the in-stack
  `UdpSocket` subset: `sendto` + `recvfrom(bufsize, timeout)` + `close`)
  and the 16-bit transaction-id source are injected, so the resolver is
  unit-tested with a state-driven fake socket factory and a pinned id; the
  default factory opens a real `pytcp.runtime.socket` datagram socket. 6
  unit tests (resolve A, cache-within-TTL, re-query after expiry,
  id-mismatch retry, timeout exhaustion, NXDOMAIN name error). lint clean,
  12611 passing. Next (A5.4): the `resolve` control op + client
  `getaddrinfo` / `gethostbyname` + `ClientStack.resolver` binding.
- **2026-06-01** — A5.4 (resolve control op + client shims) complete in
  two commits. **A5.4a (daemon side):** `pytcp/stack/resolver.py`
  `ResolverApi` (the getaddrinfo analogue — `resolve(*, host, family)`
  over the `DnsResolver`, querying A and/or AAAA, returning a tuple of
  natively-IPC-encodable `Ip4Address`/`Ip6Address`); a `resolver:
  ResolverApi` singleton + `STACK__DNS_SERVER` default (Quad9) wired in
  `lifecycle.py` `mock__init` + `init`; `ipc__control.py` `resolver ->
  {resolve}` allowlist + dispatch. 5 unit tests. **A5.4b (client side):**
  `pytcp/client/client__resolver.py` `ClientResolver` — `resolve` mirror
  plus stdlib-shaped `gethostbyname` (first IPv4 string) and `getaddrinfo`
  (list of 5-tuples) with an IP-literal fast path and faithful
  `socket.gaierror` translation of control failures; bound as
  `ClientStack.resolver`. 4 integration tests over a live IPC server with
  a fake-backed daemon resolver (resolve, gethostbyname, getaddrinfo,
  IP-literal bypass). lint clean, 12620 passing. Next (A5.5): wire
  `pytcp.socket.getaddrinfo`/`gethostbyname` to the daemon resolver +
  `create_connection`, so `http.client` connects by hostname.
- **2026-06-01** — A5.5 (socket-layer wiring) complete, **closing A5**:
  `pytcp.socket` now overrides `getaddrinfo` / `gethostbyname` (sourced
  from `socket__dropin`, delegating to `_get_default_stack().resolver`)
  instead of re-exporting the stdlib host-OS versions, and adds
  `create_connection` (resolve via the daemon, then try each candidate
  until one connects) + the `_GLOBAL_DEFAULT_TIMEOUT` sentinel for
  http.client compatibility. 3 integration tests added to the dropin
  suite (the class now injects a table-driven fake daemon resolver):
  `getaddrinfo` / `gethostbyname` through the daemon, and the **capstone**
  — `create_connection(("echo.example", port))` resolves the hostname via
  the daemon, opens a drop-in socket, completes the handshake on an
  ephemeral local port, and exchanges data. This is the full stdlib
  connect path P1 bypassed. lint clean, 12623 passing. **A5 done — DNS is
  resolved through the daemon end to end, and the synchronous drop-in now
  supports name-based connect.**

- **2026-06-01** — B1 (socket introspection) complete in two commits.
  **B1a (stack side):** `pytcp/stack/socket_introspect.py` — `SocketSnapshot`
  (frozen, copy-by-value) + `build_socket_snapshots` (pure, stack-free
  filter/sort core reading each socket through an `IntrospectableSocket`
  protocol, duck-typing the TCP-only state/queues) + `SocketIntrospectApi.
  list_sockets` over the live `stack.sockets`; `ss: SocketIntrospectApi`
  singleton wired in lifecycle. 5 unit tests over socket doubles.
  **B1b (IPC + client):** registered `SocketSnapshot` in
  `ipc__values._DATACLASS_TYPES` and `FsmState` in `_ENUM_TYPES`;
  `socket_introspect -> {list_sockets}` in the control allowlist + dispatch;
  `pytcp/client/client__socket_introspect.py` `ClientSocketIntrospect` bound
  as `ClientStack.ss`. 3 integration tests open real daemon sockets via
  `ClientStack.socket()` and list them over IPC (listening TCP with LISTEN
  state, UDP with no state, listening-only filter). lint clean, 12631
  passing. Next (B2): the `pytcp` argparse multitool (`daemon`/`ss`/`link`/
  `addr`/`route`/`neigh`/`sysctl`) + pure golden-tested formatters.

- **2026-06-01** — B2 (the `pytcp` CLI multitool) core complete in two
  commits. **B2a (formatters):** `pytcp/cli/cli__format.py` — pure,
  daemon-free `format_socket_table` (`ss -tuln`), `format_neighbor_table`
  (`ip neighbor show`), `format_route_table` (`ip route show`),
  `format_sysctl` (`key = value`); 4 golden tests pin the exact rendered
  output. **B2b (dispatcher):** `pytcp/cli/__main__.py` — the argparse
  multitool with `ss` (`-t`/`-u`/`-l`/`-4`/`-6`), `route`, `sysctl`
  (read / `key=value` set / list-all), and `daemon start`; each
  observation subcommand opens a short-lived `ClientStack`, calls the API,
  and renders via the formatters. Added `pytcp = "pytcp.cli.__main__:main"`
  to `[project.scripts]` (verified the console entry point runs). 3
  integration tests run `main()` against the live IPC server (ss lists a
  listening socket, route matches the formatter, sysctl lists entries).
  lint clean, 12638 passing. Deferred to a B2 follow-up: `neigh` / `addr`
  / `link` subcommands and `daemon stop` (pidfile + SIGTERM).
- **2026-06-01** — B2 follow-up complete, **closing B2 / Track B**.
  **B2c (neigh / addr / link):** `cli__format.InterfaceView` + `format_addr`
  (`ip addr show`) / `format_link` (`ip link show`); `pytcp neigh`
  aggregates `list_neighbors` across interfaces, `pytcp addr` / `pytcp
  link` render per-interface link + address views. 2 golden + 3
  integration tests (the integration test installs real ARP/ND caches —
  the harness mocks them). **B2d (daemon stop):** `run_daemon` gains a
  `pidfile_path` (written on start, removed on exit) + `default_pidfile_
  path()` / `remove_pidfile()`; `pytcp daemon stop` reads the pidfile and
  sends SIGTERM, cleaning up a stale pidfile when the process is gone. 4
  unit tests (SIGTERM sent, stale-pidfile removal, no-pidfile, helper
  round-trip). lint clean, 12647 passing. **Track B is complete**: `pytcp`
  is a full operator multitool (`ss` / `route` / `sysctl` / `neigh` /
  `addr` / `link` / `daemon start` / `daemon stop`).

- **2026-06-01** — A3.1 / A3.2 (non-blocking readiness baseline). **A3.1
  prototype validated:** filling a socketpair end's `SO_SNDBUF` with
  filler makes it read *not*-writable via `select`, and draining the far
  end flips it writable — the connect-edge mechanism A3.3 will use is
  feasible on this platform. **A3.2 baseline:** the established-socket
  readiness foundation already works through the drop-in with zero
  production change — the data fd is a real kernel socketpair end, so
  `setblocking(False)` makes `recv` raise `BlockingIOError`, `select`
  reports not-readable with no data and readable once a peer segment
  arrives, and the bridge backpressure gives honest data-phase
  writability. Pinned by an integration test (non-blocking recv EAGAIN +
  select read-readiness on driven data). Added `Socket.connect_ex`
  (returns the errno instead of raising; 0 on success), tested via a
  driven handshake. The genuinely new daemon-side work — non-blocking
  connect (A3.3, EINPROGRESS + worker thread + filler drain on success +
  SO_ERROR) and accept readiness (A3.4) — remains. lint clean, 12649
  passing.

- **2026-06-02** — B2 follow-up: `pytcp daemon status`. Reports whether
  the daemon is running (pidfile present + the recorded pid alive via a
  null-signal probe) and, when the control socket is reachable, a summary
  of the stack's interface addressing state (`format_addr`) plus the route
  and socket counts — so an operator can see what the stack autoconfigured
  to. Exit 0 when running, 3 (LSB "program is not running") when not; a
  running-but-unreachable control socket still reports the pid and exits 0.
  Factored the pidfile read out of `daemon stop` into a shared
  `_read_pidfile` helper. 3 unit tests (no-pidfile, stale-pidfile,
  running-but-unreachable) + 1 integration test (running + reachable
  renders the stack summary against the live IPC server). lint clean.
- **2026-06-13** — B2 follow-up: `pytcp ping` (commit `d31545d0`). A
  Linux-`ping`-style subcommand over the `pytcp.socket` drop-in
  (unprivileged ICMP datagram socket, raw fallback / `-e` force; `-c -i
  -W -s`; v4/v6 by destination; hostname via the daemon DNS resolver).
  The ICMP Echo engine is extracted into a shipped, daemon-independent
  `pytcp/cli/cli__ping.py` (wire helpers + an injectable-socket
  `run_ping` generator yielding `PingOutcome` + plain formatters), shared
  with `examples/ping.py` — the example is now a thin coloured Click
  veneer over the engine (~150 dup lines removed). 20 unit tests (RFC
  1071 checksum, RFC 792/4443 profile + request wire format, reply
  parsing, the loop over a fake socket, formatters, two `main(["ping",
  …])` command tests with the socket faked). lint clean.
- **2026-06-29** — A3.3 non-blocking connect (two commits: `d66d45ec`
  SO_ERROR constant + the previously-missing `SolSocketOption` parity
  test; `d23752a7` the core). Re-verified the filler trick empirically
  before building (fresh socketpair end writable; prime 4096 →
  not-writable; drain 4096 → writable), settling a doc-vs-recon conflict
  in the doc's favour — the data fd is *not* honestly selectable on the
  connect edge, the trick is required. Landed exactly the §8 design:
  client `ClientTcpSocket.connect_start` shrinks `SO_SNDBUF` + fills to
  EAGAIN + sends a `connect_start` RPC carrying the filler length;
  drop-in `Socket.connect` takes this path when non-blocking and raises
  `BlockingIOError(EINPROGRESS)`; daemon `_DaemonSocket.start_connect_async`
  spawns a per-handle worker so the dispatch thread returns at once; the
  worker runs the blocking handshake, drains exactly the filler via the
  new deadline-bounded `SocketBridge.prime_drain` (flips the fd writable
  on success *and* failure), and starts the bridge on success; the
  session intercepts `getsockopt(SOL_SOCKET, SO_ERROR)` to return-and-
  clear the worker-published result. Two integration tests (EINPROGRESS
  + not-writable → SYN-ACK → writable + SO_ERROR==0; EINPROGRESS → RST →
  writable + SO_ERROR==ECONNREFUSED), neither needing a background
  connect thread. Deferred-with-rationale: `SO_SNDBUF` stays shrunk
  post-connect (invisible through the public getsockopt, which hits the
  stack socket; the bridge drains continuously). lint clean, 111 ipc
  integration + 464 socket unit passing. Remaining: A3.4 + P2.
- **2026-06-29** — A3.4 non-blocking accept (commit `95142ec2`). Landed a
  *cleaner* mechanism than the §8 spec's polling-watcher + queue: the
  in-daemon `TcpSocket` listener **already** maintains accept-readiness as
  a level-triggered OS eventfd (`fileno()`) — the FSM signals it readable
  when `tcp__fsm__syn_rcvd` queues a child and `accept()` drains it when
  the queue empties. So instead of a watcher thread duplicating the accept
  queue, the daemon `dup()`s that eventfd at `listen()` and passes it to
  the client via SCM_RIGHTS; dup'd eventfds share the kernel counter, so
  the daemon's accept-side drain reflects on the client fd with **no
  watcher thread and no handle-table locking** (verified empirically:
  signal → readable, drain → not-readable across dups). `listen` is now
  fd-bearing; `ClientTcpSocket.fileno()` returns the eventfd for a
  listener (data channel otherwise); `accept_take` is a non-blocking
  dispatch-thread accept returning the child or `BlockingIOError(EAGAIN)`,
  sharing child-building with blocking `_accept`. The `handle()` fd-pass
  contract widened to `socket.socket | int | None` so the raw eventfd
  rides SCM_RIGHTS (it cannot be socket-wrapped — ENOTSOCK). Integration
  test proves empty→EAGAIN/not-readable → driven passive handshake →
  readable + child(peer) → not-readable, no background accept thread. 112
  ipc integration + 110 ipc unit + 464 socket unit passing. Only P2
  (asyncio proof point) remains on the A3 track.
- **2026-06-29** — P2 asyncio proof point (commit `62b98dec`), closing
  the A3 non-blocking readiness track. Two integration tests drive
  asyncio's low-level primitives against daemon-backed drop-in sockets
  with the synthetic wire as peer: `loop.sock_connect`+`sock_sendall`+
  `sock_recv` echo (exercises A3.3 + A3.2) and `loop.sock_accept`+
  `sock_recv` (exercises A3.4). The asyncio loop runs on a background
  thread — its selector polls the drop-in's real data-channel fd /
  accept-readiness eventfd in real time — while the main thread plays
  the wire. Verified asyncio's `loop.sock_*` are duck-typed (only
  `_check_ssl_socket` + a debug `gettimeout` check), so the drop-in
  `Socket` works where the stubs name `socket.socket` (bridged with a
  documented `cast`). No source change — a pure proof over the
  A3.2/A3.3/A3.4 surface. 114 ipc integration passing, deterministic
  across repeat runs. **The A3 track (non-blocking / asyncio readiness)
  is complete.** Remaining daemon-track work is the long-tail
  follow-ups in §8 (TLS, datagram asyncio, sendmsg/recvmsg cmsg on the
  drop-in, every setsockopt honored, B2 output-parity polish).
- **2026-07-01** — Datagram-endpoint asyncio (one §8 long-tail item
  closed). Tests-first integration proof that
  `loop.create_datagram_endpoint(protocol_factory, sock=<drop-in UDP>)`
  works over the daemon: a peer datagram on the synthetic wire reaches
  the `DatagramProtocol.datagram_received` (data + sender address), and
  the protocol's `transport.sendto` reply reaches the wire addressed to
  the peer (`test__ipc__asyncio_datagram.py`, mirrors the streams proof —
  asyncio loop on a background thread, wire driven from the main thread).
  The proof drove out a real stdlib-parity bug: the stack socket's
  `getpeername()` returned `('0.0.0.0', 0)` for an unconnected socket
  instead of raising `OSError(ENOTCONN)`, so asyncio's datagram transport
  (which calls `getpeername()` to detect a connected socket) sent via
  `send()` with no destination and the reply was silently dropped. Fixed
  in `runtime/socket/__init__.py::getpeername` (raise `ENOTCONN` when the
  remote port is zero) with a base-socket unit test. lint clean.
- **2026-07-01** — `sendmsg` cmsg on the drop-in (one §8 long-tail item
  closed). The drop-in `Socket` gained `sendmsg` (datagram; it already had
  `recvmsg`), and a per-send IP_TOS (IPv4) / IPV6_TCLASS (IPv6) ancillary
  control message now round-trips end-to-end: drop-in `Socket.sendmsg` →
  `ClientUdpSocket.sendmsg` (frames the cmsg via `encode_dgram`) → the
  datagram bridge `_pump_tx` (routes a framed cmsg through the stack
  socket's `sendmsg` instead of the cmsg-less `sendto`) → `UdpSocket.sendmsg`,
  which now honours the per-send TOS byte by overriding the outbound DSCP +
  ECN (the send-direction mirror of the IP_RECVTOS `recvmsg` path; flips
  that method's `# Phase 2` marker for TOS — IP_TTL / IP_PKTINFO remain
  deferred). `send` / `sendto` were refactored into thin wrappers over
  private `_send` / `_sendto` helpers taking explicit dscp/ecn, so the
  public overrides keep their signatures. Tests-first: a stack unit test
  (IP_TOS cmsg → outbound DSCP/ECN; unknown cmsg ignored), a bridge unit
  test (framed cmsg routes to `sendmsg`), and two daemon integration tests
  (`ClientUdpSocket` + drop-in `Socket` sendmsg IP_TOS → wire DSCP). lint
  clean.

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

---

## 8. Remaining work (deferred) — resume notes

Everything through A3.2 is shipped + pushed (`origin/PyTCP_3_0_8`, 25
commits, head `20d2f3ec`). What's left is the fragile non-blocking
`connect`/`accept` edge + the asyncio proof. This section is the durable
spec so the work can resume cold.

### A3.3 — non-blocking connect (EINPROGRESS + worker + filler + SO_ERROR)

**SHIPPED 2026-06-29** (commits `d66d45ec` + `d23752a7`) — the spec below
was implemented as written; see the 2026-06-29 progress-log entry above.

The hardest, most fragile piece. Mechanism (the A3.1-validated filler
trick; see §7 "the trick"):

1. **New constant.** `SO_ERROR` is **missing** from
   `pytcp.runtime.socket` — add it to the `SolSocketOption` IntEnum + a
   bare `SO_ERROR = SolSocketOption.SO_ERROR` alias (Linux value 4), per
   `enums.md` §2.2 stdlib-parity pattern. (`SOL_SOCKET`=1, `SO_SNDBUF`=7
   already exist.)
2. **Client prime (drop-in `Socket.connect`, non-blocking path =
   `self._timeout == 0`).** Set a small `SO_SNDBUF` on the data fd, then
   `send` filler until `BlockingIOError` (count `M` = bytes written so the
   fd reads *not*-writable). Issue a **`connect_start`** RPC carrying
   `{address, filler_len: M}` (a synchronous `socket_call` that the daemon
   answers *immediately* — no need for the A1 mux client), then raise
   `BlockingIOError(EINPROGRESS)`.
3. **Daemon `connect_start`** (`ipc__socket_session.py`, add to
   `_ALLOWED_METHODS`, stream-only): spawn a per-handle **connect worker
   thread** and return `None` at once. `_DaemonSocket` gains
   `_so_error: int | None`, `_connect_thread`, `start_connect_async`,
   `take_so_error`.
4. **Worker `_run_connect(address, filler_len)`:** `try
   self._socket.connect(address)` (blocks until handshake/refuse) capturing
   `errno` (0 on success); then **drain exactly `filler_len` bytes** from
   the bridge's `data_end` (new `SocketBridge.prime_drain(n)` — read-and-
   discard, bounded by a wall-clock deadline so a lying client can't spin)
   to flip the client fd writable on *both* success and failure; set
   `_so_error`; on success `start_bridge()` (the TX pump then forwards real
   data *after* the filler the worker already consumed — no double-reader).
5. **`getsockopt(SO_ERROR)` interception:** in the session `getsockopt`
   case, when `level==SOL_SOCKET and optname==SO_ERROR` and a pending
   `_so_error` exists, return-and-clear it (BSD read-once); else fall
   through to the stack socket.
6. **Client/drop-in:** `ClientTcpSocket.connect_start(address, filler_len)`;
   `Socket.connect_ex` non-blocking path returns `EINPROGRESS` first then
   reads `SO_ERROR`; `Socket.getsockopt(SO_ERROR)` returns the cached value.

**Tests (integration, TcpTestCase):** non-blocking connect →
`BlockingIOError(EINPROGRESS)`, `select([],[s],[],0)` *not* writable;
drive SYN-ACK + advance → writable, `getsockopt(SO_ERROR)==0`; refused
(drive RST) → writable, `SO_ERROR==ECONNREFUSED`.

**Risk/notes:** `SO_SNDBUF` accounting is platform-dependent (validated on
this box in the A3.1 prototype: prime 4096 → not-writable, drain 4096 →
writable). The bridge MUST strip exactly the filler before real data.
Watch races between worker, prime_drain, and the bridge pumps. Fallback if
the filler trick proves too fragile: a two-fd readiness model (data fd +
readiness eventfd) — needs `ipc__fdpass` generalised to an fd array; bigger
change, flagged not-default.

### A3.4 — non-blocking accept (listener readiness + accept_take)

**SHIPPED 2026-06-29** (commit `95142ec2`) — implemented with a *simpler*
mechanism than the sketch below: rather than a polling watcher that
duplicates the accept queue + writes a separate eventfd, the daemon
shares the listener's **existing** stack-socket accept-readiness eventfd
(`TcpSocket.fileno()`) with the client by `dup()`+SCM_RIGHTS at
`listen()`; the shared kernel counter means the daemon's accept-side
drain flips the client fd not-readable with no watcher thread. See the
2026-06-29 progress-log entry. The original sketch is retained below for
context.

Listener fd must be **readable** when a child is queued. Daemon: on a
non-blocking listener, a watcher polls `TcpSocket.accept`, builds the child
socketpair+bridge, queues `(child_handle, peer, client_end)`, and writes a
listener **eventfd** → listener fd readable. New `accept_take` socket
method pops one queued child (fd via SCM_RIGHTS). Client non-blocking
`accept`: not-readable → `BlockingIOError(EAGAIN)`; else `accept_take`.
Blocking `accept` keeps the existing RPC. Tests:
`test__ipc__nonblocking_accept.py`.

### P2 — asyncio proof point

**SHIPPED 2026-06-29** (commit `62b98dec`) — realized as two focused
proofs (asyncio client echo + asyncio server accept) driving asyncio's
low-level `loop.sock_*` primitives against the drop-in over the
synthetic wire, rather than a full two-asyncio-endpoints echo (the mock
harness has no loopback for a same-stack client+server). The A3 track is
complete; see the 2026-06-29 progress-log entry.

A real `asyncio` TCP echo client+server over the daemon (the
`sys.modules['socket'] = pytcp.socket` monkeypatch path + an event loop),
once A3.3/A3.4 land. Honest bar = a *relevant subset* of CPython
`Lib/test/test_socket.py` (INET/INET6 TCP+UDP client/server + timeouts +
common options), not a turnkey gate (see §7).

### Long-tail follow-ups (tracked, out of A3 scope)

TLS over the drop-in; every `setsockopt` *honored* (not merely
accepted); errno-exactness sweep; B2 polish (`pytcp addr` JSON/`-j`,
column alignment parity with real `ip`/`ss`). (Datagram-endpoint asyncio
— **done** 2026-07-01; `sendmsg`/`recvmsg` cmsg on the drop-in `Socket` —
**done** 2026-07-01; see the §6 phase log.)

## 9. Live verification — async FTP over a real stack (2026-06-30)

The asyncio integration (streams + `start_server`, control + PASV-data
connections) was confirmed **live** end-to-end: the `examples/ftp_server__async.py`
async FTP server, run over a real PyTCP daemon on a TAP interface, served a
full session to a real `ftplib` client over the wire. The committed example
needed **zero code changes**.

### Reproducible recipe (point-to-point TAP, static address)

`pytcp stack start` autoconfigures via DHCPv4, so with no DHCP server on the
link give the daemon a **static** address via `run_daemon`. The stack and the
host sit on opposite ends of one TAP's L2 segment (no bridge needed).

```bash
# 1. Host side of the link (the interface name MUST start with tap/tun).
ip tuntap add name tap8 mode tap
ip addr add 192.168.100.1/24 dev tap8
ip link set dev tap8 up

# 2. Stack side: a daemon with a static host address on tap8.
python -c 'from net_addr import Ip4IfAddr; \
  from pytcp.daemon.daemon import run_daemon; \
  run_daemon(socket_path="/tmp/pytcp.sock", interfaces=["tap8"], \
             ip4_host=Ip4IfAddr("192.168.100.2/24"), ip6_support=False)' &
# wait for "Interface tap8 listening on unicast IPv4 addresses: 192.168.100.2"
ping -c1 192.168.100.2          # sanity: ICMP over the TAP

# 3. The async FTP server against that daemon, and a real client.
PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_server__async.py \
    --host 192.168.100.2 --root /srv/ftp &
python -c 'import ftplib; f=ftplib.FTP(); f.connect("192.168.100.2",21); \
  f.login("anonymous","x"); print(f.pwd()); f.retrlines("LIST"); \
  buf=bytearray(); f.retrbinary("RETR readme.txt", buf.extend); print(buf); f.quit()'
```

### Result (confirmed)

- `ping 192.168.100.2` → 0% loss (ICMP over the real TAP, not loopback).
- Raw TCP connect to `192.168.100.2:21` → real 3-way handshake accepted.
- Full `ftplib` session: `220` greeting, `USER`/`PASS` login, `SYST`, `PWD`,
  `LIST` (over a **PASV data connection** — a second TCP conn to the stack),
  `RETR` of a text file **and** a 4096-byte binary (**SHA-256 byte-exact**),
  `CWD` into a subdir, `SIZE`, `QUIT`. `>>> LIVE FTP RESULT: PASS`.

This upgrades the P2 / streams proofs (§6, mock-wire harness) to a real-stack
confirmation: high-level asyncio (`start_server` + `StreamReader`/`Writer` +
multi-connection PASV) genuinely works over the PyTCP daemon.

### Setup gotchas (so the next run avoids them)

- The interface name **must** start with `tap`/`tun` (`_resolve_interface`
  rejects others) — `ftpXXX` fails.
- Host and stack addresses must share the subnet; a leftover second interface
  carrying the same `/24` steals the route (`ip neigh` shows `FAILED` on the
  wrong device).
- Don't `pkill -f <launcher>` from a shell whose own command line contains
  that string — it kills the shell. Track the daemon by PID instead.

### Two-stack async client ↔ async server (2026-06-30)

The **high-level asyncio client** path (`asyncio.open_connection(sock=...)` over
a `loop.sock_connect`'d PyTCP socket) was confirmed **live** with the two
examples talking to each other over real PyTCP stacks — `examples/
ftp_client__async.py` driving `examples/ftp_server__async.py`.

At the time, PyTCP had **no intra-stack loopback**: a socket connecting to its
own stack's IP sent the SYN out the interface and nothing looped it back, so
server + client on one stack (to `192.168.100.2` from `.2`) hung. The
confirmation therefore used **two independent stacks on one isolated L2 bridge**.
(A real loopback interface has since landed — see the single-stack subsection
below — so the two-stack setup is **no longer required**; it is kept here as the
historical record.)

```bash
# Isolated bridge (do NOT reuse a bridge that carries a physical NIC).
ip link add name brftp type bridge && ip link set brftp type bridge stp_state 0
ip link set brftp up
ip tuntap add name tap20 mode tap && ip link set tap20 master brftp && ip link set tap20 up
ip tuntap add name tap21 mode tap && ip link set tap21 master brftp && ip link set tap21 up

# Two daemons, static addresses + explicit MACs. (The name-derived MAC needs a
# single hex char at name[3:5], e.g. 'tap7'; multi-digit names like 'tap20'
# require an explicit mac_address — passed here.)
python -c 'from net_addr import Ip4IfAddr, MacAddress; from pytcp.daemon.daemon \
  import run_daemon; run_daemon(socket_path="/tmp/pytcp_srv.sock", \
  interfaces=["tap20"], mac_address=MacAddress("02:00:00:00:00:02"), \
  ip4_host=Ip4IfAddr("192.168.100.2/24"), ip6_support=False)' &
python -c 'from net_addr import Ip4IfAddr, MacAddress; from pytcp.daemon.daemon \
  import run_daemon; run_daemon(socket_path="/tmp/pytcp_cli.sock", \
  interfaces=["tap21"], mac_address=MacAddress("02:00:00:00:00:03"), \
  ip4_host=Ip4IfAddr("192.168.100.3/24"), ip6_support=False)' &

# Server on stack .2, client on stack .3 -> connects to .2 over the bridge.
PYTCP_DAEMON_SOCKET=/tmp/pytcp_srv.sock ./examples/ftp_server__async.py \
    --host 192.168.100.2 --root /srv/ftp &
PYTCP_DAEMON_SOCKET=/tmp/pytcp_cli.sock ./examples/ftp_client__async.py \
    --host 192.168.100.2 --get pub/payload.bin > got.bin
```

**Result (confirmed):** `LIST`, `RETR` of a text file, and `RETR` of an
8192-byte binary (**SHA-256 byte-exact**) — `TWO-STACK ASYNC FTP: PASS`. The
server stack's TCP-session log shows both connections between the stacks: the
control channel `192.168.100.2/21 <-> 192.168.100.3/<ephemeral>` and the PASV
data channel `192.168.100.2/<ephemeral> <-> 192.168.100.3/<ephemeral>`.

This closes the last high-level-surface gap: both directions of the asyncio
streams API (`start_server` **and** `open_connection`) are now proven live over
real PyTCP stacks, including multi-connection PASV data transfer.

### Single-stack async client ↔ server over loopback (2026-07-01)

With the loopback interface shipped (`docs/refactor/loopback_interface.md`,
phases P0–P6), the two-stack bridge is no longer needed: a single PyTCP daemon
can host both the async FTP server and the client, with traffic looping inside
the stack over `lo`. Confirmed **live** on one daemon:

```bash
# One TAP just so the daemon has a device to boot on; loopback traffic never
# touches it. Give the daemon a static address (no DHCP server on the link).
ip tuntap add name tap8 mode tap
ip addr add 192.168.100.1/24 dev tap8 && ip link set dev tap8 up
python -c 'from net_addr import Ip4IfAddr; from pytcp.daemon.daemon import \
  run_daemon; run_daemon(socket_path="/tmp/pytcp.sock", interfaces=["tap8"], \
  ip4_host=Ip4IfAddr("192.168.100.2/24"), ip6_support=False)' &
# Boot log now shows: "Interface lo listening on unicast IPv4 addresses: 127.0.0.1"

# Server AND client on the SAME daemon — both the own routable IP and 127.0.0.1.
PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_server__async.py \
    --host 192.168.100.2 --root /srv/ftp &      # (or --host 127.0.0.1)
PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_client__async.py \
    --host 192.168.100.2 --get blob.bin > got.bin
```

**Result (confirmed):** `LIST` + `RETR` of an 8192-byte binary, **SHA-256
byte-exact**, for BOTH the stack's own routable address (`192.168.100.2 → .2`)
AND the pure loopback address (`127.0.0.1 → 127.0.0.1`), on a single stack with
no bridge and no second daemon. Both the FTP control connection and the PASV
data connection loop internally through `lo`. The `127.0.0.1` case is
conclusive — that address cannot traverse the TAP wire, so it must have looped
inside the stack, and it completed instead of hanging.

This retires the two-stack workaround above for same-host async testing.
