# Real-TAP end-to-end smoke suite — scope

| Field    | Value                                                              |
|----------|-------------------------------------------------------------------|
| Kind     | Test-infrastructure proposal (scoping doc, not yet implemented)    |
| Target   | A small, root-gated smoke suite that runs the real stack over an actual TAP |
| Status   | **Phase 1 shipped** — the IPv4 smoke suite (5 tests) runs green over a real tap; IPv6 variant deferred (§7b) |
| Precedent| `tests/integration/ipc/` (real `IpcServer` + drop-in), `tests/integration/loopback/` |

---

## §1. Why — the gap this closes

The ~11k-test suite is layered, and every layer stubs the OS edge:

- **Unit** — isolated value types / wire codecs.
- **Wire-level integration** (the bulk, incl. all the router / multicast
  work) — drives an RX frame into a real `PacketHandler` and asserts on
  emitted frames + stat counters, but **`TxRing` / `ArpCache` /
  `NdCache` are `create_autospec` mocks and the clock is a
  `FakeTimer`.** Protocol *logic* is pinned; the real runtime is not.
- **IPC / daemon integration** (`tests/integration/ipc/`) — a real
  `IpcServer` + the real stdlib-`socket` drop-in against a **mocked**
  UDP runtime (`UdpTestCase`). End-to-end for the *socket → daemon*
  boundary; still no real interface.

Nothing in the automated suite exercises the parts those mocks replace:

1. **Real `/dev/net/tun` I/O** — `os.read` / `os.write` on the tap fd
   (`stack.initialize_interface__tap`, `stack/__init__.py:1152`).
2. **The real `TxRing`** actually dispatching frames onto the wire (the
   wire tests assert against a mocked `enqueue`).
3. **The real `RxRing`** parsing frames that arrived from an external
   source rather than hand-injected `PacketRx`.
4. **Real threading + real timers** — the `Timer` subsystem firing on
   wall-clock deadlines (RTOs, ARP/ND aging, IGMP/MLD query intervals),
   under the real thread interleaving `FakeTimer` hides.
5. **Real neighbor resolution** — ARP / ND probe → reply → cache under
   live timing, feeding a real TX.

A **smoke** suite (not exhaustive) that boots the daemon on an actual
TAP and does a handful of end-to-end operations catches the class of
bug the mocked layers structurally cannot: a frame that assembles
correctly but never leaves the ring, a timer that never fires, a
threading deadlock, a `/dev/net/tun` framing mismatch.

## §2. Non-goals

- **Not a replacement** for the wire-level integration tests — those
  stay the exhaustive protocol/FSM/stat-counter coverage. The real-TAP
  suite is a thin end-to-end confidence layer, deliberately small.
- **Not run in the normal `make test`** — it needs `CAP_NET_ADMIN`
  (create a tap, open `/dev/net/tun`), so it is opt-in and skipped by
  default (§6).
- **No interop with third-party stacks on the wire** as a hard
  requirement — the peer is the test process itself (§4). A future
  extension could add a real-Linux-peer namespace, but that is out of
  scope here.
- **No performance / throughput / soak** — smoke means "does the real
  path work at all," a few packets each.

## §3. What it covers — the smoke inventory

Keep it to ~6 tests. Each exercises the real ring + real threads;
several also exercise real timers.

| # | Test | Real path exercised |
|---|------|---------------------|
| 1 | **Daemon boots on a real tap** — start on `tapNN` with a static IPv4+IPv6 address, reach readiness | `/dev/net/tun` open, thread spawn, `daemon_readiness` signal |
| 2 | **ARP round trip** — peer sends an ARP Request for the stack's IPv4; assert a real ARP Reply is read off the wire | RxRing parse + ArpCache + real TxRing → tap fd |
| 3 | **ICMPv4 Echo** — peer sends an Echo Request; assert an Echo Reply on the wire | full RX→TX through the real rings |
| 4 | **ICMPv6 ND + Echo** — peer sends a Neighbor Solicitation / Echo Request; assert NA / Echo Reply | IPv6 RX/TX, solicited-node multicast RX |
| 5 | **UDP echo end-to-end** — a drop-in `ClientStack` UDP socket sends to the peer; peer reads it off the wire and replies; client `recv`s it | socket → daemon → stack → tap → **wire** → tap → stack → socket, real threads |
| 6 | **Timer-driven** — e.g. an ARP cache entry ages out, or a UDP send to an unresolved next hop resolves via a real ARP probe→reply→flush | the real `Timer` subsystem firing on wall-clock |

**Stretch (optional, second phase):** a two-tap variant that boots
*two* daemons on one bridge and forwards / IGMP-joins between them —
the only way to validate the M5 querier + multicast forwarding over a
real interface (a real IGMP Report / General Query on the wire, a real
replicated datagram). Gated the same way; kept separate so the core
smoke suite stays minimal.

## §4. The peer mechanism — how the test becomes "the wire"

A TAP interface's fd is the *external network* from the kernel's view:
the daemon holds it, `write(fd, frame)` injects a frame as if received,
`read(fd)` yields a frame the kernel transmitted. The test needs to be
the thing on the other side.

**Recommended: raw `AF_PACKET` bound to the tap interface.** The test
opens `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` bound to `tapNN`:

- test `sendto(frame)` → kernel transmits out `tapNN` → daemon
  `read(tap_fd)` receives it (test → daemon RX);
- daemon `write(tap_fd, reply)` → kernel RX on `tapNN` → test
  `AF_PACKET recv` yields it (daemon TX → test).

No bridge, no second tap. **One spike is required first** to confirm
the RX/TX directions behave as expected for a tap (tap TX/RX visibility
on `AF_PACKET` has a couple of kernel-version subtleties); if it does
not, fall back to:

**Fallback: two taps on a bridge.** `br0` + `tap-pytcp` (daemon) +
`tap-peer` (the test holds this fd directly). Frames the daemon writes
traverse the bridge to `tap-peer`, readable off its fd; the test writes
to `tap-peer`, they reach the daemon. Matches the existing
`make bridge` / `make tap7` topology exactly, at the cost of managing a
bridge + two taps per test.

Either way the peer is **the test process assembling/parsing raw
Ethernet frames with the existing `net_proto` assemblers/parsers** — no
third-party stack, fully deterministic frame content.

## §5. Harness — `RealTapTestCase`

A new base at `packages/pytcp/pytcp/tests/lib/real_tap_testcase.py`,
sibling to `network_testcase.py` but with **no mocks and a real
clock**:

```python
@unittest.skipUnless(_real_tap_enabled(), "real-TAP suite: set PYTCP_REAL_TAP=1 and run as root")
class RealTapTestCase(unittest.TestCase):
    # setUp:
    #   - allocate a unique tap name (tap-<pid>-<n>) to avoid collisions
    #   - create it (ioctl TUNSETIFF on /dev/net/tun, or `ip tuntap add`),
    #     set it up (SIOCSIFFLAGS / `ip link set up`)
    #   - boot the real daemon on it: run_daemon(interfaces=[tap], ...)
    #     in a background thread OR a subprocess, with a static address
    #     (skip DHCP for determinism)
    #   - open the peer (AF_PACKET bound to the tap)
    #   - block until daemon readiness (reuse the daemon_readiness signal)
    # helpers:
    #   _peer_send(frame: bytes)                       # inject onto the wire
    #   _peer_recv(*, timeout, match=...) -> bytes     # bounded real-time wait
    #   _client() -> ClientStack                       # the drop-in over IPC
    #   frame builders reuse EthernetAssembler / Ip4Assembler / ...
    # tearDown (must run even on failure — addCleanup):
    #   - stop the daemon, join the thread / kill the subprocess
    #   - close the AF_PACKET socket + tap fd
    #   - delete the tap (+ bridge in the fallback topology)
```

Design constraints unique to this suite (they invert the wire-level
harness rules deliberately):

- **Real time, bounded.** No `FakeTimer`. Every wait is a real timeout
  (`_peer_recv(timeout=2.0)`); a test never blocks unbounded. This is
  the one PyTCP test surface where `time.sleep` / real clocks are
  legitimate — document the exception loudly.
- **Robust teardown via `addCleanup`**, registered *immediately* after
  each resource is created, so a mid-setUp failure still deletes the
  tap. A leaked tap/bridge across tests is the failure mode to design
  against (name uniqueness + cleanup).
- **Daemon in a subprocess vs. a thread.** A subprocess (`python -m
  pytcp.daemon -i tap …`) is the more faithful "real" boot and isolates
  the daemon's global stack state from the test process; a background
  thread is lighter but shares module-level `stack` state (the
  snapshot/restore concern). **Recommend subprocess** for fidelity and
  isolation; the readiness signal + AF_UNIX socket path make it
  addressable.

## §6. CI gating

The suite must **skip cleanly** where it cannot run:

- `@skipUnless(os.geteuid() == 0 and os.environ.get("PYTCP_REAL_TAP") == "1", …)`
  — needs root *and* an explicit opt-in, so a normal `make test` (or a
  root CI job that did not opt in) skips every test with a clear reason.
- A dedicated make target: `make test-realtap` sets `PYTCP_REAL_TAP=1`
  and runs only `tests/integration/real_tap/`.
- A separate, privileged CI job (a container with `--cap-add=NET_ADMIN`
  and `/dev/net/tun`) runs `make test-realtap`; the normal job never
  does. Document the container requirements in the Makefile target.

The suite is therefore **advisory in CI** (a privileged job) and
**on-demand locally** (`sudo make test-realtap`), never part of the
default gate — matching how `make bridge` / `make tap7` are already
manual sudo steps.

## §7. Risks & open questions (resolve in a spike before building)

1. **AF_PACKET tap direction visibility** (§4) — confirm the test sees
   daemon TX and can inject daemon RX on a single tap; else adopt the
   bridge fallback. *This is the one must-verify item.*
2. **Daemon lifecycle from a test** — `run_daemon` is written for a CLI
   `main`; confirm it stops cleanly on a signal / stop event so a
   subprocess can be torn down deterministically (not left as a zombie
   holding the tap).
3. **Static addressing path** — the smoke tests want a fixed address
   (no DHCP round trip) for determinism; confirm `run_daemon` / the
   daemon args support a static IPv4+IPv6 without a DHCP server on the
   wire (`python -m pytcp.daemon` static-address mode exists per the
   3.0.8 CHANGELOG).
4. **Readiness handshake** — reuse whatever `test__ipc__daemon_readiness`
   waits on so the peer does not race the daemon's bring-up.
5. **Free-threading** — under a no-GIL interpreter the real-thread
   interleaving here is exactly what the wire tests cannot exercise;
   this suite is the natural home for a future concurrency smoke, but
   keep the first cut single-flow.

## §7a. Phase-0 spike — DONE (mechanism validated)

Two throwaway spikes confirmed the approach end-to-end; every §7 risk
is resolved:

1. **AF_PACKET-on-tap is viable (risk #1).** A single `AF_PACKET`
   socket bound to the tap both sees the daemon's TX (as an incoming
   frame, `sll_pkttype=1`) and injects the daemon's RX. **No bridge and
   no second tap** — the §4 "recommended" path stands; the fallback is
   unnecessary.
2. **Real daemon on a real tap does a real ARP round trip.** A
   subprocess `run_daemon(socket_path=…, interfaces=[tap],
   mac_address=…, ip4_host=Ip4IfAddr("10.0.0.7/24"), ip6_support=False,
   on_ready=<ready-file>)` booted, reached readiness, answered an
   `AF_PACKET`-injected ARP Request (`10.0.0.7 is-at 02:…:07`) read back
   off the wire, and **stopped cleanly on SIGTERM (rc=0)** — resolving
   risks #2 (lifecycle), #3 (static addressing, no DHCP), #4
   (readiness handshake).

## §7b. Phase-1 build — DONE (IPv4 smoke suite green)

Built and validated on a real tap (root + `PYTCP_REAL_TAP=1`):

- **Harness** `packages/pytcp/pytcp/tests/lib/real_tap_testcase.py`
  (`RealTapTestCase`) — persistent tap, subprocess daemon via
  `run_daemon(..., on_ready=<ready-file>)`, `AF_PACKET` peer, real-clock
  bounded `_peer_expect` / `select` waits, `addCleanup` teardown.
- **5 smoke tests**
  `packages/pytcp/pytcp/tests/integration/real_tap/test__real_tap__smoke.py`:
  daemon-boots-and-serves-IPC, ARP request→reply, ICMPv4 Echo→reply,
  UDP-send-resolves-neighbor-via-real-ARP, UDP-echo-round-trip.
  All green (~50 s wall; per-test daemon boot dominates).
- **`make test-realtap`** target (sets `PYTCP_REAL_TAP=1`); the suite
  **skips cleanly** under a normal `make test` (`OK (skipped=5)`), so it
  never breaks the default gate. Lint clean; §7.2 audit clean.

**The suite is IPv4-only.** Two deviations from the §3 inventory,
resolved during the build:

1. **Test 3 (ICMPv6 NS→NA) dropped** — see the IPv6 finding below.
2. **Tap-name prefix** must be `tap…` — `run_daemon`'s
   `_resolve_interface` accepts only `tap` / `tun` name prefixes, so the
   harness names the tap `tap<pid>`.

**IPv6 finding (deferred, worth a follow-up):** booting the daemon with
a **static `ip6_host`** on a router-less tap did **not** reach readiness
within 40 s — the interface logged an *empty* IPv6-unicast list and
`stack.start()` did not complete. A static IPv6 address should not
depend on a router (DAD alone completes in ~1 s), so this looks like a
real bring-up stall on a router-less link, not just slowness. Filed as
the blocker for a dual-stack real-TAP variant; the IPv4 smoke suite is
unaffected. **This is exactly the class of bug the real-TAP layer exists
to surface** — the wire-level tests (mocked clock + injected frames)
cannot see it.

**One refinement the spike surfaced:** the tap must be **persistent**
(`ip tuntap add name <tap> mode tap`, exactly like `make tap7`) so the
daemon attaches it *by name* while the peer uses `AF_PACKET` — the
harness must not itself hold the `/dev/net/tun` fd (that would conflict
with the daemon's attach on a non-multiqueue tap).

**Proven recipe for the harness:** persistent tap via `ip tuntap add`
→ daemon subprocess via `run_daemon(... on_ready=ready-file ...)` →
wait on the ready file → peer via `AF_PACKET` bound to the tap using
the `net_proto` assemblers/parsers → teardown via SIGTERM + `ip tuntap
del`.

## §8. Deliverables & phasing

- **Phase 0 — spike:** ✅ done (see §7a). AF_PACKET chosen; recipe
  proven.
- **Phase 1 — harness + IPv4 smoke (5 tests) + `make test-realtap`:**
  ✅ done (see §7b). Green over a real tap; skips off the default gate.
- **Phase 1 — harness + core smoke (tests 1–6):** `RealTapTestCase`,
  the `make test-realtap` target, the skip gating, and the six tests in
  §3. This is the shippable unit.
- **Phase 2 — router/multicast stretch (optional):** the two-tap
  two-daemon variant validating unicast forwarding + an IGMP/MLD
  join / General Query / replicated multicast datagram on a real wire —
  the only end-to-end proof of the 3.0.9 router work.

Phase 1 is the recommended cut: ~6 tests, one harness, one make target,
gated off by default. It closes the "does the real path work at all"
gap without touching the exhaustive wire-level suite.

## §9. What it will and will not prove

**Will:** the real `/dev/net/tun` read/write framing is correct; the
`TxRing` actually transmits; the `RxRing` parses real inbound frames;
the `Timer` subsystem fires on wall-clock deadlines; the threaded
daemon boots, serves the drop-in socket end-to-end, and shuts down
cleanly.

**Will not:** replace protocol-conformance coverage (the wire tests
own that); prove interop with real-world routers/hosts (the peer is
PyTCP's own frame codec); measure performance; or exhaustively cover
every protocol path (smoke = a representative few).
