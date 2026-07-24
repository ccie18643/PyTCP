# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyTCP is a pure Python TCP/IP stack (Python 3.14+) built on TAP/TUN interfaces. It implements Ethernet through TCP/UDP with zero runtime dependencies (stdlib only). The project is structured as three independent packages: `net_addr`, `net_proto`, and `pytcp`.

## Project North Star

PyTCP's goal is to be a pure-Python TCP/IP stack that is **feature-equivalent to the Linux kernel network stack**, in three phases:

- **Phase 1 (current):** host-stack parity. Default-configured Linux host coverage — every protocol mechanism a Linux host runs by default.
- **Phase 2 (future):** router-grade parity. Full forwarding plane: FIB, IP forwarding, ICMP Redirect generation, PMTU advertising on transit, RFC 1812 router requirements, IGMP/MLD querier role.
- **Phase 3 (future):** kernel/userspace boundary. PyTCP becomes a self-contained "kernel" exposing a small Linux-mirrored set of user-facing APIs. Everything else is internal to the stack. Consumers — tests, examples, CLI tools, eventually external applications — interact with PyTCP only through these surfaces, the way a Linux process talks to its kernel.

  | PyTCP API | Plane | Linux equivalent |
  |-----------|-------|------------------|
  | BSD-style `socket()` factory + methods | Data | `socket(2)` |
  | `pytcp.stack.sysctl` registry | Protocol-policy control | `/proc/sys/net/` |
  | Link API (interface up/down/MTU/MAC) | Link control | `ip link` / RTNETLINK `RTM_NEWLINK` |
  | Address API (assign / remove IPv4 / IPv6 host per interface) | Network-layer control | `ip addr` / `RTM_NEWADDR` |
  | Route API (add / remove / list routes, gateways) | Routing control | `ip route` / `RTM_NEWROUTE` |
  | Neighbor API (permanent / static ARP & ND entries; cache flush) | Neighbor control | `ip neighbor` / `RTM_NEWNEIGH` |
  | Introspection API (read-only route table, neighbor cache, socket list, per-interface counters) | State observation | `/proc/net/route`, `/proc/net/arp`, `ss`, `/proc/net/dev` |

Design decisions made in Phase 1 must not foreclose Phase 2. Concretely:

- **Don't bake "we are the destination" assumptions** into parser / dispatch code paths that will later need to make a forwarding decision. Keep RX-path delivery and forward-or-deliver routing as separable steps even if the forward branch is currently a stub.
- **Parse extension headers / options as full typed objects, not opaque blobs**, even when the host has no semantic use for them — Phase 2 needs to forward them faithfully (RH preservation, HBH walking, etc.).
- **Per-destination routing state must be representable** in the eventual data model. Single-gateway shortcuts are tolerated as Phase 1 simplifications; they should be marked with a `# Phase 2: ...` comment so the upgrade path is greppable.
- **Hop-Limit / TTL handling, ICMP error rate-limiting, embedded-data preservation** — already wired host-side, designed once with forwarding in mind.

Design decisions made in Phase 1 / Phase 2 must not foreclose Phase 3. Concretely:

- **Every new user-observable knob lands on one of the sanctioned APIs.** Socket option, socket method, sysctl entry, or one of the link / address / route / neighbor / introspection APIs above. Never as a direct attribute on a `PacketHandler` / `TcpStack` / `NdCache` instance that consumers are expected to read or write.
- **No "userspace" reach-through to stack internals.** Consumers MUST NOT import from `pytcp.runtime.packet_handler.*`, `pytcp.protocols.tcp.tcp__session`, or any other implementation-detail module. If a piece of state needs to be visible outside the stack, expose it through `getsockopt` / `setsockopt`, a sysctl, or one of the dedicated control APIs (link / address / route / neighbor / introspection). Mark Phase-1/2 reach-throughs in tests with `# Phase 3: ...` so the cleanup path is greppable.
- **Configuration mutations go through the API for their plane.** Address changes go through the address API, not `packet_handler._ip6_ifaddr.append(...)`. Route changes go through the route API, not `Ip4IfAddr.gateway = ...`. Sysctl changes go through `sysctl_module.override(...)` or `pytcp.stack.sysctl["key"] = value`, not direct module-attribute assignment. Each plane's API is the boundary; the underlying attribute is implementation.
- **State introspection is read-only and copy-by-value.** Route-table / neighbor-cache / socket-list / packet-counter accessors return immutable snapshots, never live references the caller could mutate. The Linux equivalent is `/proc/net/*` text — readable, never writable by reading.
- **Stack lifecycle is its own API surface.** `stack.init()` / `stack.start()` / `stack.stop()` (and the `stack.mock__init()` test affordance) are the boundary; treat them like `clone(2)` / `exit(2)` rather than ordinary function calls. Adding a new stack-wide singleton means extending that boundary, not piggy-backing on import-time module state.
- **The socket factory's `__new__` dispatch is the user/kernel transition.** Keep it dumb — argument validation, family / type / proto match, allocate the per-flavour socket object. Putting protocol logic in the factory pulls Phase-3 work into the wrong layer.
- **Asymmetric data path / control path is fine.** The data path stays per-socket and high-throughput; the control APIs are coarse-grained, low-frequency, and OK with full-table copies on each call. Don't conflate the performance budgets — Linux makes the same split between `sendmsg(2)` and netlink.

Conformance precedence:

1. **RFC text first.** When the governing RFC is unambiguous, PyTCP follows it. Deliberate deviation requires an inline comment citing the rationale.
2. **Linux behavior as tiebreaker.** When the RFC is silent, ambiguous, or offers a SHOULD/MAY menu, PyTCP picks the Linux choice. Cite the Linux source file or sysctl in the commit body so the decision is greppable.
3. **Linux-specific extensions are in scope** when there is a real PyTCP consumer (e.g. CIPSO/CALIPSO, IP_RECVERR-style socket APIs, sysctl knobs that gate behavior).

Explicit non-goals (out of scope regardless of phase):

- Hardware offloads, XDP / AF_XDP, kernel-bypass paths
- Netfilter / eBPF / nftables hooks
- Crypto extensions (AH, ESP, IPsec, MACsec)
- Mobility extensions (MIPv6, NEMO, RH2 mobility processing)
- Userspace routing protocols (BGP, OSPF, RIP — these belong outside the stack)

Feature triage uses this north star:

- A gap that exists in PyTCP but not in Linux as host (Phase 1) or router (Phase 2) is on-list.
- A consumer surface that bypasses the socket / sysctl boundary (Phase 3) is on-list — even if functionally correct today.
- Phase-1 items are not deferrable; Phase-2 and Phase-3 items are tracked but deferrable. Phase-3 cleanups land naturally as code touches the boundary; resist large dedicated sweeps.

## Commands

```bash
# Setup
make                      # build everything (default goal = 'make all': venv + editable installs)
source venv/bin/activate

# Development
make lint                 # codespell + isort + black + flake8 + mypy + pylint + pyright
make test                 # run all three test suites via unittest
make validate             # lint + test together

# Run the stack (daemon + CLI; requires sudo for bridge/tap/tun setup)
sudo make bridge && sudo make tap7        # one-time: create a TAP on br0 (sudo)
sudo venv/bin/pytcp stack start -i tap7   # start the stack daemon
sudo venv/bin/pytcp ss                    # drive it (like 'ss'); see 'pytcp --help'
sudo venv/bin/pytcp stack stop            # stop the daemon

# Clean
make clean                # remove venv, caches, build artifacts
```

### Running a single test

```bash
# unittest is the test framework — run a specific test file directly
PYTHONPATH=. python -m unittest packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__assembler__operation.py

# Or run an entire suite via the find-glob the Makefile uses
PYTHONPATH=. python -m unittest $(find packages/net_proto/net_proto/tests/unit -name 'test__*.py')
```

## Architecture

### Package boundaries

| Package | Role |
|---|---|
| `packages/net_addr/net_addr/` | Standalone address library: `Ip4Address`, `Ip6Address`, `MacAddress`, etc. No dependency on the other packages. Published as its own dist (see below). |
| `packages/net_proto/net_proto/` | Protocol packet library: parse/assemble/validate. Depends on `net_addr` only. Published as its own dist (see below). |
| `packages/pytcp/pytcp/` | Running stack: threads, sockets, ARP/ND caches, RX/TX rings. Depends on both. Published as the `PyTCP` dist (see below). |

All three packages have been extracted into their own PEP 517
projects under `packages/` for independent PyPI publication. The
folder ↔ dist ↔ import mapping (one invariant: project folder ==
import name, no exceptions):

| Project folder | PyPI dist | Import |
|---|---|---|
| `packages/net_addr` | `PyTCP-net_addr` | `net_addr` |
| `packages/net_proto` | `PyTCP-net_proto` | `net_proto` |
| `packages/pytcp` | `PyTCP` | `pytcp` |

The repo-root `pyproject.toml` is now tooling-only (no
`[build-system]`/`[project]`) — the workspace root carrying the
shared lint/type config. All three packages are resolved in
development via editable installs (`make venv` runs
`pip install -e packages/net_addr` → `… net_proto` → `… pytcp`,
all `--config-settings editable_mode=compat` so mypy can follow
them); imports are unchanged (`from net_addr import ...`,
`from net_proto import ...`, `from pytcp import ...`). The
`PyTCP` dist depends on `PyTCP-net_proto==<ver>` +
`PyTCP-net_addr==<ver>` (lockstep); `net_proto` depends only
on `PyTCP-net_addr` (the former `aenum` dependency was removed
— `ProtoEnum` extends unknown wire codepoints via a native
stdlib `enum.Enum._missing_` hook); `net_addr`'s `click`-typed
CLI helpers are an opt-in `[cli]` extra, lazily imported, so
importing `net_addr` is stdlib-only.

### Packet flow

```
TAP/TUN fd
  └─> RxRing  ──> PacketHandler (per protocol, RX side)
                     └─> Socket queues / ARP cache / ND cache / fragment store
  <── TxRing  <── PacketHandler (per protocol, TX side)
                     <── Socket send / ARP probe / ICMPv6 ND / DHCP
```

RX and TX handlers live in `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__<proto>__<rx|tx>.py`. There are 20 handler files covering Ethernet, 802.3, ARP, IPv4, IPv6, IPv6-frag, ICMPv4, ICMPv6, TCP, and UDP — one RX file and one TX file per protocol.

The stack is threaded; every subsystem extends `packages/pytcp/pytcp/runtime/subsystem.py` (`Subsystem` base class) and implements `_subsystem_loop()`. Startup / shutdown use `threading.Event`.

The socket API (`packages/pytcp/pytcp/socket/`) mimics BSD sockets: `TcpSocket`, `UdpSocket`, `RawSocket` are returned by a factory `__new__` on the abstract `socket` class. TCP's FSM is a separate runtime under `packages/pytcp/pytcp/protocols/tcp/`, with `tcp__session.py` (the `TcpSession` class), `tcp__enums.py`, `tcp__constants.py`, plus a dedicated `packages/pytcp/pytcp/protocols/tcp/fsm/` subdirectory containing the dispatch table `tcp__fsm.py` and one `tcp__fsm__<state>.py` free-function module per FSM state. `packages/pytcp/pytcp/socket/tcp__socket.py` is the BSD-facade shim that delegates to `TcpSession`.

Stack-wide configuration constants (IP/MAC addresses, ARP/ND cache timers, MTU, port ranges, logger channels) live in `packages/pytcp/pytcp/stack/__init__.py`.

### Per-RFC adherence

Per-RFC adherence audits live at `docs/rfc/<family>/rfcXXXX__<name>/adherence.md` across the `tcp`, `ip6`, `ip4`, `icmp6`, `icmp4`, and `arp` families. Use the [`rfc_adherence_audit`](.claude/skills/rfc_adherence_audit/SKILL.md) skill to add or refresh an entry.

## Canonical Rules

PyTCP has ten canonical rule files in `.claude/rules/`. They are auto-loaded into the session context — read the relevant one before any non-trivial change. CLAUDE.md does not duplicate their content; when something feels missing here, it lives in one of the rules below.

| Rule | What it covers | Read when |
|---|---|---|
| [`feature_implementation.md`](.claude/rules/feature_implementation.md) | tests-first workflow, spec grounding, commit discipline, phase reporting | Every code change |
| [`python_features.md`](.claude/rules/python_features.md) | Python 3.10–3.14 language features (PEP 604 / 585 / 695 / 696 / 698 / 649); forbidden pre-3.10 fallbacks | Any new file or refactor |
| [`typing.md`](.claude/rules/typing.md) | mypy strict, annotations, generics, `Self` / `@override`, `Protocol` / `TypedDict`, `cast` and `# type: ignore` policy | Any annotation |
| [`enums.md`](.claude/rules/enums.md) | enum discipline — protocol codepoints / socket-option numbers / flag bits as IntEnum/ProtoEnum members; stdlib-socket-parity bare-alias pattern; forbidden bare-int-as-enum constants | Any new constant representing one of a set |
| [`source_files.md`](.claude/rules/source_files.md) | general source-file mechanics — file skeleton, copyright block, module docstring, imports, naming, formatting, inline comments, source docstrings | Any new source file |
| [`net_addr.md`](.claude/rules/net_addr.md) | `net_addr/` value-type library (at `packages/net_addr/net_addr/`) — ABC hierarchy, slot-based value types, multi-form `__init__`, equality / hashing, `click` CLI helpers | Any new value type under `packages/net_addr/net_addr/` |
| [`net_proto.md`](.claude/rules/net_proto.md) | `packages/net_proto/net_proto/` per-protocol six-file layout (`*Header` / `*HeaderProperties` / `*Base` / `*Parser` / `*Assembler` / `*Errors`), options, enums, validation helpers, error templates, buffer/struct conventions | Any new protocol authoring under `packages/net_proto/net_proto/protocols/` |
| [`pytcp.md`](.claude/rules/pytcp.md) | `pytcp/` runtime services (at `packages/pytcp/pytcp/`) — `Subsystem` base, packet-handler mixins, BSD socket facade, sysctl registry, stack configuration | Any new runtime service under `packages/pytcp/pytcp/` |
| [`unit_testing.md`](.claude/rules/unit_testing.md) | unit tests (framework, mocking discipline §6a, isolation §10a, modern Python features §10b, the §7.2 docstring audit) | Any new unit test |
| [`integration_testing.md`](.claude/rules/integration_testing.md) | integration tests (harness hierarchy, drive_rx / probe / fluent-assert pattern, stat-counter assertions) | Any new integration test |

### Pre-commit checklist (MANDATORY)

1. `make lint` clean (codespell + isort + black + flake8 + mypy strict + pylint + pyright). `make lint` runs pyright reading `[tool.pyright]` in `pyproject.toml`, so the CLI gate matches what VS Code's Pylance shows; mypy strict stays the type authority and the inference rules pyright diverges on are silenced there.
2. `make test` clean.
3. **§7.2 docstring audit** clean on any test file you wrote or modified (see [`unit_testing.md`](.claude/rules/unit_testing.md) §7.2).
4. **Modernise legacy typing / Python forms on touch** — fix them in the same commit, not as a separate sweep. Forbidden forms catalogued in [`python_features.md`](.claude/rules/python_features.md) §22 and [`typing.md`](.claude/rules/typing.md) §23.

### Tests-first (MUST)

Every behavioural change opens with one or more **failing tests** that pin the spec requirement, then the implementation flips them green. See [`feature_implementation.md`](.claude/rules/feature_implementation.md) §2 for the full procedure.

### Skills

- [`rfc_adherence_audit`](.claude/skills/rfc_adherence_audit/SKILL.md) — add or refresh a per-RFC adherence record.
- [`sysctl_knob`](.claude/skills/sysctl_knob/SKILL.md) — add a runtime-tunable sysctl-backed constant.
- [`mutation_testing`](.claude/skills/mutation_testing/SKILL.md) — run a cosmic-ray mutation-testing audit of a package, triage survivors (equivalent vs real gap), and close real gaps with kill-proven unit tests.
