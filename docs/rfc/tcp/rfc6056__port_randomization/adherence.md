# RFC 6056 — Port Randomization (BCP 156, TCP perspective)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6056                                           |
| Title       | Recommendations for Transport-Protocol Port Randomization |
| Authors     | M. Larsen, F. Gont                             |
| Category    | Best Current Practice (BCP 156)                |
| Date        | January 2011                                   |
| Source text | [`rfc6056.txt`](rfc6056.txt)                   |

This is the **TCP-side** RFC 6056 audit. The picker
itself is a cross-protocol primitive — one
implementation at
`packages/pytcp/pytcp/runtime/socket/socket__bind_helpers.py:122::pick_local_port` serves
both `packages/pytcp/pytcp/runtime/socket/tcp__socket.py` and
`packages/pytcp/pytcp/runtime/socket/udp__socket.py`. This record therefore
**inherits the implementation findings from the UDP-side
audit** at
[`../../udp/rfc6056__port_randomization/adherence.md`](../../udp/rfc6056__port_randomization/adherence.md);
the TCP framing emphasizes the per-RFC-§3.5 recommendation
that TCP use **Algorithm 3** (hash-based per-destination
isolation) which the UDP picker is not obliged to satisfy.

The convention of per-family adherence records for
multi-family RFCs is established elsewhere in the audit
corpus (RFC 1122 has separate records under `arp/`,
`icmp4/`, `ip4/`, `tcp/`, `udp/`).

---

## Top-line summary

| §        | Topic                                          | PyTCP status (TCP) |
|----------|------------------------------------------------|--------------------|
| §3.1     | Obfuscation of port selection                  | met (shared fix; `secrets.choice` — see UDP audit) |
| §3.2     | Ephemeral port range (49152-65535 or wider)    | met (shared fix; `range(32768, 61000)` Linux parity — see UDP audit) |
| §3.3.1   | Algorithm 1 (Simple Randomization)             | implemented — used for TCP `bind(0)` (no destination known yet) |
| §3.3.3   | Algorithm 3 (Hash-Based, RFC 6528-style)       | met — used for TCP `connect()` via `pick_local_port_for` |
| §3.3.4   | Algorithm 4 (Double-Hash + Increment Table)    | not implemented (refinement on 3) |
| §3.3.5   | Algorithm 5 (Random Increments)                | not implemented |
| §3.4     | Secret-key considerations                      | met — `TCP__PORT_SECRET` (16 random bytes at module import, never persisted, regenerated on restart) |
| §3.5     | Choosing an algorithm                          | met — Algorithm 3 on `connect()`, Algorithm 1 fallback on pre-bound sockets |
| §4       | NAPT interaction                               | N/A — PyTCP is not a NAPT |

The UDP-side audit catalogues the implementation in
detail. This record adds the **TCP-specific findings**
that don't apply equally to UDP:

1. **§3.5 recommends Algorithm 3 (hash-based) for TCP.**
   Linux uses Algorithm 3 for TCP source-port selection
   (`__inet_hash_connect` in
   `net/ipv4/inet_hashtables.c`); PyTCP uses Algorithm 3
   on the `connect()` path (`pick_local_port_for`) and
   the Algorithm 1 set-pop fallback only on `bind(0)`,
   where the remote tuple is not yet known.
2. **TCP connections are long-lived**, so the
   port-reuse-frequency property Algorithm 3/4 optimize
   matters more for TCP than UDP. PyTCP's Algorithm 3
   walk starts from a per-destination secret-keyed
   offset, giving the per-destination subspaces that
   scale better than a plain unused-port pool.
3. **The RFC 6528 ISS-secret infrastructure already
   exists** (`TCP__ISS_SECRET` at `packages/pytcp/pytcp/stack/__init__.py`;
   used by `compute_iss` for sequence-number selection).
   Algorithm 3 for TCP source ports reuses that
   keyed-hash pattern almost verbatim via
   `TCP__PORT_SECRET` — only the inputs change (the hash
   tuple is `local_ip + remote_ip + remote_port`).

---

## TCP-specific findings

### §3.3.3 Algorithm 3 — Hash-Based Selection (TCP)

The RFC 6056 §3.3.3 algorithm:

```
offset = F(local_IP, remote_IP, remote_port, secret_key)
count  = num_ephemeral
do {
    port = min_ephemeral + ((offset + next_ephemeral) mod num_ephemeral)
    next_ephemeral++
    if (check_suitable_port(port)) return port
    count--
} while (count > 0)
return ERROR
```

The keyed-hash offset means: for any given
`(local_IP, remote_IP, remote_port)` triple, the port
walk starts at a fixed offset that's determined by the
destination AND the per-stack secret. Two consequences:

1. **Per-destination isolation.** An attacker who
   guesses the source port of a connection to one
   server learns nothing about source ports for
   connections to other servers (the secret keys the
   offsets).
2. **Lower port-reuse frequency to the same destination.**
   Successive connects to the same `(remote_IP,
   remote_port)` walk forward from the same offset,
   spreading port usage across the range deterministically.

**Adherence:** met. PyTCP ships
`pick_local_port_for(*, local_ip, remote_ip, remote_port)`
at `packages/pytcp/pytcp/runtime/socket/socket__bind_helpers.py`:

```python
def pick_local_port_for(
    *,
    local_ip: Ip4Address | Ip6Address,
    remote_ip: Ip4Address | Ip6Address,
    remote_port: int,
) -> int:
    digest = hashlib.blake2s(
        bytes(local_ip) + bytes(remote_ip) + remote_port.to_bytes(2, "big"),
        key=stack.TCP__PORT_SECRET,
        digest_size=4,
    ).digest()
    offset = int.from_bytes(digest, "big")
    pool = list(stack.EPHEMERAL_PORT_RANGE)
    used = {socket.local_port for socket in stack.sockets.values()}
    pool_len = len(pool)
    for i in range(pool_len):
        port = pool[(offset + i) % pool_len]
        if port not in used:
            return port
    raise OSError("...")
```

The TCP `connect()` call site at
`packages/pytcp/pytcp/runtime/socket/tcp__socket.py` orders operations so the
destination IP is resolved before the picker runs, then
invokes `pick_local_port_for(local_ip, remote_ip,
remote_port)` to derive the source port. The
`TCP__PORT_SECRET` (16 random bytes at module import
via `secrets.token_bytes`) keys the BLAKE2s hash; same
allocation pattern as `TCP__ISS_SECRET` /
`TCP__FASTOPEN_SECRET` / `IP6__FLOW_SECRET`.

The unit tests at
`packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__bind_helpers.py::TestPickLocalPortFor`
pin the three RFC-relevant properties:

- **Deterministic for same inputs** (same offset for the
  same five-tuple inputs + secret).
- **Per-destination isolated** (different `remote_ip`
  values produce different ports).
- **Secret-keyed** (mutating `TCP__PORT_SECRET` produces
  different ports for the same inputs).

Plus the operational properties (linear scan past
in-use ports; raise on exhaustion).

### TCP-specific call sites for the picker

The picker is invoked from three sites in `tcp__socket.py`:

- **`bind((addr, 0))`** at `tcp__socket.py:431+` — the
  BSD convention "bind to port 0 means pick ephemeral"
  results in `pick_local_port()` getting called before
  `connect()` knows the remote tuple. **§3.5
  "lazy-binding" issue** — Algorithm 3 cannot run here
  because the remote tuple isn't known yet. RFC 6056
  §3.5 recommends Algorithm 2 fall-back in this case, OR
  "lazy binding" — defer the port pick until
  `connect()` / `send()` is called. Linux does the
  latter.
- **`connect((addr, port))`** at
  `tcp__socket.py:503+` — if `_local_port == 0`, the
  picker runs here. Algorithm 3 **CAN** run here
  because the remote tuple is in scope.
- **`accept()`** at `tcp__socket.py` — server-side
  accepted sockets inherit the listening socket's local
  port; no picker call.

The mixed timing means a strict Algorithm 3 implementation
needs a hybrid: Algorithm 2 (random pick with collision
re-pick) when `bind()` picks before connect, Algorithm 3
when `connect()` knows the remote. This is exactly the
shape Linux's `__inet_hash_connect` implements.

### §3.4 Secret-Key Considerations for Hash-Based Algorithms

Algorithm 3's secret-key handling follows the
established PyTCP pattern:

- Generated via `secrets.token_bytes(16)` at module
  import (`TCP__PORT_SECRET` in
  `packages/pytcp/pytcp/stack/__init__.py`).
- Never persisted to disk.
- Re-keying on process restart is acceptable (and
  desirable — RFC 6056 §3.4 notes "the secret should be
  regularly regenerated").
- Mirrors the naming convention: `TCP__PORT_SECRET`
  alongside the existing `TCP__ISS_SECRET` /
  `TCP__FASTOPEN_SECRET` / `IP6__FLOW_SECRET`.

The
[RFC 6528 ISS hash audit](../rfc6528__iss_hash/adherence.md)
documents the same established pattern — Algorithm 3 for
ports consumes the same scaffolding.

---

## Cross-references — shared findings with UDP audit

The Phase-1 fix (widened ephemeral range +
`secrets.choice` entropy) was applied to the shared
`pick_local_port` helper and benefits both protocols.
The implementation details are documented once in the
UDP audit:

| Finding                                                | Detail in |
|--------------------------------------------------------|-----------|
| §3.1 obfuscation: `secrets.choice` for entropy         | [UDP audit §3.1](../../udp/rfc6056__port_randomization/adherence.md#31-characteristics-of-a-good-algorithm) |
| §3.2 port range: `range(32768, 61000)` Linux parity    | [UDP audit §3.2](../../udp/rfc6056__port_randomization/adherence.md#32-ephemeral-port-number-range) |
| §3.3.1 Algorithm 1 implementation                      | [UDP audit §3.3.1](../../udp/rfc6056__port_randomization/adherence.md#331-algorithm-1--simple-port-randomization) |
| Phase-1 fix history                                    | [UDP audit "Phase-1 fix history"](../../udp/rfc6056__port_randomization/adherence.md#phase-1-fix-history) |

---

## Test coverage audit

The UDP audit covers the picker's general test surface.
TCP-specific tests for RFC 6056 conformance would be:

### §3.3.3 Algorithm 3 — per-destination isolation

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__bind_helpers.py::TestPickLocalPortFor`
  — 5 tests: same inputs + secret → same port;
  different `remote_ip` → different ports; different
  secret → different ports; skips ports in use (linear
  scan); raises OSError on exhaustion.

**Status:** locked in.

### §3.5 lazy-binding (bind before connect)

**Existing test:**
`packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__tcp__socket.py:296+`
patches `pytcp.runtime.socket.tcp__socket.pick_local_port` for
the ephemeral-assignment-on-`bind(0)` path. The test
pins the picker is called via the bare (no-destination)
`pick_local_port` route — matching RFC 6056 §3.5's
Algorithm 1 fallback for the case where the destination
isn't yet known.

**Status:** locked in.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Picker is invoked on TCP `bind(0)` / `connect()`      | locked in |
| §3.3.3 Algorithm 3 per-destination isolation          | locked in |
| §3.3.3 Algorithm 3 secret-keyed                       | locked in |
| §3.5 lazy-binding Algorithm 1 fallback                | locked in |
| Phase-1 common picker fixes                           | covered by UDP audit |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Obfuscation                                      | met (shared Phase-1 fix; `secrets.choice`) |
| §3.2 Range                                            | met (shared Phase-1 fix; `range(32768, 61000)`) |
| §3.3.1 Algorithm 1 (UDP-acceptable)                   | implemented — used for `bind(0)` (no destination yet) |
| §3.3.3 Algorithm 3 (TCP-recommended per §3.5)         | met — used on `connect()` via `pick_local_port_for` |
| §3.3.4 Algorithm 4                                    | not implemented (refinement on 3; no operational need) |
| §3.3.5 Algorithm 5                                    | not implemented |
| §3.4 Secret-key handling                              | met — `TCP__PORT_SECRET` follows the established 128-bit per-process token pattern |
| §3.5 Lazy-binding hybrid (Alg 1 / Alg 3)              | met — Algorithm 1 on `bind(0)`; Algorithm 3 on `connect()` |
| §4 NAPT                                               | N/A |

PyTCP **fully conforms** to RFC 6056 for both TCP and
UDP. The shared Phase-1 fix brought §3.1 and §3.2 into
compliance; the TCP-specific Phase-2 fix added
Algorithm 3 for the `connect()` path — Linux-parity
behaviour with per-destination port-subspace isolation
and a 128-bit secret keying the BLAKE2s offset.

Algorithm 4 (RFC 6056 §3.3.4 — double-hash with
per-destination increment table) is a refinement on
Algorithm 3 that reduces port-reuse frequency at the
cost of additional kernel memory. PyTCP has no
operational need that Algorithm 3 alone doesn't already
address; Algorithm 4 remains "not implemented" without
a conformance impact.

---

## Cross-references

- **UDP-side audit (primary findings):** [`../../udp/rfc6056__port_randomization/adherence.md`](../../udp/rfc6056__port_randomization/adherence.md)
- **RFC 6528 ISS hashing (template for Algorithm 3 secret-key handling):** [`../rfc6528__iss_hash/adherence.md`](../rfc6528__iss_hash/adherence.md)
- **RFC 5961 blind-attack hardening (companion security audit):** [`../rfc5961__blind_attack_hardening/adherence.md`](../rfc5961__blind_attack_hardening/adherence.md)
- **RFC 9293 TCP base spec (`bind()` / `connect()` user/TCP interface):** [`../rfc9293__tcp/adherence.md`](../rfc9293__tcp/adherence.md)
- Shared picker: `packages/pytcp/pytcp/runtime/socket/socket__bind_helpers.py:122::pick_local_port`
- Ephemeral range constant: `packages/pytcp/pytcp/stack/__init__.py:175::EPHEMERAL_PORT_RANGE`
- Secret-key pattern: `packages/pytcp/pytcp/stack/__init__.py` (`TCP__ISS_SECRET`, `TCP__FASTOPEN_SECRET`, `IP6__FLOW_SECRET`)
- Socket-API parity: `docs/refactor/socket_linux_parity_audit.md`
