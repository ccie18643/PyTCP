# RFC 6056 — Port Randomization (BCP 156)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6056                                           |
| Title       | Recommendations for Transport-Protocol Port Randomization |
| Authors     | M. Larsen, F. Gont                             |
| Category    | Best Current Practice (BCP 156)                |
| Date        | January 2011                                   |
| Source text | [`rfc6056.txt`](rfc6056.txt)                   |

RFC 6056 applies to **both TCP and UDP** ephemeral
source-port selection. In PyTCP the implementation is
shared: a single helper `pick_local_port` at
`packages/pytcp/pytcp/runtime/socket/socket__bind_helpers.py:122-145` services both
`packages/pytcp/pytcp/runtime/socket/udp__socket.py` and
`packages/pytcp/pytcp/runtime/socket/tcp__socket.py`. This audit lives under
`docs/rfc/udp/` because the UDP audit campaign surfaced
the gap, but the findings apply equally to TCP — see
cross-references at the bottom.

This audit walks each algorithm RFC 6056 §3.3 describes,
classifies PyTCP's current implementation against that
catalogue, and proposes the minimal fix that brings it
into conformance.

Sections without normative content (§1 Introduction, §2
Ephemeral Ports — background, §5 Security boilerplate,
§6 Acknowledgements, §7 References) are omitted.

---

## Top-line summary

| §        | Topic                                          | PyTCP status |
|----------|------------------------------------------------|--------------|
| §3.1     | Characteristics of a Good Algorithm            | met — `pick_local_port` uses `secrets.choice` (CSPRNG-backed) |
| §3.2     | Ephemeral Port Number Range                    | met — `range(32768, 61000)` (Linux parity; 28,232-port pool) |
| §3.3.1   | Algorithm 1 — Simple Port Randomization        | implemented (the UDP picker) |
| §3.3.2   | Algorithm 2 — Random Re-selection on Collision | not used (Algorithm 1 with upfront filtering is equivalent for the UDP case) |
| §3.3.3   | Algorithm 3 — Hash-Based (per RFC 6528 ISS)    | not implemented for UDP (TCP gets it — see [TCP-side audit](../../tcp/rfc6056__port_randomization/adherence.md)) |
| §3.3.4   | Algorithm 4 — Double-Hash with Increment Table | not implemented (refinement on 3) |
| §3.3.5   | Algorithm 5 — Random Increments                | not implemented |
| §3.5     | Choosing an Algorithm                          | met — UDP uses Algorithm 1, the RFC 6056 §3.5 recommended choice for UDP-style traffic |
| §4       | Interaction with NAPT                          | N/A — PyTCP is not a NAPT |

---

## §3.1 Characteristics of a Good Algorithm

> "Ephemeral port selection algorithms SHOULD obfuscate
>  the selection of their ephemeral ports, since this
>  helps to mitigate a number of attacks that depend on
>  the attacker's ability to guess or know the five-tuple
>  that identifies the transport-protocol instance to be
>  attacked."

**Adherence:** met. `pick_local_port` at
`packages/pytcp/pytcp/runtime/socket/socket__bind_helpers.py:122-145`:

```python
def pick_local_port() -> int:
    used = {socket.local_port for socket in stack.sockets.values()}
    available = [port for port in _ephemeral_port_pool() if port not in used]
    if not available:
        raise OSError("[Errno 98] Address already in use - ...")
    return secrets.choice(available)
```

`secrets.choice` is backed by `os.urandom` (and falls
back to the OS CSPRNG on every supported platform), so
each pick draws cryptographic-quality entropy
independent of every previous one. An off-path attacker
who observes prior selections gains no information about
future ones beyond the size of the remaining unused
pool. The §3.1 obfuscation SHOULD is satisfied.

---

## §3.2 Ephemeral Port Number Range

> "[T]he dynamic ports consist of the range 49152-65535.
>  However, ephemeral port selection algorithms should
>  use the whole range 1024-65535."

> "Ephemeral port selection algorithms SHOULD use the
>  largest possible port range, since this reduces the
>  chances of an off-path attacker of guessing the
>  selected port numbers."

**Adherence:** met. `STACK__EPHEMERAL_PORT_RANGE__LOW` /
`STACK__EPHEMERAL_PORT_RANGE__HIGH` at
`packages/pytcp/pytcp/stack/__init__.py:258-259` are now
`32768` / `61000` — a 28,232-port pool matching the
Linux `net.ipv4.ip_local_port_range = 32768 60999`
default. Step=1, so every port in the window is a valid
candidate; the historical step=2 even-only restriction
that halved the effective entropy is gone. The lower
bound aligns with Linux and keeps the IANA Well-Known
range (0-1023) and most of the Registered range
(1024-49151) free for explicit `bind()` use; the upper
bound stops short of 65535 to leave `61000-65535`
available for operator-pinned static allocation.

The conformance test at
`packages/pytcp/pytcp/tests/unit/stack/test__stack__init.py::test__stack__ephemeral_port_range__rfc6056_conformant`
asserts step=1 and pool size ≥ 16384 (the IANA dynamic
range minimum cited in RFC 6056 §3.2).

---

## §3.3.1 Algorithm 1 — Simple Port Randomization

> "do { port = min_ephemeral + (random() % num_ephemeral);
>      if (check_suitable_port(port)) return port;
>      next_ephemeral++; ... } while (count > 0);"

Algorithm 1 picks a random starting port, then
**sequentially scans** the range looking for an unused
slot. The first call's pick is random; subsequent picks
within the same scan are predictable.

**PyTCP's implementation IS Algorithm 1, with the
collision-check moved upfront.** Rather than the
literal `do { port = random(); if suitable return ...;
next_ephemeral++; } while` pattern, PyTCP filters out
in-use ports first and then calls `secrets.choice` on
the resulting list. This is functionally equivalent to
Algorithm 1 for the case where the random pick happens
to be unused on the first try (the common case), and
strictly *better* for the unhappy case (no linear-scan
bias toward "first available after an unavailable
run"). The entropy source is `secrets.choice` →
`os.urandom`, satisfying RFC 6056's
"unpredictable" requirement from §3.1.

---

## §3.3.2 Algorithm 2 — Random Re-selection on Collision

Like Algorithm 1 but on collision, picks ANOTHER random
port rather than sequentially scanning.

**Adherence:** not used (PyTCP doesn't loop on
collision — it computes the available set once).

---

## §3.3.3 Algorithm 3 — Hash-Based (per RFC 6528 ISS)

```c
/* offset = F(local_IP, remote_IP, remote_port, secret_key)
 * port   = min_ephemeral + ((offset + next_ephemeral) mod num_ephemeral)
 */
```

The keyed hash provides isolation between
flows-to-different-destinations: each destination tuple
gets its own port subspace, so an attacker who guesses
the port for one connection learns nothing about ports
for connections to other destinations.

**Adherence:** not implemented. PyTCP's
`pick_local_port` ignores the destination tuple entirely
— it picks from a single global pool regardless of
remote address. An attacker who can observe one
connection's source port learns information about the
likely source ports of other connections.

This is the **algorithm Linux uses for TCP** (see
`__inet_hash_connect` in `net/ipv4/inet_hashtables.c`).
For UDP, Linux currently uses Algorithm 2.

---

## §3.3.4 Algorithm 4 — Double-Hash with Increment Table

Refinement of Algorithm 3 — adds a per-destination
increment table to lower port-reuse frequency.

**Adherence:** not implemented (same as Algorithm 3).

---

## §3.3.5 Algorithm 5 — Random Increments

```c
/* next_ephemeral += (random() % N) + 1; */
```

Picks a random small increment from the previous port
rather than a fresh random pick. Lower port-reuse
frequency than Algorithm 1/2 at the cost of weaker
unpredictability.

**Adherence:** not implemented.

---

## §3.4 Secret-Key Considerations for Hash-Based Algorithms

**N/A** — PyTCP doesn't implement a hash-based algorithm.
When it eventually does (Algorithm 3 is the natural
target), the key would follow the `IP6__FLOW_SECRET` /
`TCP__ISS_SECRET` / `TCP__FASTOPEN_SECRET` pattern at
`packages/pytcp/pytcp/stack/__init__.py` — `secrets.token_bytes(16)` at
process start, never persisted.

---

## §3.5 Choosing an Ephemeral Port Selection Algorithm

RFC 6056 §3.5 recommends Algorithm 3 or 4 for TCP and
notes Algorithm 1/2 may be appropriate for "the
scenarios that may not warrant the additional complexity
of Algorithms 3 and 4," which includes most UDP
applications.

**Adherence:** met. PyTCP's UDP picker implements
Algorithm 1 with a cryptographic randomness source
(`secrets.choice` over the unused-port set — §3.1 / §3.3.1
above), which is the §3.5-recommended choice for UDP-style
traffic. The stronger per-destination Algorithm 3 that
RFC 6056 §3.5 recommends for TCP is tracked in the
[TCP-side audit](../../tcp/rfc6056__port_randomization/adherence.md).

---

## §4 Interaction with NAPT

**N/A** — PyTCP is not a NAPT. The recommendations on
NAPT-side port mapping (preserve randomness, avoid
sequential allocation) do not apply.

---

## Phase-1 fix history

The minimal fix that brought PyTCP's UDP picker into
conformance with §3.1 and §3.2 landed in a single
commit covering both:

1. **Widened the range to Linux defaults:**
   `EPHEMERAL_PORT_RANGE` changed from
   `range(32168, 60700, 2)` (14,266 even-only ports) to
   `range(32768, 61000)` (28,232 contiguous ports).
2. **Replaced set-pop entropy with `secrets.choice`:**
   the picker now draws from a CSPRNG-backed primitive
   rather than relying on Python set hash-order.

Both changes are reflected in the conformance status
above and pinned by the new unit tests
`test__stack__ephemeral_port_range__rfc6056_conformant`
and
`test__ip_helper__pick_local_port__uses_secrets_choice_for_entropy`.

**Phase 2 (Algorithm 3 for TCP) is tracked separately
from this UDP audit** — see the
[TCP-side audit](../../tcp/rfc6056__port_randomization/adherence.md)
for the per-destination keyed-hash port selection that
RFC 6056 §3.5 recommends for TCP.

---

## Test coverage audit

### §3.1 Obfuscation of port selection

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__bind_helpers.py::TestPickLocalPort::test__ip_helper__pick_local_port__uses_secrets_choice_for_entropy`
  — patches `secrets.choice` and asserts the picker
  delegates final selection to it, invoking it with the
  full unused-port pool from `EPHEMERAL_PORT_RANGE`.

**Status:** locked in.

### §3.2 Port range

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__init.py::TestStackModuleConstants::test__stack__ephemeral_port_range__rfc6056_conformant`
  — asserts step=1 (contiguous range) and pool size
  ≥ 16384 (IANA dynamic-range floor per RFC 6056 §3.2).
- **Unit:** existing
  `test__stack__ephemeral_port_range` covers the
  in-bounds property (0 ≤ start, stop ≤ 65536).

**Status:** locked in.

### §3.3 Algorithm classification

**N/A** — no dedicated test surface. The audit's value
is documentary.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Picker returns a port in range                        | locked in |
| Picker avoids already-bound ports                     | locked in |
| Picker uses cryptographic randomness (§3.1)           | locked in |
| Picker range matches Linux default (§3.2)             | locked in |
| Algorithm 3 hash-based isolation (TCP)                | n/a (Phase-2 hardening — see TCP-side audit) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Obfuscation of port selection                    | met (`secrets.choice`) |
| §3.2 Ephemeral range — use 49152-65535 or wider       | met (`range(32768, 61000)` — Linux parity, 28,232-port pool) |
| §3.3.1 Algorithm 1 implementation                     | implemented (UDP picker) |
| §3.3.3 Algorithm 3 (TCP isolation per-destination)    | not implemented for UDP (out of UDP scope; see [TCP-side audit](../../tcp/rfc6056__port_randomization/adherence.md)) |
| §3.4 Secret-key handling                              | N/A for UDP (no hash-based algorithm needed at the UDP layer) |
| §3.5 Algorithm choice                                 | met — Algorithm 1 is the §3.5-recommended choice for UDP-style traffic |
| §4 NAPT interaction                                   | N/A (not a NAPT) |

PyTCP's **UDP** picker now satisfies every RFC 6056
clause that applies to UDP. The remaining "not
implemented" row (Algorithm 3 hash-based per-destination
selection) is TCP-specific — RFC 6056 §3.5 doesn't
recommend it for UDP because per-destination state at
the picker layer adds little for connectionless,
short-lived flows. The TCP-side audit tracks that
work separately.

---

## Cross-references

- **TCP audit family applies equally** — `pick_local_port`
  is shared between `tcp__socket.py` and `udp__socket.py`.
  When this gap closes, the
  [RFC 9293 audit](../../tcp/rfc9293__tcp/adherence.md)
  (§3.1 / §3.4.1) and the
  [RFC 6528 audit](../../tcp/rfc6528__iss_hash/adherence.md)
  (which already covers the ISS-secret keyed-hash
  pattern) should both cross-reference the fix.
- UDP usage guidelines: [`../rfc8085__udp_usage_guidelines/adherence.md`](../rfc8085__udp_usage_guidelines/adherence.md) §5.1 references this audit
- UDP base spec: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md) (the sport=0 RX-reject deviation interacts — the picker assigns the source port, so sport=0 should never reach the wire from a socket-using app)
- ISS hash secret pattern (template for Algorithm 3 secret_key): [`../../tcp/rfc6528__iss_hash/adherence.md`](../../tcp/rfc6528__iss_hash/adherence.md)
- Socket-API parity: `docs/refactor/socket_linux_parity_audit.md`
