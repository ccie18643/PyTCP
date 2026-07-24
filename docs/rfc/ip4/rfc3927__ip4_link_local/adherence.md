# RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3927                                                 |
| Title       | Dynamic Configuration of IPv4 Link-Local Addresses   |
| Category    | Standards Track                                      |
| Date        | May 2005                                             |
| Source text | [`rfc3927.txt`](rfc3927.txt)                         |

This document records the PyTCP codebase's adherence to RFC 3927
clause by clause. RFC 3927 defines the IPv4 Link-Local
mechanism (169.254/16) — pseudo-random address selection, ARP
Probe / Announce, conflict detection / defense. PyTCP today
recognises 169.254/16 at the address-classification layer
(`Ip4Address.is_link_local`) and uses it in the IPv4 source-
selection scope ordering, but **does not autoconfigure** a
link-local address. The full RFC 3927 state machine is **not
implemented**.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_address.py`,
`packages/pytcp/pytcp/protocols/ip4/ip4__source_selection.py`, and the IPv4
packet handlers directly. Non-normative content (§1 Introduction,
§1.1-§1.9 Requirements / Applicability, §3 Considerations, §4
Security, §5 Acknowledgements) is omitted.

---

## Top-line adherence

PyTCP **met (Phase 1 complete)**: the RFC 3927 IPv4 link-local
autoconfig client ships as a `Subsystem` in
`packages/pytcp/pytcp/protocols/ip4/link_local/`. Operators opt in via
`stack.init(ip4_link_local=True)` and tune the DHCP-fallback
window via the `ip4_link_local.dhcp_fallback_timeout_ms`
sysctl. The §2.1 MAC-seeded RNG, §2.2 ARP probe, §2.4 ARP
announce, §2.5(a/b) defend / abandon decision tree, §9 retry +
rate-limit loop, and §1.9 / §2.11 DHCP coordination are all
implemented. The §2.6 source/destination scope-mismatch gate
on the TX path closes the §2.7 / §2.8 host-side cases.

| Section | Topic                                                       | Status |
|---------|-------------------------------------------------------------|--------|
| §1.9    | When to configure a Link-Local address (after DHCP fails)   | met (`_reconcile_with_dhcp` fallback timer) |
| §2.1    | Random address selection from 169.254.1.0 - 169.254.254.255 | met (`link_local__rng.candidate_from_mac`) |
| §2.2    | Claim via ARP Probe                                         | met (`Ip4Acd.claim` → RFC 5227 §2.1.1) |
| §2.4    | Announce via gratuitous ARP                                 | met (`Ip4Acd.claim` → RFC 5227 §2.3) |
| §2.5    | Conflict detection / defense                                | met (`_handle_bound_conflict` defend/abandon decision tree) |
| §2.6    | Source / destination address usage rules                    | met (`_phtx_ip4` scope-mismatch gate) |
| §2.7    | Link-local packets are not forwarded                        | n/a (no forwarding) |
| §2.8    | Link-local packets are local-only                           | met (subsumed by §2.6) |
| §2.11   | DHCPv4 client interaction                                   | met (`_reconcile_with_dhcp` one-way state poll) |

---

## §1.9 When to Configure an IPv4 Link-Local Address

> "A host SHOULD NOT configure an IPv4 Link-Local address if it
> already has an IPv4 address assigned through a means other
> than IPv4 Link-Local address autoconfiguration."

**Adherence:** met. `Ip4LinkLocal._reconcile_with_dhcp`
polls `is_dhcp_bound()` on every subsystem-loop tick; while
DHCP is BOUND the link-local subsystem stays HALTED (or
releases any held address if it was BOUND when DHCP
succeeded). The check runs before state dispatch so a
DHCP-bind observation propagates without delay. Static
addresses installed via the address API are not affected
(the subsystem only claims if it has nothing).

> "An IPv4 host that is configured with a routable address
> obtained via PPP or some other means and is then attached to
> a different link that does not have a DHCP server, may need
> to obtain an IPv4 Link-Local address ..."

**Adherence:** met. The fallback timer in
`_reconcile_with_dhcp` measures continuous DHCP-unbound time;
after `ip4_link_local.dhcp_fallback_timeout_ms` milliseconds
the subsystem transitions HALTED → INIT and starts claiming.
A DHCP-bind during the fallback window resets the timer. The
default sysctl value is 0 ("feature off") — operators opt in
to the fallback policy.

## §2.1 Link-Local Address Selection

> "When a host wishes to configure an IPv4 Link-Local address,
> it selects an address using a pseudo-random number
> generator with a uniform distribution in the range from
> 169.254.1.0 to 169.254.254.255 inclusive."

**Adherence:** met.
`packages/pytcp/pytcp/protocols/ip4/link_local/link_local__rng.py::candidate_from_mac`
implements a MAC-seeded Linear Congruential Generator that
maps any (MAC, attempt) pair to a uniformly-distributed
address in `169.254.1.0..169.254.254.255` (65024 addresses).
The reserved first /24 (`169.254.0.0/24`) and last /24
(`169.254.255.0/24`) are excluded by the modulus arithmetic.
Linux comparison: avahi-autoipd uses the same manual-LCG
pattern; systemd's sd_ipv4ll uses SipHash24 — both satisfy
the §2.1 "different hosts diverge" rule.

> "The pseudo-random number generation algorithm MUST be
> chosen so that different hosts do not generate the same
> sequence of numbers."

**Adherence:** met. The LCG seeds from the 48-bit MAC; two
hosts with different MACs always produce different first
candidates.

> "If the host has access to persistent information that is
> different for each host, such as its IEEE 802 MAC address,
> then the pseudo-random number generator SHOULD be seeded
> using a value derived from this information."

**Adherence:** met. The seed IS the MAC bytes (struct-packed
as a 64-bit big-endian int).

> "Hosts that are equipped with persistent storage MAY, for
> each interface, record the IPv4 address they have
> selected."

**Adherence:** not implemented (MAY, not MUST). The MAC-
seeded RNG gives reboot-stability without persistent storage
for the same-host case. Phase 6 of the implementation track
left persistent caching as an optional follow-on.

## §2.2 Claiming a Link-Local Address — ARP Probe

> "Before using the IPv4 Link-Local address (e.g., using it as
> the source address in an IPv4 packet, or as the Sender IPv4
> address in an ARP packet) a host MUST perform the probing
> test described below ..."

**Adherence:** met.
`Ip4LinkLocal._do_claiming` calls
`self._acd.claim(address=self._candidate.address)` on the
`Ip4Acd` engine, which runs the RFC 5227 §2.1.1 ARP probe
sequence. The probe is synchronous (blocks ~5-9 s on the
subsystem's dedicated thread). On clean probe the address
is announced via RFC 5227 §2.3 (the engine keeps the defense
socket open) and installed through the `ip addr` surface via
`self._address_api.add(ifaddr=self._candidate)`; on conflict
the candidate is cleared and the FSM cycles back to INIT for
a fresh attempt with the RNG's `attempt` counter incremented.

## §2.5 Conflict Detection and Defense (post-claim)

> "Address conflict detection is an ongoing process that is in
> effect for as long as a host is using an IPv4 Link-Local
> address."

**Adherence:** met. While BOUND, the subsystem loop polls
the ACD engine every tick via `self._acd.poll_conflict()`;
a returned peer MAC (RFC 5227 §2.4 detection) invokes
`_handle_bound_conflict(peer_mac)`, which implements the
§2.5 decision tree:

- **§2.5(b)** — first conflict in `ARP__DEFEND_INTERVAL`:
  one defensive gratuitous ARP via `self._acd.defend()`,
  stay BOUND.
- **§2.5(a)** — second conflict within the window: abandon.
  `self._address_api.remove(address=...)` uninstalls the
  address (and, with `abort_bound_sessions=True` by default,
  honours the §2.5 paragraph 7 SHOULD by resetting bound TCP
  sessions); `self._acd.release()` closes the defense socket;
  state cycles to INIT for a fresh reconfigure.

The decision uses `ARP__DEFEND_INTERVAL` (RFC 5227 §1.1
DEFEND_INTERVAL = 10 s, exposed via the `arp.defend_interval`
sysctl) — operator overrides resolve live via qualified-
module access.

## §2.6 Source Address Usage

> "A host MUST NOT send packets with an IPv4 Link-Local source
> address to any destination that is not itself an IPv4 Link-
> Local destination."

**Adherence:** met.
`packet_handler__ip4__tx.py::_phtx_ip4` rejects any datagram
where `ip4__src.is_link_local != ip4__dst.is_link_local` with
`TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH` and the
`ip4__link_local_scope_mismatch__drop` counter bump. The gate
sits between destination validation and assembly so it fires
after `__validate_src_ip4_address` has confirmed the source
is owned. Both halves of the rule are symmetric (the
`!=` check catches both link-local→global and global→
link-local mixes). The DHCP-client path
(src=0.0.0.0, dst=255.255.255.255) is naturally exempt
because neither address is link-local.

## §2.7 Link-Local Packets Are Not Forwarded

> "Routers MUST NOT forward a packet with an IPv4 Link-Local
> source or destination address, irrespective of the router's
> default route configuration or routes obtained from dynamic
> routing protocols."

**Adherence:** n/a (host stack; no forwarding). The Phase-2
forwarder will need this rule; the predicate is ready.

## §2.8 Link-Local Packets Are Local

> "A host MUST NOT send a packet with an IPv4 Link-Local
> destination address to any router for forwarding."

**Adherence:** met (subsumed by §2.6). The §2.6 scope-
mismatch gate at the IPv4 layer rejects every send where
src and dst differ in link-local scope. The only paths that
reach `_phtx_ethernet` with a link-local destination are:

1. **Link-local-to-link-local sends** — both src and dst are
   in 169.254/16. When a link-local source is owned the
   host has an `Ip4IfAddr("169.254.x.y/16")` configured, so
   the link-local destination IS in the host's network and
   the Ethernet-layer gateway path is naturally skipped
   (the `ip4_dst not in ip4_host.network` branch fails).
2. **Caller-supplied broadcast** — not a §2.8 scenario.

So §2.8 cannot fire independently of §2.6 in PyTCP's
host-stack model — the gate at the IPv4 layer is necessary
and sufficient. An explicit Ethernet-layer short-circuit
would be dead code and is intentionally omitted. The
adherence is observable via the §2.6 test class
(`TestIp4TxRfc3927ScopeGate`) which proves
every non-link-local-to-link-local path is rejected before
reaching the gateway-selection logic.

## §2.11 DHCPv4 Client Interaction

> "A host that has obtained an IPv4 Link-Local address MAY
> attempt to use DHCP to obtain a routable address."

**Adherence:** met (one-way state poll). The DHCPv4 client
is unchanged by the link-local subsystem —
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` runs its own FSM
independently. The link-local subsystem reads `dhcp4_client.state`
via a dependency-injected `is_dhcp_bound: Callable[[], bool]`
predicate, wired in `stack.init()` as `lambda:
dhcp4_client.state is Dhcp4State.BOUND`. The DHCP client
never reads link-local state — the coordination is strictly
one-way, satisfying §2.11's "do not alter the DHCPv4 client"
rule.

> "A device that implements both IPv4 Link-Local and a DHCPv4
> client should not alter the behavior of the DHCPv4 client to
> accommodate IPv4 Link-Local configuration."

**Adherence:** met. The DHCPv4 client constructor /
lifecycle / FSM is identical with or without the link-local
subsystem present. The only DHCP-side change in the
RFC 3927 track was adding a read-only `state` property on
`Dhcp4Client` so external callers don't reach into `_state`.

---

## Test coverage audit

### Link-local predicate (Ip4Address.is_link_local)

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  Parametric cases verifying `is_link_local` on
  169.254.0.0, 169.254.255.255, and boundary addresses just
  outside.

**Status:** locked in.

### Link-local scope in IPv4 source selection (RFC 6724-style)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  Verifies that the link-local scope value
  `IpScope.LINK_LOCAL = 0x2`
  (`packages/pytcp/pytcp/protocols/ip/ip_scope.py:58`, returned by
  `ip4_address_scope` in
  `packages/pytcp/pytcp/protocols/ip4/ip4__source_selection.py`) is consulted
  by the rule-2 source-scope sort key.

**Status:** locked in.

### §2.6 TX-side scope-mismatch gate

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc3927ScopeGate`
  Five cases: link-local src + global dst → drop with new
  TxStatus + counter bump; symmetric global src + link-
  local dst → same drop; link-local src + link-local dst →
  passes the gate; global src + global dst → unaffected;
  DHCP-client path (src=0.0.0.0 + dst=255.255.255.255) →
  unaffected.

**Status:** locked in.

### §2.1 MAC-seeded candidate generator

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/link_local/test__link_local__rng.py`
  Seven cases: same-MAC determinism, different-MAC
  divergence, attempt-counter rolls the sequence, every
  candidate in [169.254.1.0, 169.254.254.255], reserved
  first /24 excluded, reserved last /24 excluded, range
  constants match RFC.

**Status:** locked in.

### §2.2 / §2.4 ARP Probe + Announce via the ACD API

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__claiming.py`
  Six FSM cases: clean claim → BOUND with candidate
  installed; conflict → INIT + counter bump + candidate
  cleared; retry picks a different candidate via attempt-
  roll; MAX_CONFLICTS triggers RATE_LIMIT sleep + counter
  reset; sysctl overrides honoured via qualified-module
  access; `_subsystem_loop` dispatches CLAIMING. Six
  sysctl-shape cases for `max_conflicts` /
  `rate_limit_interval_s`.

**Status:** locked in.

### §2.5 Defend / abandon decision

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__bound.py`
  Five cases: BOUND transition subscribes for conflicts;
  first conflict in window → defend (single gratuitous
  ARP); second conflict in window → abandon (abort TCP,
  remove host, unsubscribe, → INIT); two conflicts outside
  the window → both defend (rolling window);
  `ARP__DEFEND_INTERVAL` honoured via qualified-module
  access.

**Status:** locked in.

### §1.9 / §2.11 DHCPv4 coordination

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/link_local/test__link_local__client__dhcp.py`
  Ten cases: feature disabled (timeout=0) → eager INIT;
  feature enabled + DHCP getter → initial HALTED; DHCP-bind
  while BOUND → release + halt; DHCP-unbound continuously
  past timeout → HALTED→INIT kick; within window → stays
  HALTED; DHCP-bind during window resets the timer; no
  DHCP getter → eager; sysctl default 0; registered;
  rejects negative.

**Status:** locked in.

### §2.6 TX-side scope-mismatch gate

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc3927ScopeGate`
  Five cases: link-local src + global dst → drop with new
  TxStatus + counter bump; symmetric global src + link-
  local dst → same drop; link-local src + link-local dst →
  passes the gate; global src + global dst → unaffected;
  DHCP-client path (src=0.0.0.0 + dst=255.255.255.255) →
  unaffected.

**Status:** locked in.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Link-local predicate (169.254/16 recognition)         | locked in |
| Link-local scope in source selection                  | locked in |
| §2.1 MAC-seeded candidate generator                   | locked in |
| §2.2 / §2.4 ARP probe + announce via ACD API          | locked in |
| §2.5 Defend / abandon decision tree                   | locked in |
| §2.6 TX-side scope-mismatch gate                      | locked in |
| §2.8 Link-local-not-to-router                         | locked in (subsumed by §2.6) |
| §1.9 / §2.11 DHCPv4 coordination                      | locked in |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §1.9 Link-local fallback when DHCP fails            | met (fallback timer in `_reconcile_with_dhcp`) |
| §2.1 Random address selection from 169.254.1-254/24 | met (MAC-seeded LCG in `link_local__rng`) |
| §2.2 ARP Probe                                      | met (`Ip4Acd.claim` → RFC 5227 §2.1.1) |
| §2.4 ARP Announce                                   | met (`Ip4Acd.claim` → RFC 5227 §2.3) |
| §2.5 Conflict detection / defense                   | met (`_handle_bound_conflict` decision tree) |
| §2.6 TX-side scope-mismatch gate                    | met (`_phtx_ip4` scope check) |
| §2.7 / §2.8 No forwarding / local-only              | n/a (host) / met (subsumed by §2.6) |
| §2.11 DHCP client interaction                       | met (one-way state poll; DHCP behaviour unchanged) |

PyTCP **fully implements** the RFC 3927 IPv4 link-local
autoconfig mechanism for the host-stack case (Phase 1 of the
project north-star). The implementation lives in
`packages/pytcp/pytcp/protocols/ip4/link_local/` as a `Subsystem` instantiated
by `stack.init(ip4_link_local=True)`. Operators opt in via the
`ip4_link_local` boot kwarg and tune the DHCP-fallback window
via `ip4_link_local.dhcp_fallback_timeout_ms`. The Linux
analogues are `avahi-autoipd` / `dhcpcd --ipv4ll` /
`systemd-networkd`'s `LinkLocalAddressing=fallback`.

The implementation track is documented in
`docs/refactor/rfc3927_link_local_autoconfig.md`, shipped in
phases 0-5 on `PyTCP_3_0__pre_release`.
