# RFC 6398 — IP Router Alert Considerations and Usage

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6398                                           |
| Title       | IP Router Alert Considerations and Usage       |
| Category    | Best Current Practice (BCP 168)                |
| Date        | October 2011                                   |
| Updates     | RFC 2113 (IPv4 Router Alert), RFC 2711 (IPv6 RAO) |
| Source text | [`rfc6398.txt`](rfc6398.txt)                   |

This document records the PyTCP codebase's adherence to RFC 6398
clause by clause. RFC 6398 is **a BCP that primarily addresses
router implementations and operator deployment guidance** — most
of its normative content is Phase-2 router-grade. PyTCP today is
a host stack; this audit verifies that the host-relevant
behaviours (carry the option on the wire, do not break on
receipt) are met and records the Phase-2 gaps so they are
greppable.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_proto/net_proto/protocols/ip4/options/ip4__option__router_alert.py`
and `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py`
directly. Non-normative sections (§1 Introduction, §2
Terminology, §3 Security Concerns discussion, §6 Security
Considerations boilerplate, §7-§9) are omitted.

---

## Top-line adherence

PyTCP **meets** the host-side posture for RFC 6398:

- The IPv4 Router Alert option is implemented as a typed
  dataclass (`Ip4OptionRouterAlert`) with full wire-format
  round-trip.
- Frames carrying RAO are accepted and delivered to the
  transport layer (no host-side filtering or special
  processing).
- We do not originate Router Alert frames from a host context;
  no application API exposes the option setter for general use
  (it can be added explicitly to a TX call's `ip4__options`).

The router-side BCP guidance (filtering, rate-limiting,
fast-path forwarding of unknown-protocol RAO, selective
processing by Value field) is **Phase 2** — PyTCP does not
forward today and so cannot exhibit DoS susceptibility to RAO
floods.

| Section | Topic                                                          | Status |
|---------|----------------------------------------------------------------|--------|
| §4.1    | End-to-end use of RAO in the Internet (host-side)              | met    |
| §4.2.1  | RAO within an administrative domain                            | host-side met; router-side Phase 2 |
| §4.2.2  | Overlay-model RAO use                                          | host-side met; router-side Phase 2 |
| §4.3    | Service-provider protection approaches                         | n/a (router/operator) |
| §5      | Router-Alert protection mechanisms (filtering / rate-limiting) | n/a (Phase 2) |
| §5      | "Forward in fast path, do not punt unknown-protocol RAO"       | n/a (Phase 2) |
| §5      | Configuration to ignore RAO                                    | n/a (Phase 2) |

---

## §4.1 Use of Router Alert End to End in the Internet

> "RFC 2113 specifies that 'Hosts SHOULD ignore this option.'"

**Adherence:** met. The PyTCP RX handler does not consult the
Router Alert option for any host-side decision; the option is
parsed into the typed `Ip4OptionRouterAlert` object and
delivered to the transport layer (or higher) intact. There is
no special-case in `packet_handler__ip4__rx.py` that fires on
Router Alert.

## §4.2.1 / §4.2.2 RAO in Controlled Environments / Overlay Model

These sections describe operator-managed deployments where
specific edge devices process RAO for specific signalling
protocols (RSVP, MPLS Label Distribution). PyTCP has no router
plane, no LDP, no RSVP — these scenarios are operationally
out of scope. The host-side requirement (do not break on
receipt) is met as noted above.

## §5 Router Alert Implementation Guidelines (router-side)

> "A router implementation of the IP Router Alert Option SHOULD
> include protection mechanisms against Router-Alert-based DoS
> attacks ..."
> "Router implementations ... SHOULD offer the configuration
> option to simply ignore the presence of 'IP Router Alert'."
> "A router implementation SHOULD forward within the 'fast path'
> ... a packet carrying the IP Router Alert Option containing a
> next level protocol that is not a protocol of interest to that
> router."

**Adherence:** n/a (Phase 2). All three are router-side
requirements that PyTCP cannot meet because PyTCP does not
forward. When forwarding lands the natural fix points are:

1. In the forward decision (post-routing-table-lookup), check
   `packet_rx.ip4.router_alert is not None`. If True and the
   inner protocol is not on a configured "interesting"
   allow-list, take the fast-path (forward without further
   inspection).
2. Add a sysctl `ip4.router_alert.process` (default False,
   matching Linux's `net.ipv4.conf.*.router_solicitations`-style
   "off by default" posture) so operators can opt in.
3. Add a per-source rate-limiter for RAO frames that *do*
   trigger slow-path processing.

---

## Test coverage audit

### Router Alert option wire codec

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__option__router_alert.py`
  Round-trip identity matrix on the 4-byte option (type 148,
  length 4, value field).

**Status:** locked in.

### RX delivery of RAO-bearing frames (host-side ignore)

- **Integration:** the IPv4 RX integration suite exercises
  packets with arbitrary option sets (including Router Alert
  via the `Ip4Options` constructor) and verifies that the
  destination filter / transport dispatch behaves the same as
  for an option-less frame.

**Status:** locked in indirectly via the broader IPv4 RX matrix.
A dedicated test that specifically pins "Router Alert option
does not divert delivery from the normal path" would be a
one-line assertion if needed.

### Phase-2 gaps

**No test surface — Phase 2.** When the forwarder lands:

1. Test that a Router-Alert frame carrying a known-interesting
   inner protocol triggers slow-path processing.
2. Test that a Router-Alert frame carrying an
   unknown/uninteresting inner protocol fast-paths through.
3. Test the rate-limiter and the operator-controlled
   ignore-RAO sysctl.

### Test coverage summary

| Aspect                                                  | Coverage |
|---------------------------------------------------------|----------|
| §4.1 / RFC 2113 — host ignores Router Alert             | locked in indirectly |
| Router Alert wire codec                                 | locked in |
| §5 router-side filtering / rate-limiting / fast-path    | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| Host accepts Router Alert frames (RFC 2113 "ignore") | met    |
| Wire codec round-trip                               | met    |
| Router-side DoS protections / filtering / rate-limit | n/a (Phase 2) |
| Router-side fast-path forwarding for unknown inner proto | n/a (Phase 2) |
| Operator config to ignore RAO                       | n/a (Phase 2) |

RFC 6398 is a router-grade BCP. PyTCP meets the host-side
"do not break, do not divert delivery" implied requirement
inherited from RFC 2113. When PyTCP gains a forwarding plane
the Phase-2 hooks listed in §5 above are the natural place to
add the BCP's recommended protections.
