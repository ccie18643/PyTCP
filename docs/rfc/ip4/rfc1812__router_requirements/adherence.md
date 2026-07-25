# RFC 1812 — Requirements for IP Version 4 Routers

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 1812                                                 |
| Title       | Requirements for IP Version 4 Routers                |
| Category    | Internet Standard (STD 4)                            |
| Date        | June 1995                                            |
| Updated by  | RFC 2644 (directed broadcast), RFC 6633 (Source Quench deprecation) |
| Source text | [`rfc1812.txt`](rfc1812.txt)                         |

This document records the PyTCP codebase's adherence to RFC 1812.
RFC 1812 is the **router-grade companion** to RFC 1122 — it
defines what an IPv4 router MUST do. As of PyTCP 3.0.9 the
**IPv4 unicast forwarding plane is complete** (Phase-2 milestones
**M1–M4**): the forward-or-deliver decision, the TTL decrement
with ICMPv4 Time Exceeded on expiry, and the no-route ICMPv4
Destination Unreachable (M1); forwarded-packet fragmentation and
the transit-PMTU Fragmentation Needed (M2); ICMP Redirect
generation + host RX-accept (M3); and the forward-path martian /
directed-broadcast / source filtering plus IP-options preservation
(M4) are all **met**. A small residue of §5.2.4 SHOULD refinements
(active Record-Route / Timestamp append, LSRR/SSRR source-route
forwarding) and the policy-routing / RPF / multipath features stay
deferred with rationale, per the project north-star (`CLAUDE.md`
"Project North Star" → Phase 2: router-grade parity).

This audit enumerates the §4-§5 normative requirements and
classifies each as one of:

- **n/a (Phase 2):** Forwarder-only requirement; will be
  addressed when the Phase-2 forwarding plane lands.
- **inherited from RFC 1122 host audit:** Requirement that
  also applies to hosts (e.g. RFC 1122 §3.2.1.7 TTL handling);
  audited under the host record.
- **met (host-side):** Requirement that PyTCP satisfies even
  in its current host posture (e.g. ICMP error rate limiting).

The audit was performed by reading the RFC text fresh and
inspecting the IPv4 packet handlers and ICMP machinery
directly. Non-normative content (§1 Introduction, §2 Internet
Architecture, §3 Link Layer, Appendices) is omitted.

---

## Top-line adherence

PyTCP implements the **IPv4 unicast forwarding plane** as of
3.0.9 M1; the transit PMTU (M2), Redirect (M3), and IP-options
(M4) clauses remain deferred. The audit enumerates both what M1
now satisfies and the remaining Phase-2 gaps so the migration
path is greppable.

| Section group | Topic                                            | Status |
|---------------|--------------------------------------------------|--------|
| §4.2.2.1      | IP options on forwarded packets (preservation)   | met (M4); active RR/TS append deferred |
| §4.2.2.2      | Addresses in options (LSRR/SSRR rewrite)         | n/a — source-routed dropped at RX gate by default |
| §4.2.2.4      | TOS routing                                      | n/a (Phase 2) |
| §4.2.2.5      | Header checksum recomputation                    | met (M1) |
| §4.2.2.7      | Fragmentation on forward                         | met (M2) |
| §4.2.2.8      | Reassembly (routers MUST NOT reassemble in transit) | met by absence |
| §4.2.2.9      | TTL decrement + Time Exceeded                    | met (M1) |
| §4.2.2.10     | Multi-subnet broadcasts                          | n/a (Phase 2) |
| §4.2.3.1      | IP broadcast addresses                           | inherited from RFC 1122 host audit |
| §4.2.3.2      | IP multicasting                                  | inherited (host-side) |
| §4.2.3.3      | Path MTU Discovery (router side: emit Frag-Needed) | met (M2) — transit Frag-Needed carries the egress MTU |
| §4.3          | ICMP general (TTL, source, error reporting)      | inherited from RFC 1122 host audit + RFC 4884 / RFC 6633 audits |
| §4.3.2.8      | ICMP error rate limiting                         | met (host-side; reused on the transit-error path) |
| §4.3.3        | ICMP Destination Unreachable                     | met (host + M1 no-route network-unreachable) |
| §4.3.3.2      | ICMP Redirect (emission + RX accept)             | met (M3) |
| §4.3.3.3      | ICMP Source Quench (emission)                    | n/a (deprecated by RFC 6633; audit there) |
| §4.3.3.4      | ICMP Frag-Needed (transit PMTU emission)         | met (M2) |
| §4.3.3.5      | ICMP Time Exceeded (emission)                    | met (M1) |
| §4.3.3.7      | ICMP Echo Reply                                  | met (RFC 1122 / icmp4 audit) |
| §5            | Forwarding plane                                 | partial — unicast forwarding + PMTU/frag met (M1+M2); Redirect (M3), options (M4) deferred |

---

## §4.2.2.7 Fragmentation (router-side)

> "A router MUST support fragmenting datagrams that it
> forwards if their length exceeds the next hop's MTU
> (unless they have DF set, in which case it MUST emit ICMP
> Destination Unreachable / Frag-Needed)."

**Adherence:** met (M2). When a forwarded datagram exceeds the
egress MTU, `Ip4ForwardHandler.try_forward_ip4`
(`packet_handler__ip4__forward.py`) branches on the DF flag:
- **DF=1** → discard + ICMPv4 Destination Unreachable /
  Fragmentation Needed (Code 4) carrying the egress MTU (transit
  PMTU, §4.3.3.4 below), bumping `ip4__forward_too_big__drop`.
- **DF=0** → `_forward_fragmented_ip4` fragments to the egress
  MTU and forwards each fragment, reusing the origination-path
  `iter_fragment_chunks` + `Ip4FragAssembler` machinery. Each
  fragment inherits the original DSCP / ECN / **Identification**
  (preserved so the far end reassembles) / protocol and carries
  the TTL decremented by one; the first fragment keeps the full
  options, later fragments only the copy-flag=1 subset (RFC 791
  §3.1). Counted in `ip4__forward_fragmented`.

## §4.2.2.8 Reassembly

> "A router MAY perform reassembly of datagrams which it
> forwards, but MUST do so in such a way that does not
> introduce dropped datagrams. ... A router MUST NOT
> reassemble datagrams in transit unless it is the final
> destination."

**Adherence:** met by absence. PyTCP only reassembles
datagrams **destined for itself** (the destination filter at
`packet_handler__ip4__rx.py:149-153` happens **before**
the fragmentation branch at line 171). A datagram in transit
would never reach the fragmentation branch in PyTCP because
forwarding is not implemented.

## §4.2.2.9 Time to Live

> "When forwarding a datagram, a router MUST decrement the
> Time-to-Live field by at least one. If the TTL field is
> decremented to zero, the router MUST discard the datagram
> and MUST send an ICMP Time Exceeded message."

**Adherence:** met (M1). The forward path at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__forward.py`
(`Ip4ForwardHandler.try_forward_ip4`) branches off
`_forward_or_deliver_ip4` when the destination is not owned and
forwarding is enabled. It rejects a datagram arriving with
`ttl <= 1` (bumping `ip4__forward_ttl_exceeded__drop`) and emits
ICMPv4 Time Exceeded (Type 11, Code 0) back to the source; a
forwarded datagram has its TTL decremented by one and its header
checksum recomputed before re-emission. The pre-existing host-side
"TTL=0 on receive rejects the datagram" behaviour (RFC 1122
§3.2.1.7 audit) is unchanged.

## §4.2.2.5 Header Checksum Recomputation

> "A router MUST recompute the IP header checksum whenever it
> modifies the header (e.g. on the TTL decrement)."

**Adherence:** met (M1). After decrementing the TTL byte, the
forward path zeroes the checksum field and recomputes it over
the IHL-bounded header via `inet_cksum`
(`packet_handler__ip4__forward.py`, `try_forward_ip4` step 8).
The forwarded-frame integration tests re-parse the egress frame
and assert the header checksum sums to zero (valid).

## §4.3.2.8 ICMP Error Rate Limiting

> "A router MUST implement a configurable rate-limiting
> mechanism for the generation of ICMP error messages."

**Adherence:** met (host-side; also applies to routers). The
ICMPv4 rate limiter at `packages/pytcp/pytcp/protocols/icmp/icmp__rate_limiter.py`
is consumed by every ICMP error path in PyTCP
(`packet_handler__ip4__rx.py:233-256` and
`packet_handler__ip4__rx.py:258-300`). Token-bucket parameters
are operator-tunable.

This is a rare host-relevant § from RFC 1812; the host audit
under RFC 1122 §3.2.2 also references it.

## §4.3.3.2 ICMP Redirect Emission

> "A router MUST generate a Redirect message ... when it is
> aware of a better path."

**Adherence:** met (M3). When a datagram is forwarded back out
the interface it arrived on (ingress == egress, the next hop
on-link to the source), `Ip4ForwardHandler._maybe_emit_redirect`
sends an ICMPv4 Redirect (Type 5, Code 1 — host redirect, per
§5.2.7.2 / Linux `ICMP_REDIR_HOST`) advising the source of the
better first hop, gated by the per-interface `ip4.send_redirects`
sysctl (default on; Linux `net.ipv4.conf.<iface>.send_redirects`)
and suppressed for source-routed datagrams. The triggering
datagram is still forwarded. The new ICMPv4 Redirect wire codec
lives at
`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__redirect.py`
(`Icmp4Type.REDIRECT = 5`, `Icmp4RedirectCode`), with the full
net_proto unit-test matrix. The IPv6 ND Redirect parallel is
generated by `Ip6ForwardHandler._maybe_emit_redirect` (RFC 4861
§4.5, link-local source, Target/Redirected-Header options).

**Host RX-accept** (RFC 1122 §3.3.1.2): an inbound ICMPv4 Redirect
whose advertised gateway is on-link installs a per-destination
host route (`RouteProtocol.REDIRECT`) via
`Icmp4RxHandler.__phrx_icmp4__redirect`, gated by
`ip4.accept_redirects` (default on).

## §4.3.3.5 ICMP Time Exceeded Emission

> "If a router discards a packet because its TTL was decremented
> to zero, it MUST send an ICMP Time Exceeded (Code 0) to the
> source."

**Adherence:** met (M1). See §4.2.2.9 — the forward path emits
ICMPv4 Time Exceeded (Type 11, Code 0, TTL exceeded in transit)
from `Ip4ForwardHandler._emit_time_exceeded`, sourced from the
ingress interface's address toward the original sender (RFC 1812
§4.3.2.5) and embedding the offending datagram. The emission
runs the shared host-requirements gate + the existing ICMPv4
error rate limiter (§4.3.2.8). The ICMPv4 TX handler gained a
`TIME_EXCEEDED` dispatch arm (`icmp4__time_exceeded__send`).

## §4.3.3.1 Destination Unreachable on No Route

> "A router MUST generate a Destination Unreachable message ...
> Code 0 (Network Unreachable) when it cannot forward a packet
> because it has no route to the destination network."

**Adherence:** met (M1). When the FIB resolves no route for a
transit destination, the forward path bumps
`ip4__forward_no_route__drop` and emits ICMPv4 Destination
Unreachable (Type 3, Code 0, network unreachable) from
`Ip4ForwardHandler._emit_dest_unreachable`. The ICMPv4 TX
handler gained a `DESTINATION_UNREACHABLE, NETWORK` dispatch arm
(`icmp4__destination_unreachable__network__send`).

**Host Unreachable (Code 1) on next-hop resolution failure —
deferred.** RFC 1812 also prescribes Destination Unreachable /
Host Unreachable (Code 1) when a router cannot resolve the
next-hop link-layer address. PyTCP today queues the forwarded
datagram pending ARP resolution (`ip4__forward_no_neighbor__drop`,
the RFC 1122 §2.3.2.2 soft queue) rather than emitting Host
Unreachable, because there is no "resolution hard-failed after N
probes" signal from the neighbor cache to the forward path yet.
Emitting Host Unreachable needs a cache-exhaustion callback that
distinguishes a transit datagram from a host-originated one; it is
tracked as a Phase-2 refinement, not part of the M2 cut.

## §4.3.3.4 ICMP Fragmentation Needed (transit PMTU)

> "A router MUST send an ICMP Destination Unreachable / Code 4
> (Fragmentation Needed and DF set) when it needs to fragment a
> datagram whose DF bit is set, and SHOULD include the next-hop
> MTU (RFC 1191)."

**Adherence:** met (M2). See §4.2.2.7 — a DF=1 forwarded datagram
exceeding the egress MTU is discarded and
`Ip4ForwardHandler._emit_frag_needed` sends ICMPv4 Destination
Unreachable / Fragmentation Needed (Type 3, Code 4) carrying the
egress interface MTU in the next-hop-MTU field (RFC 1191 §3), back
to the source, gated by the shared host-requirements gate + ICMP
error rate limiter. The ICMPv4 TX handler gained a
`DESTINATION_UNREACHABLE, FRAGMENTATION_NEEDED` dispatch arm
(`icmp4__destination_unreachable__frag_needed__send`). The
transit-forwarder row of the RFC 1191 PMTU record
[`../rfc1191__pmtud_ip4/adherence.md`](../rfc1191__pmtud_ip4/adherence.md)
references this emission.

## §5 Forwarding

The IPv4 **unicast** forward path is implemented across M1–M4: the
forward-or-deliver split (§5.2.1), next-hop determination via
the FIB (§5.2.4), the TTL decrement (§5.3.1), forwarded-packet
fragmentation + transit PMTU (§5.2.6 / §4.2.2.7 / §4.3.3.4, M2),
ICMP Redirect generation + RX-accept (§4.3.3.2, M3), and the M4
conformance items below. The `ip4.ip_forward` / `ip4.forwarding`
sysctls gate it (Linux `net.ipv4.ip_forward` /
`net.ipv4.conf.<iface>.forwarding`; default off = exact host
behaviour).

## §5.3.5.2 / §5.3.7 Forward-path filtering (M4)

> "A router MUST NOT forward a directed broadcast [§5.3.5.2 / RFC
> 2644] ... MUST verify the source address is plausible and MUST
> NOT forward datagrams with a martian source or destination
> [§5.3.7]."

**Adherence:** met (M4). The forward-destination martian filter in
`Ip4ForwardHandler.try_forward_ip4` drops loopback / unspecified /
limited-broadcast / link-local / multicast destinations **and** the
directed broadcast of any directly-connected subnet
(`stack.is_ip4_broadcast`, RFC 2644 default-off). Source-address
validation happens ahead of the forward branch: the parser sanity
check rejects broadcast / multicast / reserved sources, and
`_phrx_ip4` drops a datagram whose source is a locally-connected
directed broadcast (`ip4__src_directed_broadcast__drop`) — so a
martian-source datagram never reaches the forward path. The
deliver-or-forward decision runs local delivery first, so a
locally-destined low-TTL datagram is delivered (never Time
Exceeded). IPv6 link-local scope (source or destination) is
enforced in the IPv6 forward path (`ip6__forward_scope__drop`, RFC
4007).

## §5.2.4 IP options on forwarded datagrams (M4)

**Adherence:** met (M4) for **preservation**. The forward path
re-emits the received IPv4 datagram byte-for-byte apart from the
TTL decrement and header-checksum recomputation, so header options
(Record-Route, Timestamp, Router Alert, CIPSO, …) are carried
across the forward unchanged and the header length is preserved.

**Deferred (a §5.2.4 SHOULD refinement):** active option
**processing** on forward — appending the router's address to a
Record-Route option or a timestamp/address pair to a Timestamp
option — is not yet performed; the options are forwarded
faithfully but not mutated. LSRR/SSRR **source-route forwarding**
(pointer advance + destination rewrite) is likewise deferred:
inbound source-routed datagrams are dropped at the IPv4 RX gate by
default (`ip4.accept_source_route=False`, Linux parity), so they
never reach the forward branch.

---

## Test coverage audit

### §4.3.2.8 ICMP error rate limiting

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/icmp/test__icmp__rate_limiter.py`
  Token-bucket algorithm under sustained / burst load.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  ICMP Parameter Problem / Destination Unreachable rate-limit
  suppression paths.

**Status:** locked in.

### §4.2.2.8 Reassembly only on final-destination datagrams

- **Verification by code structure**, not by dedicated test.
  The RX dispatch ordering (destination filter at line 149,
  fragmentation branch at line 171) makes "reassemble in
  transit" structurally impossible until forwarding lands.

**Status:** locked in indirectly.

### §4.2.2.9 / §4.3.3.5 / §4.3.3.1 / §5 IPv4 unicast forwarding (M1)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/router/test__router__ip4__forwarding.py`
  on the three-interface `RouterTestCase` topology — happy-path
  forward out a connected LAN and via the default gateway (TTL
  decrement, correct egress + next-hop MAC, byte-identical
  payload, valid recomputed checksum, ingress isolation); TTL=1
  → ICMPv4 Time Exceeded; no route → ICMPv4 Destination
  Unreachable; martian destination / oversize / unresolved
  next-hop drops; forwarding-disabled host-parity drop.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__forwarding_sysctl.py`
  the `ip4.ip_forward` / `ip4.forwarding` knob registration,
  defaults, validation, and per-interface scope.

**Status:** locked in (M1 scope).

### §4.2.2.7 / §4.3.3.4 / §4.2.3.3 IPv4 transit PMTU + fragmentation (M2)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/router/test__router__ip4__forwarding.py`
  — DF=1 oversize → ICMPv4 Fragmentation Needed (Type 3, Code 4)
  carrying the egress MTU; DF=0 oversize → multiple fragments on
  the egress interface, each fitting the MTU, preserving
  src/dst/Identification, carrying the decremented TTL, with
  contiguous offsets and MF flags, reassembling to the original
  UDP datagram byte-for-byte.

**Status:** locked in (M2 scope).

### §4.3.3.2 ICMP Redirect generation + RX-accept (M3)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/router/test__router__ip4__forwarding.py`
  and `.../test__router__ip6__forwarding.py` — hairpin forward
  (ingress == egress) emits an ICMPv4 / ICMPv6 Redirect with the
  correct gateway/target while still forwarding; cross-interface
  forward emits none; `send_redirects=0` suppresses; an inbound
  ICMPv4 Redirect with an on-link gateway installs a
  `RouteProtocol.REDIRECT` host route (and is ignored when
  `accept_redirects=0`).
- **Unit (wire codec):**
  `packages/net_proto/net_proto/tests/unit/protocols/icmp4/test__icmp4__message__redirect__*.py`
  — the new ICMPv4 Redirect message asserts / assembler / parser /
  integrity-check matrix.

**Status:** locked in (M3 scope).

### §5.3.5.2 / §5.3.7 / §5.2.4 forward-path filtering + options (M4)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/router/test__router__rfc1812_conformance.py`
  — directed-broadcast forward-destination drop; local delivery
  precedes the forward branch (low-TTL local datagram not Time
  Exceeded); martian-source datagram dropped before forward;
  IPv4 options preserved byte-for-byte across a forward. IPv6
  link-local source/destination scope drops in
  `.../test__router__ip6__forwarding.py`.

**Status:** locked in (M4 scope).

### Remaining Phase-2 gaps (deferred with rationale)

1. Host Unreachable (Code 1) on next-hop resolution hard-failure
   — needs a neighbor-cache probe-exhaustion callback (see §4.3.3.1).
2. Active IP-options processing on forward (Record-Route /
   Timestamp append) and LSRR/SSRR source-route forwarding — a
   §5.2.4 SHOULD refinement; options are preserved but not mutated,
   and source-routed datagrams are dropped at the RX gate by
   default (see §5.2.4).
3. RPF / ingress-filter checks; §4.2.2.4 TOS routing; §4.2.2.10
   multi-subnet broadcasts — policy-routing / multi-homing
   features tracked for later phases.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4.2.2.9 TTL decrement + Time Exceeded (M1)         | locked in |
| §4.2.2.5 Header checksum recomputation (M1)         | locked in |
| §4.3.3.1 Destination Unreachable on no route (M1)   | locked in |
| §4.3.3.5 ICMP Time Exceeded emission (M1)           | locked in |
| §5 unicast forward-or-deliver + next-hop (M1)       | locked in |
| §4.2.2.7 / §4.3.3.4 transit PMTU + fragmentation (M2) | locked in |
| §4.3.2.8 ICMP error rate limiting                   | locked in |
| §4.2.2.8 No in-transit reassembly                   | locked in by code structure |
| §4.3.3.2 (M3) / §4.2.2.1-2 (M4)                      | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §4.2.2.1 IP options preserved on forward            | met (M4); active RR/TS append deferred |
| §4.2.2.5 Header checksum recomputation              | met (M1) |
| §4.2.2.7 Fragmentation on forward                   | met (M2) |
| §4.2.2.8 No reassembly in transit                   | met by absence (host-side reassembly intact) |
| §4.2.2.9 TTL decrement + Time Exceeded              | met (M1) |
| §4.2.3.1 IP broadcast handling                      | inherited from RFC 1122 host audit |
| §4.2.3.3 PMTUD (router side)                        | met (M2) — transit Frag-Needed with egress MTU |
| §4.3.2.8 ICMP error rate limiting                   | met    |
| §4.3.3.1 Destination Unreachable on no route        | met (M1) |
| §4.3.3.2 ICMP Redirect (emission + RX accept)       | met (M3) |
| §4.3.3.4 ICMP Fragmentation Needed (transit PMTU)   | met (M2) |
| §4.3.3.5 ICMP Time Exceeded emission                | met (M1) |
| §5.3.5.2 / §5.3.7 forward-path filtering            | met (M4) |
| §5.2.4 IP options on forward (preservation)         | met (M4) |
| §5 Forwarding plane (unicast)                       | met (M1–M4) |

**The IPv4 unicast forwarding plane is complete (M1–M4).** As of
3.0.9 PyTCP forwards IPv4 unicast transit traffic; decrements the
TTL and originates Time Exceeded on expiry; emits Destination
Unreachable on no route; fragments a DF=0 oversize datagram and
emits Fragmentation Needed (transit PMTU) for a DF=1 one;
generates ICMP Redirects on a same-interface forward and accepts
inbound Redirects host-side; filters martian / directed-broadcast
destinations and martian sources; and preserves IP options across
a forward. A small set of §5.2.4 SHOULD refinements (active
Record-Route / Timestamp append, LSRR/SSRR source-route
forwarding), Host Unreachable on next-hop hard-failure, and the
policy-routing / RPF / multipath features are deferred with
rationale (see "Remaining Phase-2 gaps" above). Default-off
forwarding keeps the Phase-1 host posture byte-for-byte intact.
