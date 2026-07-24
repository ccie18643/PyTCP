# RFC 1812 — Requirements for IP Version 4 Routers

| Field       | Value                                 |
|-------------|---------------------------------------|
| RFC number  | 1812                                  |
| Title       | Requirements for IP Version 4 Routers |
| Category    | Standards Track                       |
| Date        | June 1995                             |
| Source text | [`rfc1812.txt`](rfc1812.txt)          |

As of PyTCP 3.0.9 (Phase-2 milestone M1) the stack forwards IPv4
unicast transit traffic, so the §4.3.3 ICMP error clauses a
forwarder must originate — Time Exceeded on TTL expiry and
Destination Unreachable on no route — are now **met** (see the
companion IPv4 record
[`../../ip4/rfc1812__router_requirements/adherence.md`](../../ip4/rfc1812__router_requirements/adherence.md)).
The §4.3.2 rate-limiting and source-address rules are reused on
the transit-error path.

Currently relevant clauses, as of the ICMP host-requirements work
plus the M1 transit-forwarding plane:

- **§4.3.2.5 (Source Address)** — outbound ICMP errors source from
  the interface facing the original sender. Adherence: met. For a
  host-delivered datagram the UDP closed-port path reflects
  `ip4__src=packet_rx.ip4.dst`
  (`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`);
  for a **transit** datagram — whose destination is not ours to
  reflect — the forward path selects the ingress interface's
  address toward the source via
  `select_ip4_source(packet_rx.ip4.src)`
  (`packet_handler__ip4__forward.py::_emit_forward_icmp_error`).
- **§4.3.3.1 (Destination Unreachable — no route)** — a router
  MUST send Destination Unreachable (Code 0, network unreachable)
  when it has no route for a forwarded datagram. Adherence: met
  (M1) via `Ip4ForwardHandler._emit_dest_unreachable`; the ICMPv4
  TX handler has a `DESTINATION_UNREACHABLE, NETWORK` dispatch arm
  (`icmp4__destination_unreachable__network__send`). Tested at
  `packages/pytcp/pytcp/tests/integration/router/test__router__ip4__forwarding.py`.
- **§4.3.3.5 (Time Exceeded)** — a router MUST send Time Exceeded
  (Code 0) when it discards a forwarded datagram whose TTL
  decremented to zero. Adherence: met (M1) via
  `Ip4ForwardHandler._emit_time_exceeded`; the ICMPv4 TX handler
  has a `TIME_EXCEEDED` dispatch arm (`icmp4__time_exceeded__send`).
  Tested in the same router integration file.
- **§4.3.3.4 (Fragmentation Needed — transit PMTU)** — a router
  MUST send Destination Unreachable / Fragmentation Needed (Code
  4) with the next-hop MTU when it must fragment a DF=1 forwarded
  datagram. Adherence: met (M2) via
  `Ip4ForwardHandler._emit_frag_needed`, which carries the egress
  interface MTU (RFC 1191 §3); the ICMPv4 TX handler has a
  `DESTINATION_UNREACHABLE, FRAGMENTATION_NEEDED` dispatch arm
  (`icmp4__destination_unreachable__frag_needed__send`). Tested in
  the same router integration file. (The IPv6 parallel — ICMPv6
  Packet Too Big on transit oversize — is audited under the icmp6
  RFC 4443 record.)
- **§4.3.3.2 (Redirect — emission + RX accept)** — a router SHOULD
  send an ICMP Redirect (Type 5) advising a better first hop when
  it forwards a datagram back out the interface it arrived on, and
  a host MAY act on an inbound Redirect (RFC 1122 §3.3.1.2).
  Adherence: met (M3). Emission:
  `Ip4ForwardHandler._maybe_emit_redirect` (Code 1, host redirect;
  gated by `ip4.send_redirects`); the ICMPv4 Redirect wire codec is
  new (`Icmp4Type.REDIRECT = 5`,
  `icmp4__message__redirect.py`) with a full net_proto unit-test
  matrix, and the ICMPv4 TX handler has a `REDIRECT` dispatch arm
  (`icmp4__redirect__send`). RX-accept:
  `Icmp4RxHandler.__phrx_icmp4__redirect` installs a
  `RouteProtocol.REDIRECT` host route toward an on-link gateway,
  gated by `ip4.accept_redirects`. Tested in the router
  integration files.
- **§4.3.2.8 (Rate-Limiting)** — token-bucket rate limit on
  originated ICMP error messages. Adherence: met (post-Phase α1.1).
  Implemented in `packages/pytcp/pytcp/protocols/icmp/icmp__error_emitter.py`
  via `IcmpErrorRateLimiter`; instantiated per-version on
  `pytcp.stack.icmp4_error_rate_limiter` and consumed by
  `try_emit_icmp_error()` from the UDP closed-port path. Default
  rate=100 pps, burst=50.
- **§4.3.3.6 (Echo Request / Reply)** — MUST NOT reply to bcast/
  mcast Echo Request. Adherence: met (post-A1) via
  `packages/pytcp/pytcp/protocols/icmp4/icmp4__echo_gate.py::should_emit_echo_reply`.
  The MUST form (RFC 1812) is stricter than the MAY form
  (RFC 1122 §3.2.2.6) — PyTCP applies the stricter rule even
  though it is a host, because the same Smurf vector applies.

For the canonical host-side audit of the §3.2.2 rules, see
[`../rfc1122__host_requirements_icmp/adherence.md`](../rfc1122__host_requirements_icmp/adherence.md).

The full per-section RFC 1812 walkthrough is deferred — the
remaining router-side ICMP work (Host Unreachable on next-hop
hard-failure) and non-ICMP sections (routing protocols,
source-route processing) land with later Phase-2 milestones.
