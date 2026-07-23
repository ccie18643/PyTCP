# RFC 1812 — Requirements for IP Version 4 Routers

| Field       | Value                                 |
|-------------|---------------------------------------|
| RFC number  | 1812                                  |
| Title       | Requirements for IP Version 4 Routers |
| Category    | Standards Track                       |
| Date        | June 1995                             |
| Source text | [`rfc1812.txt`](rfc1812.txt)          |

This adherence record is currently a stub. PyTCP is a host stack,
not a router, so most of RFC 1812 does not apply directly. The
RFC is included for reference because §4.3.2 and §4.3.3 prescribe
the canonical forms of the ICMP error messages PyTCP both sends
(Port Unreachable in response to closed-port datagrams) and
receives (Destination Unreachable, Frag-Needed/PTB during PMTUD).

Currently relevant clauses, as of the recent ICMP host-requirements
work:

- **§4.3.2.5 (Source Address)** — outbound ICMP errors source from
  the egress interface address. Adherence: met via
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:306`,
  which sets `ip4__src=packet_rx.ip4.dst` (reflection of the
  inbound destination, which is the stack's own address for
  unicast-delivered datagrams).
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

The full per-section RFC 1812 walkthrough is deferred — most
sections (gateway-side forwarding, routing protocols, source-route
processing) have no implementation surface in PyTCP.
