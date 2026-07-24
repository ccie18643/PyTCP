# RFC 6980 — Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6980                                              |
| Title       | Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery |
| Category    | Standards Track (Updates RFC 3971, RFC 4861)      |
| Date        | August 2013                                       |
| Source text | [`rfc6980.txt`](rfc6980.txt)                      |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 6980 §5.

**TX side** (MUST NOT send): the ND emit path
(`packet_handler__icmp6__tx.py`) builds each ND message as a
single IPv6 packet sized below the link MTU and never
invokes the IPv6 fragmentation extension header for ND
traffic. The MUST-NOT-send half holds by construction —
there is no codepath that would request fragmentation of
an ND message — and is additionally enforced by an
explicit defensive gate in
`packet_handler__ip6_frag__tx.py::_phtx_ip6_frag`: the
`is_ndp_message(ip6_packet_tx.payload)` predicate (also
exported from the same module for unit testing) returns
True for any Icmp6Assembler whose message type is in
{ND__ROUTER_SOLICITATION, ND__ROUTER_ADVERTISEMENT,
ND__NEIGHBOR_SOLICITATION, ND__NEIGHBOR_ADVERTISEMENT,
ND__REDIRECT}; the gate returns
`TxStatus.DROPPED__IP6__ND_FRAGMENTATION_FORBIDDEN` and
bumps the `ip6_frag__nd_message__drop` counter. The gate
is dead code under normal operation (every ND message
PyTCP emits today fits in a single MTU) but defends
against hypothetical future code paths that might compose
oversized ND options.

**RX side** (MUST silently ignore on receipt if
fragmented): a new `was_fragmented: bool` attribute on
`PacketRx` (defaults to False) is set to True by the IPv6
frag-RX handler on the reassembled `PacketRx` it forwards
back into the IPv6 chain walker. The ICMPv6 RX dispatch in
`_phrx_icmp6` adds a gate immediately after parsing: if
`was_fragmented` is set and the message type is one of
NS / NA / RS / RA, the message is silently dropped, the
`icmp6__nd_message__fragmented__drop` counter increments,
and no per-type handler runs.

---

## §1 Background — motivation

> "The IPv6 stateless address autoconfiguration mechanism
> [RFC4862] uses Neighbor Discovery messages [RFC4861] to
> obtain configuration information from routers... Several
> attacks against the Neighbor Discovery protocol leverage
> IPv6 fragmentation to evade firewalls and similar
> filtering devices."

**Adherence:** N/A (motivation). The §5 silent-discard
requirement removes the attack surface.

## §3 Scenarios — non-conformant cases

> "It is possible for an attacker, possibly off-link, to
> send fragmented Neighbor Discovery messages..."

**Adherence:** N/A (analysis). PyTCP's gate prevents the
described scenarios from completing.

## §5 Specification — the normative MUST

> "Nodes MUST NOT employ IPv6 fragmentation for sending any
> of the following Neighbor Discovery and SEcure Neighbor
> Discovery messages: Neighbor Solicitation, Neighbor
> Advertisement, Router Solicitation, Router Advertisement,
> Redirect, or Certification Path Solicitation."

**Adherence:** shipped (TX side, by construction). Each of
the relevant ND emit sites in
`packet_handler__icmp6__tx.py` builds a single
`Ip6Assembler` per message and dispatches to `_phtx_ip6` —
which only invokes the fragment-emission machinery when
the fully-assembled IPv6 datagram exceeds the MTU. Since
ND messages are well below the IPv6 minimum MTU of 1280
bytes (NS/NA: 24 + options; RS/RA: 8/16 + options;
typically <100 bytes), fragmentation never fires.

> "Nodes MUST silently ignore any of these messages on
> receipt if fragmented."

**Adherence:** shipped (RX side). The gate in
`_phrx_icmp6`:

```python
if packet_rx.was_fragmented and packet_rx.icmp6.message.type in {
    Icmp6Type.ND__ROUTER_SOLICITATION,
    Icmp6Type.ND__ROUTER_ADVERTISEMENT,
    Icmp6Type.ND__NEIGHBOR_SOLICITATION,
    Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
    Icmp6Type.ND__REDIRECT,
}:
    self._if._packet_stats_rx.icmp6__nd_message__fragmented__drop += 1
    return
```

PyTCP implements Redirect: `Icmp6Type.ND__REDIRECT` (137) is
defined (`icmp6__message.py:68`), the parser materialises an
`Icmp6NdMessageRedirect`, a dedicated
`__phrx_icmp6__nd_redirect` handler
(`packet_handler__icmp6__rx.py:1082`) consumes it into the ND
cache, and — as shown above — the fragmentation gate covers
`ND__REDIRECT` so fragmented Redirects are silently dropped
alongside the other four ND types. SEcure Neighbor
Discovery's Certification Path Solicitation is out of scope
per the North Star (SEND is a deliberately-skipped crypto
extension — see RFC 8504 §5.5).

The gate's scope is intentionally limited to ND types;
fragmented Echo Requests / Replies and other ICMPv6
messages still progress to their handlers normally —
RFC 6980 §5 silent-discard applies only to ND / SEND.

## §6 Security Considerations

> "This document mitigates Neighbor Discovery vulnerabilities
> arising from the use of IPv6 fragmentation."

**Adherence:** shipped. The gate eliminates the firewall-
evasion and reassembly-DoS vectors §3 describes.

---

## Test coverage audit

| Clause | Test file / class |
|--------|-------------------|
| Fragmented NS silent-drop + counter | `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp6__rx.py::TestPacketHandlerIcmp6RxNd::test__stack__packet_handler__icmp6__rx__fragmented_neighbor_solicitation_dropped` |
| Gate scope is ND-only (Echo Request still passes) | Same class :: `test__stack__packet_handler__icmp6__rx__fragmented_echo_request_passes_through` |
| `PacketRx.was_fragmented` defaults to False | Implicit — every existing icmp6 / ip6 / tcp / udp test constructs a `PacketRx` from a wire frame and runs to completion (none of which would happen if the new attribute were True by default) |
| `was_fragmented` set on reassembled PacketRx | Implicit — the gate's positive test only triggers because the IPv6 frag-RX handler sets the flag on its forwarded reassembled packet (commit's frag-rx edit) |

The TX side's MUST-NOT-send invariant is regression-pinned
implicitly: the ND emit code does not call
`_phtx_ip6_frag` and the integration tests assert single-
frame outputs for every ND emit.

---

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (MUST)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` — parent
  SLAAC record (DAD ND messages also covered by this
  silent-discard rule)
- Implementing commit: TBD (this commit)
