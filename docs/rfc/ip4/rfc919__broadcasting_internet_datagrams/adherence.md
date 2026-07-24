# RFC 919 — Broadcasting Internet Datagrams

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 919                                            |
| Title       | Broadcasting Internet Datagrams                |
| Category    | Internet Standard (STD 5)                      |
| Date        | October 1984                                   |
| Source text | [`rfc919.txt`](rfc919.txt)                     |

This document records the PyTCP codebase's adherence to RFC 919
clause by clause. RFC 919 defines the IPv4 broadcast addressing
forms and the broadcast forwarding/reception rules. PyTCP
implements the host-side reception and source-address-
replacement aspects; the gateway-side broadcast forwarding
rules are Phase 2 (covered by RFC 1812 audit when forwarding
lands).

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_address.py`,
`packages/net_addr/net_addr/ip4_network.py`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py`, and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__tx.py`
directly; no prior memory or rule-file content was reused.
Non-normative content (§1 Introduction, §2 Why Broadcasts, §3
History, §4 Broadcast Classes discussion, §8 Acknowledgments)
is omitted.

---

## Top-line adherence

PyTCP **meets** the host-side broadcast rules from RFC 919:

- The limited-broadcast address `255.255.255.255` is
  recognised on receive and rejected as a source address.
- Network-broadcast `{net, -1}` addresses are recognised
  per-`Ip4IfAddr` and admitted on receive.
- TX-side source replacement honours the host-stack policy
  (replace bcast/mcast source with primary unicast).

The §6 gateway broadcast-forwarding rules are Phase 2.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §5      | Host MUST recognise broadcast destinations         | met    |
| §6      | Gateway broadcast forwarding rules                 | n/a (Phase 2) |
| §7      | All-ones host-number = broadcast                   | met    |
| §7      | `255.255.255.255` = local hardware broadcast       | met    |
| §7      | `255.255.255.255` MUST NOT be forwarded            | n/a (no forwarding) |

---

## §5 Broadcast Methods (host-side reception)

> "A host's IP receiving layer must be modified to support
> broadcasting. ... With broadcasting, a host must compare the
> destination address not only against the host's addresses,
> but also against the possible broadcast addresses for that
> host."

**Adherence:** met. The RX handler admits a locally-addressed
datagram via `_forward_or_deliver_ip4`
(`packet_handler__ip4__rx.py:180`), then tests the destination
separately against `_if._ip4_unicast` (`:183`),
`_if._ip4_multicast` (`:186`), and `_if._ip4_broadcast`
(`:189`) — admitting any of the three. The
`_ip4_broadcast` set is populated at boot from each
`Ip4IfAddr.network.broadcast` (`Ip4Network.broadcast` is the
{net, subnet, -1} address) plus the limited broadcast
`255.255.255.255`.

## §7 Broadcast IP Addressing — All-Ones host-number

> "The number whose bits are all ones ... is the broadcast
> host number."

**Adherence:** met. `Ip4Network.broadcast` is computed as
"network | ~mask" — yielding the all-ones host-number form.
`Ip4Address.is_limited_broadcast` recognises the
`255.255.255.255` special case.

> "The address 255.255.255.255 denotes a broadcast on a local
> hardware network, which must not be forwarded."

**Adherence:** met for the host-side half: PyTCP does not
forward, so the "must not be forwarded" constraint is
vacuously satisfied. The receive path admits frames addressed
to `255.255.255.255` when it appears in `_ip4_broadcast`.

On send, `255.255.255.255` is the canonical DHCPv4
broadcast address; the TX path admits it as a destination
under the `ip4.allow_broadcast` policy sysctl (default 0)
or unconditionally on the DHCP-client RFC 2131 §3.1 path
(`src=0.0.0.0`, UDP sport=68/dport=67), which always
bypasses the gate. Operators that need to originate
broadcast traffic from other consumers flip the sysctl
explicitly; without the override, an outbound broadcast
emission is dropped with
`TxStatus.DROPPED__IP4__DST_BROADCAST_DISALLOWED` and the
`ip4__dst_broadcast_disallowed__drop` counter bumps. The
gate mirrors the Linux per-socket `SO_BROADCAST` default-
off discipline at the IPv4 layer.

## §7 Limited-broadcast as source-address ban

> "[Limited broadcast] MUST NOT be used as a source address."
> (cross-reference RFC 1122 §3.2.1.3)

**Adherence:** met. `Ip4Parser._validate_sanity` rejects any
inbound frame whose source matches `Ip4Address.is_limited_broadcast`
with `Ip4SanityError(pointer=12)`
(`ip4__parser.py:154-158`). The handler emits ICMP
Parameter Problem subject to the rate limit.

On send, a caller-supplied broadcast source is replaced with
the stack's primary unicast address before assembly
(`packet_handler__ip4__tx.py:289-306`); if no replacement is
possible the frame is dropped with the documented counter.

## §6 Gateway broadcast forwarding (Phase 2)

> "When a gateway receives a local broadcast datagram, there
> are several things it might have to do with it. ... The
> primary rule for avoiding loops is 'never broadcast a
> datagram on the hardware network it was received on'."

**Adherence:** n/a (PyTCP does not forward). When forwarding
lands, these rules become relevant. See RFC 1812 audit (Phase
2) for the router-grade broadcast handling.

---

## Test coverage audit

### §5 / §7 RX admission of broadcast destinations

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Covers limited-broadcast and network-broadcast destination
  admission paths.

**Status:** locked in.

### §7 Source-address sanity (limited-broadcast ban)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Per-branch rejection with `pointer=12`.

**Status:** locked in.

### TX source-address replacement (broadcast source → primary unicast)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Matrix for src=limited-broadcast, src=network-broadcast.

**Status:** locked in.

### TX broadcast-destination policy gate (`ip4.allow_broadcast`)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/test__ip4__constants.py::TestIp4AllowBroadcastSysctl`
  Pins the default value (0), the registration, the
  validator's {0, 1} acceptance, and the rejection of
  out-of-range / non-int / bool values.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py::TestIp4TxRfc919AllowBroadcast`
  Drives the gate: default-deny drops both
  255.255.255.255 and the subnet-directed broadcast with
  the new TxStatus and counter bump; override-on permits
  the same; the DHCP-client (src=0.0.0.0, sport=68/
  dport=67) path bypasses; unicast destinations
  unaffected.

**Status:** locked in.

### Phase-2 gateway broadcast rules

**No test surface — n/a (Phase 2).**

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §5 RX admission of broadcast destinations           | locked in |
| §7 Limited-broadcast source rejection (RX)          | locked in |
| §7 Broadcast source replacement (TX)                | locked in |
| TX broadcast policy gate (`ip4.allow_broadcast`)    | locked in (unit + integration) |
| §6 Gateway broadcast forwarding                     | n/a (Phase 2) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §5 Host-side broadcast reception                    | met    |
| §7 All-ones broadcast address recognised            | met    |
| §7 Limited-broadcast source ban                     | met    |
| §6 Gateway broadcast forwarding rules               | n/a (Phase 2) |

RFC 919 is fully covered for the host-stack portion. The
subnetting refinement in RFC 922 (audited separately) extends
this picture; the gateway-side rules in §6 are Phase-2 router
work tracked under RFC 1812.
