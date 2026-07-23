# RFC 1112 — Host Extensions for IP Multicasting

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 1112                                           |
| Title       | Host Extensions for IP Multicasting            |
| Category    | Internet Standard (STD 5)                      |
| Date        | August 1989                                    |
| Source text | [`rfc1112.txt`](rfc1112.txt)                   |

This document records the PyTCP codebase's adherence to RFC 1112
clause by clause. RFC 1112 defines three conformance levels:

- **Level 0:** no multicast support; class D destinations
  silently discarded.
- **Level 1:** send-only multicast support.
- **Level 2:** full multicast support (send + receive + IGMP
  group membership).

PyTCP today is **Level 2**: it can send and receive multicast
IP datagrams and implements IGMP group management (IGMPv3,
RFC 3376, with the legacy v2/v1 report forms). The all-hosts
group (224.0.0.1) is joined permanently at interface bring-up;
applications join/leave further groups through the membership
API (`stack.membership` / the `IP_ADD_MEMBERSHIP` /
`IP_DROP_MEMBERSHIP` socket options), each change emitting the
corresponding IGMPv3 state-change Report. The detailed IGMP
audit lives in the RFC 3376 / RFC 2236 adherence records
alongside this one.

The audit was performed by reading the RFC text fresh and
inspecting `packages/net_addr/net_addr/ip4_address.py`,
`packages/pytcp/pytcp/stack/__init__.py`, and the IPv4 packet handlers
directly. Non-normative content (§1 Status, §2 Introduction,
§9 ICMP, §10 IANA / Appendices) is omitted.

---

## Top-line adherence

| Section | Topic                                                    | Status |
|---------|----------------------------------------------------------|--------|
| §3      | Conformance Level 0/1/2                                  | Level 2 (send + receive + IGMP) |
| §4      | Class D host-group addresses (224.0.0.0 - 239.255.255.255) | met |
| §4      | 224.0.0.1 = all hosts (permanent)                        | met (joined at bring-up) |
| §6      | Sending multicast datagrams                              | met    |
| §7      | Receiving multicast datagrams                            | met (for joined groups) |
| §7      | IGMP group management                                    | met (IGMPv3; see RFC 3376 record) |
| §6.4    | Ethernet mapping (high-23-bits)                          | met    |

---

## §4 Host Group Addresses

> "Host groups are identified by class D IP addresses, i.e.,
> those with '1110' as their high-order four bits."

**Adherence:** met. `Ip4Address.is_multicast` recognises 224/4
(`packages/net_addr/net_addr/ip4_address.py:204-210`):

```python
return self._address & 0xF0_00_00_00 == 0xE0_00_00_00
```

> "224.0.0.1 is assigned to the permanent group of all IP
> hosts (including gateways)."

**Adherence:** met. The all-hosts group is preconfigured in
the stack's `_ip4_multicast` list at boot
(`packages/pytcp/pytcp/runtime/packet_handler/__init__.py`).

## §6.1 Sending — IP Service Interface

> "First, the service interface should provide a way for the
> upper-layer protocol to specify the IP time-to-live of an
> outgoing multicast datagram, if such a capability does not
> already exist. If the upper-layer protocol chooses not to
> specify a time-to-live, it should default to 1 for all
> multicast IP datagrams."

**Adherence:** met (shipped). The TX entry point
`_phtx_ip4` accepts `ip4__ttl: int | None = None` and resolves
the default at the top via:

```python
if ip4__ttl is None:
    ip4__ttl = 1 if ip4__dst.is_multicast else IP4__DEFAULT_TTL
```

(`packet_handler__ip4__tx.py:103-108`). Callers that omit
`ip4__ttl` get TTL=1 on multicast destinations and the legacy
`IP4__DEFAULT_TTL = 64` on unicast destinations. Callers that
pass an explicit TTL value have it preserved verbatim, so the
"explicit choice required to multicast beyond a single
network" half of the §6.1 contract is also honoured.

> "For hosts that may be attached to more than one network,
> the service interface should provide a way for the upper-
> layer protocol to identify which network interface is be
> used for the multicast transmission."

**Adherence:** n/a — single interface (Phase 1).

## §6.2 Sending — IP Module

> "When the IP module sees an upper-layer 'send IP datagram'
> request whose destination is a class D address, it must
> translate the address to the corresponding local network
> multicast address before passing the datagram and address to
> the local network module."

**Adherence:** met. `Ip4Address.multicast_mac` maps the
high-23-bits of the IPv4 multicast address into the
`01:00:5E:` MAC prefix (`packages/net_addr/net_addr/ip4_address.py:120-131`). The
Ethernet TX path consumes this when resolving the destination
MAC for multicast frames
(`packet_handler__ethernet__tx.py`).

## §6.3 / §6.4 Local Network Module Extensions (Ethernet mapping)

> "An IP host group address is mapped to an Ethernet multicast
> address by placing the low-order 23 bits of the IP address
> into the low-order 23 bits of the Ethernet multicast address
> 01-00-5E-00-00-00 (hex)."

**Adherence:** met. `Ip4Address.multicast_mac`
(`packages/net_addr/net_addr/ip4_address.py:120-131`) returns
`MacAddress(MAC__IP4_MULTICAST_PREFIX | self._address & 0x7F_FFFF)`
which is exactly the high-23-bits mapping.

## §7 Receiving Multicast IP Datagrams

> "[Level 2] In order to receive multicast datagrams sent to a
> particular host group, the host must JOIN the group."

**Adherence:** met. The all-hosts group is joined at interface
bring-up and applications JOIN / LEAVE further groups through
the membership API (`stack.membership.join` / `.leave`, or the
`IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP` socket options),
which add / remove the group on the per-interface
`_ip4_multicast` list. The RX path
(`packet_handler__ip4__rx.py`) accepts any inbound datagram
whose destination is in that list.

> "Level 2 ... requires implementation of the Internet Group
> Management Protocol (IGMP)."

**Adherence:** met. PyTCP implements IGMPv3 (RFC 3376) with the
legacy v2/v1 report forms: a membership change emits an
unsolicited state-change Report (retransmitted per the
Robustness Variable), and inbound Membership Queries elicit a
current-state Report after the §5.2 random delay. The detailed
audit is in the RFC 3376 and RFC 2236 records. The
querier-version (v1/v2) fallback state machine (RFC 3376 §7)
is also implemented — an older-version Query flips the
interface into IGMPv2/v1 Host Compatibility Mode (see
`test__igmp__version_fallback.py`).

## §9 ICMP

The original RFC 1112 §9 noted that ICMP error generation in
response to multicast packets needs special-case rules.
RFC 1122 §3.2.2 and the ICMP audit
(`docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`)
cover the canonical "do not emit ICMP error to a multicast
source / multicast destination" rules. PyTCP's
`packages/pytcp/pytcp/protocols/icmp/icmp__inbound_classifier.py` enforces
these gates.

---

## Test coverage audit

### §4 Class D multicast predicate

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  Parametric matrix verifying `is_multicast` for addresses
  inside and outside 224/4.

**Status:** locked in.

### §6.4 IP-to-Ethernet multicast MAC mapping

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  Multicast MAC mapping cases (e.g., 224.0.0.1 →
  01:00:5e:00:00:01).

**Status:** locked in.

### §7 RX admission of joined multicast groups

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  All-hosts (224.0.0.1) admission path.

**Status:** locked in.

### §6.1 Multicast outbound TTL default = 1

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc1112MulticastTtl`
  Three cases: multicast dst + no caller TTL → TTL=1;
  multicast dst + caller-supplied TTL → caller value
  preserved; unicast dst + no caller TTL → TTL=64
  regression net.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ethernet__tx.py`
  `Ethernet/IPv4 - dst multicast address` case pins the
  full TX frame including TTL=1 in the IPv4 header byte 8.

**Status:** locked in.

### §7 IGMP group management (membership + reports)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_api.py`
  and `test__igmp__socket_membership_opts.py` — JOIN / LEAVE
  via `stack.membership` and the `IP_ADD_MEMBERSHIP` /
  `IP_DROP_MEMBERSHIP` socket options.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py`,
  `test__igmp__query_response.py`,
  `test__igmp__robustness_retransmit.py` — state-change
  Reports on join/leave, query-elicited Reports, robustness
  retransmits. Full per-clause detail is in the RFC 3376
  record's test audit.

**Status:** locked in (IGMPv3). The §7 querier-version (v1/v2)
fallback is covered by `test__igmp__version_fallback.py` — see
the RFC 3376 record.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4 Multicast (224/4) predicate                      | locked in |
| §4 All-hosts (224.0.0.1) joined at bring-up         | locked in (RX + membership integration) |
| §6.4 Ethernet MAC mapping                           | locked in |
| §7 RX admission of joined groups                    | locked in |
| §7 IGMP group management                            | locked in (IGMPv3; RFC 3376 record) |
| §6.1 Multicast-default TTL=1                        | locked in |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3 Conformance level                                | Level 2 (send + receive + IGMP) |
| §4 Class D multicast addressing                     | met    |
| §4 All-hosts (224.0.0.1) joined at bring-up        | met    |
| §6.1 Multicast-default TTL=1                       | met    |
| §6.2 / §6.4 IP-to-Ethernet MAC mapping             | met    |
| §7 RX admission for joined groups                  | met    |
| §7 IGMP group management                            | met (IGMPv3; RFC 3376 record) |

PyTCP reaches RFC 1112 Level 2: multicast send + receive plus
IGMP group management, including the RFC 3376 §7 querier-version
(v1/v2) Host Compatibility Mode fallback (audited in the
RFC 3376 record).
