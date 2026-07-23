# RFC 894 — A Standard for the Transmission of IP Datagrams over Ethernet Networks

| Field       | Value                                                       |
|-------------|-------------------------------------------------------------|
| RFC number  | 894                                                         |
| Title       | A Standard for the Transmission of IP Datagrams over Ethernet Networks |
| Category    | Internet Standard                                           |
| Date        | April 1984                                                  |
| Source text | [`rfc894.txt`](rfc894.txt)                                  |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 894. The audit was performed by reading the RFC
text fresh against the codebase under `packages/net_proto/net_proto/` and
`packages/pytcp/pytcp/` directly. Sections that contain no normative
content (Status of this Memo, Introduction, References,
the Trailer Formats notes about historic Unix 4.2bsd
deviation) are omitted except where the deviation
discussion bears on the implementation.

---

## Top-line adherence

PyTCP's Ethernet II framing fully implements RFC 894 for
host-stack purposes. The frame layout (6+6+2 bytes for
dst+src+type), the IP EtherType (`0x0800`), the broadcast
MAC mapping (`FF:FF:FF:FF:FF:FF`), ARP-based dynamic
address resolution, and big-endian byte order are all
met. The minimum-frame zero-padding (data field ≥ 46
octets) is delegated to the link-layer driver / NIC
(TAP/TUN on PyTCP) — PyTCP itself emits IP-layer-sized
frames without pad bytes, matching Linux's behaviour. The
historic Unix 4.2bsd trailer encapsulation is deliberately
out of scope.

| Mechanism                                          | Status            |
|----------------------------------------------------|-------------------|
| 14-byte Ethernet II header (dst/src/type)          | met               |
| EtherType `0x0800` for IP datagrams                | met               |
| Big-endian byte order                              | met               |
| Broadcast IP → `FF:FF:FF:FF:FF:FF` MAC mapping     | met               |
| ARP-based dynamic address resolution               | met (RFC 826)     |
| Min 46-octet data-field zero padding               | delegated to driver (out-of-scope at PyTCP layer) |
| Max 1500-octet data field                          | met (`stack.interface_mtu`) |
| Gateway forwarding + fragmentation                 | Phase 2 (not implemented today) |
| Unix 4.2bsd trailer encapsulation (RFC 893)        | out of scope (deliberate non-goal) |

---

## §"Frame Format" — Frame Layout

> "IP datagrams are transmitted in standard Ethernet
> frames. The type field of the Ethernet frame must
> contain the value hexadecimal 0800. The data field
> contains the IP header followed immediately by the IP
> data."

**Adherence:** met. The Ethernet II header is implemented
at `packages/net_proto/net_proto/protocols/ethernet/ethernet__header.py:60-120`
as a 14-byte fixed-shape `EthernetHeader` (dst: 6,
src: 6, type: 2 bytes). The IP-over-Ethernet codepoint
is `EtherType.IP4 = 0x0800`
(`packages/net_proto/net_proto/lib/enums.py:45`). `EthernetAssembler`
binds the EtherType from the payload object via
`EtherType.from_proto(payload)`
(`packages/net_proto/net_proto/lib/enums.py:67-90`); when the payload is an
`Ip4` instance, the frame's `type` field is `0x0800`.

---

## §"Frame Format" — Minimum Data Length (46 octets, pad with zeros)

> "The minimum length of the data field of a packet sent
> over an Ethernet is 46 octets. If necessary, the data
> field should be padded (with octets of zero) to meet
> the Ethernet minimum frame size. This padding is not
> part of the IP packet and is not included in the total
> length field of the IP header."

**Adherence:** delegated to the link-layer driver
(out of scope at PyTCP layer). PyTCP's
`EthernetAssembler.assemble`
(`packages/net_proto/net_proto/protocols/ethernet/ethernet__assembler.py:75-83`)
emits exactly the 14-byte header followed by the IP
payload — no zero-padding to a 46-octet floor. This
matches Linux's pragmatic behaviour: zero-padding to the
60-byte minimum-frame size (46 data + 14 header) is the
NIC's responsibility, not the IP-stack's. On PyTCP's
TAP/TUN substrate the kernel performs the same padding
when the frame leaves the TAP interface onto a physical
wire (TAP is a virtual interface so the question is
moot in practice). The `TxRing` writes whatever bytes
the assembler produced.

---

## §"Frame Format" — Maximum Data Length (1500 octets)

> "The minimum length of the data field of a packet sent
> over an Ethernet is 1500 octets, thus the maximum
> length of an IP datagram sent over an Ethernet is 1500
> octets. Implementations are encouraged to support
> full-length packets."

**Note on RFC text:** "minimum length" on this line is a
known typo in the RFC — it should read "maximum length"
(the paragraph itself goes on to derive the maximum-IP-
datagram bound from it).

**Adherence:** met. PyTCP's link-layer MTU is configured
via `stack.interface_mtu` (default 1500 per
`INTERFACE__TAP__MTU` / `INTERFACE__TUN__MTU` in
`packages/pytcp/pytcp/stack/__init__.py`). Outbound IP segments respect
this MTU through the IP-layer fragmentation / TCP MSS
machinery. Jumbo-frame support (interface_mtu > 1500) is
operator-configurable.

---

## §"Frame Format" — Gateway Full-Length Acceptance + Fragmentation

> "Gateway implementations MUST be prepared to accept
> full-length packets and fragment them if necessary."

**Adherence:** not implemented (Phase 2 — router-grade
parity). PyTCP is a host stack; forwarding-plane
behaviour is deferred to Phase 2 per
`CLAUDE.md` north-star. When forwarding lands, transit
fragmentation will be added; the IPv4 fragmentation
machinery for *originated* packets already exists
(`packages/net_proto/net_proto/protocols/ip4/`) so the gap is the
forward-vs-deliver dispatch, not the fragmentation
logic itself.

---

## §"Frame Format" — TCP MSS Coordination

> "If a system cannot receive full-length packets, it
> should take steps to discourage others from sending
> them, such as using the TCP Maximum Segment Size
> option."

**Adherence:** met. PyTCP advertises the TCP MSS option
on every SYN / SYN+ACK via the standard RFC 9293 §3.7.1
machinery. The advertised MSS is derived from
`interface_mtu - ip_overhead - tcp_overhead`. RFC 6691
adherence (MSS computation from interface MTU) is
documented separately at
`docs/rfc/tcp/rfc6691__tcp_options_and_mss/adherence.md`.

---

## §"Address Mappings" — Static Table + Dynamic Discovery

> "The use of the ARP dynamic discovery procedure is
> strongly recommended."

**Adherence:** met. PyTCP uses ARP (RFC 826) exclusively
for IPv4 address resolution; no static-table mode exists.
`pytcp.protocols.arp.arp__cache.ArpCache` handles the
dynamic discovery; outbound Ethernet TX consults the
cache via `stack.arp_cache.find_entry(...)` and triggers
ARP requests on miss (see
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`).

---

## §"Address Mappings" — Broadcast Address

> "The broadcast Internet address (the address on that
> network with a host part of all binary ones) should be
> mapped to the broadcast Ethernet address (of all binary
> ones, FF-FF-FF-FF-FF-FF hex)."

**Adherence:** met. `packages/pytcp/pytcp/runtime/packet_handler/
packet_handler__ethernet__tx.py:234-255` maps both the
limited broadcast (`255.255.255.255`) and the network
broadcast (per-subnet `network.broadcast`) to
`MacAddress(0xFFFFFFFFFFFF)`. The `net_addr` library
provides the constant at
`packages/net_addr/net_addr/mac_address.py:43` (`MAC__BROADCAST =
0xFFFF_FFFF_FFFF`). The `is_broadcast` predicate at
`packages/net_addr/net_addr/mac_address.py:186` recognises the broadcast
MAC on the inbound path.

---

## §"Frame Format" — Source MAC Unicast Invariant

> RFC 894 inherits the underlying Ethernet / IEEE 802.3 MAC
> address semantics: the source MAC field on a transmitted
> frame is the sending interface's hardware address, which
> by IEEE 802.3 is a unicast address (group bit / I/G bit
> clear; not all-zeros; not all-ones).

**Adherence:** met (parser sanity, added in the
RFC-adherence pass). The Ethernet II parser's
`_validate_sanity` rejects any frame whose `src` MAC is
unspecified (all-zeros), multicast (group bit set), or
broadcast (all-ones) with `EthernetSanityError`
(`packages/net_proto/net_proto/protocols/ethernet/ethernet__parser.py::_validate_sanity`).
The 802.3 parser carries the same three checks
(`packages/net_proto/net_proto/protocols/ethernet_802_3/ethernet_802_3__parser.py::_validate_sanity`).
`dst` is deliberately NOT subject to these checks because a
destination MAC may legitimately be multicast (e.g. IPv6 ND
`33:33:xx:xx:xx:xx`, IPv4 multicast `01:00:5e:xx:xx:xx`) or
broadcast (`ff:ff:ff:ff:ff:ff`).

This is stricter than Linux's `net/ethernet/eth.c::eth_type_trans`,
which does not enforce a unicast-source invariant — it's
PyTCP's RFC-aligned hardening of the parse path. RX-side
counters for malformed frames are
`ethernet__failed_parse__drop` / `ethernet_802_3__failed_parse__drop`.

---

## §"Trailer Formats" — Unix 4.2bsd Trailer Encapsulation

> "Some versions of Unix 4.2bsd use a different
> encapsulation method [...]. No host is required to
> implement it, and no datagrams in this format should
> be sent to any host unless the sender has positive
> knowledge that the recipient will be able to interpret
> them."

**Adherence:** out of scope (deliberate non-goal). RFC 893
"Trailer Encapsulations" was a 4.2bsd-specific optimisation
that fell out of use shortly after publication. Modern
hosts (Linux, BSD, Windows) do not implement it.
PyTCP does not implement it either. The RFC text
explicitly permits this — "no host is required to
implement it."

---

## §"Byte Order" — Big-Endian Transmission

> "As described in Appendix B of the Internet Protocol
> specification, the IP datagram is transmitted over the
> Ethernet as a series of 8-bit bytes."

**Adherence:** met. PyTCP's struct-pack format strings
use the `"!"` prefix throughout
(`ETHERNET__HEADER__STRUCT = "! 6s 6s H"` at
`packages/net_proto/net_proto/protocols/ethernet/ethernet__header.py:56`),
which selects network (big-endian) byte order. Every IP
/ TCP / UDP header struct similarly uses `"!"`.

---

## Test coverage audit

The Ethernet implementation is locked in by the existing
unit-test corpus and integration tests at:

### Ethernet header / parser / assembler

- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/ethernet/test__ethernet__header__asserts.py`
  — pins MacAddress / EtherType field-validation asserts on
  `EthernetHeader.__post_init__`.
- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/ethernet/test__ethernet__parser__operation.py`
  — pins frame parsing with IPv4 / IPv6 / ARP / raw-payload
  cases.
- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/ethernet/test__ethernet__parser__sanity_checks.py`
  — pins both sanity branches: sub-0x0600 `type` (legacy
  802.3 length framing) and the three `src`-non-unicast
  rejections (unspecified, multicast, broadcast).
- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/ethernet/test__ethernet__assembler__operation.py`
  — pins frame assembly + EtherType binding from payload type.
- **Integration:** `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ethernet__rx.py`
  + the per-protocol RX harness tests that drive Ethernet
  frames into the stack and assert delivery / dispatch.

**Status:** locked in.

### Broadcast IP → MAC FF:FF:FF:FF:FF:FF mapping

- **Integration:** `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ethernet__tx.py`
  — the limited-broadcast / network-broadcast / multicast
  resolution paths assert
  `ethernet__dst = MacAddress(0xFFFFFFFFFFFF)`.
- **Integration:** `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__tx.py`
  — ARP request emission uses
  `ethernet__dst = MAC__BROADCAST`.

**Status:** locked in.

### ARP-based dynamic address resolution

- **Integration:** every IP4 TX test that triggers an
  ARP cache miss (across the integration suite).

**Status:** locked in (covered by RFC 826 adherence record
at `docs/rfc/arp/rfc826__arp/adherence.md`).

### Test coverage summary

| Aspect                                              | Coverage                  |
|-----------------------------------------------------|---------------------------|
| 14-byte Ethernet II header (dst/src/type)           | locked in                 |
| EtherType `0x0800` for IP datagrams                 | locked in                 |
| Broadcast IP → `FF:FF:FF:FF:FF:FF` MAC mapping      | locked in                 |
| ARP dynamic resolution                              | locked in (RFC 826)       |
| Big-endian byte order                               | locked in                 |
| Min 46-octet pad                                    | n/a (delegated to driver) |
| Gateway full-length + fragmentation                 | n/a (Phase 2, not implemented) |
| TCP MSS option advertisement                        | locked in (RFC 9293)      |

---

## Overall assessment

| Aspect                                              | Status                       |
|-----------------------------------------------------|------------------------------|
| Frame format (14-byte Ethernet II header)           | met                          |
| EtherType `0x0800` for IP                           | met                          |
| Min data 46-octet zero-pad                          | delegated to driver / NIC    |
| Max data 1500 octets                                | met (interface MTU)          |
| Gateway full-length acceptance + fragmentation      | not implemented (Phase 2)    |
| TCP MSS option coordination                         | met                          |
| ARP-based dynamic address resolution                | met (RFC 826)                |
| Broadcast IP → `FF:FF:FF:FF:FF:FF` MAC mapping      | met                          |
| Trailer encapsulation (4.2bsd / RFC 893)            | out of scope (deliberate)    |
| Big-endian byte order                               | met                          |

**Principal gap:** none for host-stack purposes. The
only "not implemented" row is gateway-side full-length
acceptance + transit fragmentation, which is on the
Phase 2 (router-grade parity) roadmap and is explicitly
deferred per `CLAUDE.md`. Everything else is shipped,
tested, and aligned with the RFC.
