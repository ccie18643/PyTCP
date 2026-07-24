# RFC 951 — Bootstrap Protocol (BOOTP)

| Field       | Value                              |
|-------------|------------------------------------|
| RFC number  | 951                                |
| Title       | Bootstrap Protocol (BOOTP)         |
| Category    | (Historic — Standard at time)      |
| Date        | September 1985                     |
| Updated by  | RFC 1542, RFC 1395, RFC 1497, RFC 2131 |
| Source text | [`rfc951.txt`](rfc951.txt)         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 951. The audit was performed by reading the RFC
text fresh and inspecting the codebase under `packages/pytcp/pytcp/` and
`packages/net_proto/net_proto/` directly.

RFC 951 is the foundational Bootstrap Protocol that DHCP
(RFC 2131) was built on. PyTCP implements RFC 2131, not
RFC 951 — PyTCP is a DHCP client, not a BOOTP client. The
two share a wire-format header (RFC 951 §3 + the 'options'
extension RFC 2131 §2 layered on top), and PyTCP's
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py` implements
that shared header faithfully. The audit therefore
focuses on header-format compliance and explicitly marks
the BOOTP-specific semantics (boot file load, TFTP
follow-on, vendor area as raw 64 octets rather than
RFC 1497 magic-cookie + options) as not applicable to
PyTCP's scope.

Sections without normative content (§1 Status, §2
Introduction, §6 Comparison to RARP, §8 Reference
Implementations, §11 Author's Address) are omitted.

---

## §3 Packet Format — header layout

> "The BOOTP packet is enclosed in a standard IP UDP
>  datagram. For simplicity it is assumed that the BOOTP
>  packet is never fragmented."

**Adherence:** met. PyTCP sends DHCP messages over
UDP via the BSD-socket facade (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:89-92`).
The minimum-MTU constraint
`DHCP4__OPTIONS__MAX_LEN = 576 - 20 - 8 - 240 = 308`
(`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py:85`)
keeps DHCP datagrams within the unfragmented-IPv4
576-byte ceiling.

> "Any numeric fields shown are packed in 'standard
>  network byte order', i.e. high order bits are sent
>  first."

**Adherence:** met. The header struct format begins
with `"! "` (`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py:129`)
which is `struct`'s network-byte-order marker.

> "In the IP header of a bootrequest, the client fills
>  in its own IP source address if known, otherwise
>  zero. When the server address is unknown, the IP
>  destination address will be the 'broadcast address'
>  255.255.255.255."

**Adherence:** met. The client binds the socket to
`("0.0.0.0", 68)` (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:91`)
so the source IP is zero, and connects to
`("255.255.255.255", 67)`
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:92`).

> "The UDP header contains source and destination port
>  numbers. The BOOTP protocol uses two reserved port
>  numbers, 'BOOTP client' (68) and 'BOOTP server' (67).
>  The client sends requests using 'BOOTP server' as the
>  destination port; this is usually a broadcast. The
>  server sends replies using 'BOOTP client' as the
>  destination port."

**Adherence:** met. Same socket configuration as above
— bind on 68, send to 67.

### Field layout (Table from §3)

| Field   | Bytes | RFC role                                | PyTCP source                                                       |
|---------|-------|-----------------------------------------|--------------------------------------------------------------------|
| op      | 1     | 1 = BOOTREQUEST, 2 = BOOTREPLY          | `Dhcp4Operation` enum (`dhcp4__enums.py:38-44`); REQUEST always emitted |
| htype   | 1     | hardware address type (1 = Ethernet)    | `Dhcp4HardwareType.ETHERNET = 0x01` (`dhcp4__enums.py:47-52`)      |
| hlen    | 1     | hardware address length (6 for Ethernet)| `DHCP4__HARDWARE_LEN__ETHERNET = 6` (`dhcp4__enums.py:55`)         |
| hops    | 1     | client sets to zero                     | `hops: int` field; assembler-defaults 0 (`dhcp4__assembler.py:61`) |
| xid     | 4     | random transaction ID                   | `xid: int` field; client randomises (`dhcp4_client.py:87`)         |
| secs    | 2     | seconds elapsed since boot start        | `secs: int` field; sends `_elapsed_secs()`                         |
| —       | 2     | unused (in RFC 951; later: 'flags')     | `flag_b: bool` + 15 MBZ bits (RFC 2131 reuse — see below)          |
| ciaddr  | 4     | client IP if known                      | `ciaddr: Ip4Address` field; client always sends 0.0.0.0            |
| yiaddr  | 4     | 'your' (client) IP from server          | `yiaddr: Ip4Address` field                                         |
| siaddr  | 4     | server IP                               | `siaddr: Ip4Address` field                                         |
| giaddr  | 4     | gateway/relay IP                        | `giaddr: Ip4Address` field; client always sends 0.0.0.0            |
| chaddr  | 16    | client hardware address                 | `chaddr: MacAddress` field; PyTCP packs the 6-byte MAC + 10 NUL pad |
| sname   | 64    | optional server host name               | `sname: str` field; ASCII NUL-padded                               |
| file    | 128   | boot file name                          | `file: str` field; ASCII NUL-padded                                |
| vend    | 64    | optional vendor area                    | RFC 1497 + RFC 2131 superseded: magic cookie + options             |

> "The UDP checksum field can be set to zero by the
>  client (or server) if desired, to avoid this extra
>  overhead in a PROM implementation."

**Adherence:** N/A. PyTCP's UDP layer at
`packages/net_proto/net_proto/protocols/udp/udp__base.py` always emits
checksums; the optional-zero-checksum allowance is not
exploited.

---

## §3 'unused' 2 octets / RFC 2131 reinterpretation as 'flags'

> "-- 2 unused"

**Adherence:** redefined by RFC 2131 §2 / RFC 1542 §3.1.1
as the 'flags' field, with the top bit defined as the
BROADCAST (B) flag. PyTCP packs `flag_b << 15`
(`dhcp4__header.py:246`) and decodes
the top bit on RX (`dhcp4__header.py:301`),
leaving the remaining 15 bits MBZ as RFC 2131 requires.
See [`rfc2131__dhcp`](../rfc2131__dhcp/adherence.md)
§4.1 audit for the BROADCAST bit emission.

---

## §3 'vend' field reinterpretation as options

> "vend 64 optional vendor-specific area, e.g. could be
>  hardware type/serial on request, or 'capability' /
>  remote file system handle on reply."

**Adherence:** redefined. PyTCP follows RFC 2131 §2 +
RFC 1497: the field is the variable-length 'options'
area, NOT a 64-byte vendor block. The header struct's
final 4 bytes are the magic cookie
(`b"\x63\x82\x53\x63"`), and the options follow
immediately (`dhcp4__header.py:120-125`).

The original BOOTP 64-byte vend area is incompatible
with PyTCP's variable-length options — DHCP servers
and DHCP clients communicate via the options area.
PyTCP cannot interoperate with a pure RFC 951 BOOTP
server emitting a 64-byte 'vend' block; the parser
would unpack 4 bytes as magic cookie and read garbage.

---

## §4 Chicken / Egg Issues

> "How can the server send an IP datagram to the client,
>  if the client doesnt know its own IP address (yet)?
>  ... There are two options:
>  a. If the transmitter has the necessary kernel or
>  driver hooks to 'manually' construct an ARP address
>  cache entry ...
>  b. If the transmitter lacks these kernel hooks, it
>  can simply send the bootreply to the IP broadcast
>  address on the appropriate interface."

**Adherence:** PyTCP relies on option (b) — broadcast
reply. The client sets the BROADCAST flag
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:137`, `:191`)
so the server emits replies to
255.255.255.255 / link-layer broadcast. PyTCP's UDP RX
gate accepts unicast and broadcast destinations on the
bound port equivalently
(see `packages/pytcp/pytcp/runtime/socket/udp__socket.py`).

---

## §5 Client Use of ARP

> "The client PROM must contain a simple implementation
>  of ARP, e.g. the address cache could be just one
>  entry in size."

**Adherence:** met by stack-wide ARP, not by the DHCP
client. The PyTCP stack's ARP cache is at
`packages/pytcp/pytcp/protocols/arp/arp__cache.py` (full NUD machinery,
not a single-entry PROM cache). DHCP-time ARP
resolution happens transparently — the BSD-socket
`send` call goes through the standard TX path.

> "Any time the client is expecting to receive a TFTP
>  or BOOTP reply, it should be prepared to answer an
>  ARP request for its own IP to hardware address
>  mapping (if known)."

**Adherence:** N/A. The TFTP follow-on is not
implemented (boot-from-net is out of scope).

---

## §7 Packet Processing — Client Transmission

> "Before setting up the packet for the first time, it
>  is a good idea to clear the entire packet buffer to
>  all zeros; this will place all fields in their
>  default state."

**Adherence:** met by dataclass-default semantics. The
`Dhcp4Assembler` constructor at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__assembler.py`
populates each field with a zero / default value and
the `Dhcp4Header.__buffer__` packs into a freshly
zeroed `bytearray(len(self))` of 240 bytes
(`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py:236-238`).
Unused fields are zero.

> "Set 'op' to BOOTREQUEST."

**Adherence:** met
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:135`, `:189`).

> "Set 'xid' to a 'random' transaction id, as discussed
>  above."

**Adherence:** met (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:87`).

> "If the client wishes to restrict booting to a
>  particular server name, it may place a null-
>  terminated string in 'sname'. The string should be
>  one which is mappable by the standard IP address /
>  host name lookup mechanism (DNS), into the IP address
>  of the desired host."

**Adherence:** vacuous. PyTCP's DHCP exchange is not
constrained to a specific server; sname is left empty
on TX (assembler default).

> "If the client already knows its IP address, it places
>  it in 'ciaddr'. Otherwise this is set to zero."

**Adherence:** met (always 0 — see §3 table above).

> "The client fills in any of its addressing parameters
>  that it does know, namely 'chaddr' and 'htype'."

**Adherence:** met. `chaddr=self._mac_address`
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:138`, `:192`);
htype defaulted to ETHERNET in the dataclass
(`dhcp4__header.py:145-147`).

---

## §7 Packet Processing — Server Reception

> "When the server receives a bootrequest from a client,
>  it first checks to see if it serves the client's
>  request, by ..."

**Adherence:** N/A — PyTCP has no DHCP/BOOTP server.

---

## §9 Authentication / Hop count / Other policies

**Adherence:** N/A — server-side concerns.

---

## Test coverage audit

### §3 Header layout

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py` (785 lines)
  Field-level invariants for every header field.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py` (690 lines)
  Header round-trip parse on real-shaped wire frames.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py` (441 lines)
  Header round-trip emit on real-shaped wire frames.

**Status:** locked in (BOOTP-shape header wire format).

### §3 'unused' / 'flags' field

- **Unit:**
  Header asserts include `flag_b: bool` round-trip
  (`test__dhcp4__header__asserts.py`).

**Status:** locked in.

### §4 BROADCAST reply path

- **Unit (DHCP client):**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py` (4149 lines)
  Pins that the emitted DISCOVER/REQUEST carry
  `flag_b=True`.

**Status:** locked in indirectly (via the DHCP-client
behavioural tests).

### Test coverage summary

| Aspect                                  | Coverage                            |
|-----------------------------------------|-------------------------------------|
| BOOTP header layout (§3 fixed fields)   | locked in                           |
| BROADCAST flag emission                 | locked in                           |
| Vendor area reinterpretation as options | locked in (parser tests)            |
| BOOTP boot-file-load semantics          | n/a (TFTP not implemented)          |
| BOOTP-only server interop               | n/a (PyTCP is DHCP-only)            |

---

## Overall assessment

| Aspect                                            | Status                                            |
|---------------------------------------------------|---------------------------------------------------|
| BOOTP fixed-field header wire format              | met (shared with RFC 2131)                        |
| UDP transport on 67 / 68                          | met                                               |
| Source IP 0 on bootrequest, dst 255.255.255.255   | met                                               |
| Random xid                                        | met                                               |
| chaddr filled with client MAC                     | met                                               |
| Op = BOOTREQUEST in client → server               | met                                               |
| 'unused' 2 octets — MBZ in RFC 951                | met (RFC 2131 reinterpretation as flags MBZ)      |
| BROADCAST flag (RFC 1542 / 2131 reuse of 'unused')| met (always set by PyTCP client)                  |
| 64-byte 'vend' area                               | superseded by RFC 1497 + RFC 2131 options layout  |
| BOOTP boot file load + TFTP follow-on             | not implemented (out of host-parity scope)        |
| Single-entry PROM ARP cache                       | not implemented (PyTCP uses full NUD-cache)       |
| BOOTP-only server interop                         | not implemented                                   |

**Principal compliance note.** PyTCP is not a BOOTP
client — it is a DHCP client. The wire-format header
defined in RFC 951 is faithfully implemented and shared
with the RFC 2131 protocol. The BOOTP-specific
semantics (vendor area as raw bytes, boot file load via
TFTP, PROM ARP) are intentionally out of scope. A pure
RFC 951 BOOTP server (without RFC 1497 magic-cookie
options) is not interoperable with PyTCP's parser; that
is acceptable because such servers are practically
extinct (the RFC was obsoleted by RFC 2131 in 1997).
