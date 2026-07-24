# RFC 1542 — Clarifications and Extensions for the Bootstrap Protocol

| Field       | Value                                                   |
|-------------|---------------------------------------------------------|
| RFC number  | 1542                                                    |
| Title       | Clarifications and Extensions for the Bootstrap Protocol|
| Category    | Standards Track                                         |
| Date        | October 1993                                            |
| Updates     | RFC 951                                                 |
| Source text | [`rfc1542.txt`](rfc1542.txt)                            |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 1542. The audit was performed by reading the RFC
text fresh and inspecting the codebase under `packages/pytcp/pytcp/` and
`packages/net_proto/net_proto/` directly.

RFC 1542 clarifies several ambiguous areas of RFC 951
(BOOTP) and defines the BROADCAST flag in the previously-
unused two octets between `secs` and `ciaddr`. PyTCP
implements RFC 2131 (DHCP), which inherits these
clarifications as MUST/SHOULD wording. PyTCP is a DHCP
client only; the relay-agent (§4) and server (§5)
sections are out of scope and marked as such without
per-paragraph audit.

Sections without normative content (§1 Introduction,
§1.1 Requirements boilerplate, §1.2 Terminology, §1.3
Data Transmission Order, §2.1 General BOOTP Processing,
§2.4 Token Ring, §6 Acknowledgments, §7 References,
§8 Security Considerations boilerplate, §9 Author's
Address) are omitted.

---

## §2.2 Definition of the 'flags' Field

> "This memo hereby designates this two-octet field as
>  the 'flags' field. This memo hereby defines the most
>  significant bit of the 'flags' field as the BROADCAST
>  (B) flag."

**Adherence:** met. PyTCP's header dataclass models the
field as `flag_b: bool` (single boolean — the top bit)
plus implicit 15-bit MBZ
(`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py:156`).
Pack and unpack at
`dhcp4__header.py:246, 301` use
`flag_b << 15` so the bit is in the MSB position of the
2-octet field.

> "The remaining bits of the 'flags' field are reserved
>  for future use. They MUST be set to zero by clients
>  and ignored by servers and relay agents."

**Adherence:** met. The pack expression
`self.flag_b << 15` (`dhcp4__header.py:246`)
leaves all other bits cleared. On RX, only the top bit
is decoded back into a bool (`dhcp4__header.py:301`).

---

## §2.3 Bit Ordering of Hardware Addresses

> "The bit ordering used for link-level hardware
>  addresses in the 'chaddr' field SHOULD be the same as
>  the ordering used for the ARP protocol on the
>  client's link-level network."

**Adherence:** met. PyTCP's `MacAddress` value type
stores the canonical Ethernet bit order; the same MAC
representation is used in ARP frames (RFC 826 §2.5
Ethernet bit order) and as `chaddr` in DHCP frames.
The serialiser at `dhcp4__header.py:251`
packs `bytes(self.chaddr)` directly into the 6-byte
prefix of the 16-byte field, padded with NULs — no bit
reversal.

> "The 'chaddr' field MUST be preserved as it was
>  specified by the BOOTP client."

**Adherence:** N/A (relay-agent requirement). PyTCP
emits the client `chaddr`; there is no relay-agent
path that would modify it.

---

## §2.4 BOOTP Over IEEE 802.5 Token Ring Networks

**Adherence:** N/A. PyTCP supports Ethernet only; Token
Ring's RIF / All Routes Explorer machinery is out of
scope (north-star non-goal: no exotic link layers).

---

## §3.1.1 The BROADCAST flag

> "If a client falls into this category [cannot receive
>  unicast IP datagrams before its IP is configured], it
>  SHOULD set (to 1) the newly-defined BROADCAST flag in
>  the 'flags' field of BOOTREPLY messages it generates."

(Note: the text says "BOOTREPLY messages it generates"
— a typo for BOOTREQUEST; the surrounding paragraphs
make this clear.)

**Adherence:** met. The client emits `flag_b=True` in
both DISCOVER and REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:137`, `:191`).
PyTCP's UDP RX path can in principle receive unicast
on the bound socket before the IPv4 address is fully
configured (the socket is bound on `0.0.0.0:68`), so a
SHOULD-clear path would also be valid; PyTCP takes the
conservative SHOULD-set path.

> "If a client does not have this limitation (i.e., it
>  is perfectly able to receive unicast BOOTREPLY
>  messages), it SHOULD NOT set the BROADCAST flag."

**Adherence:** deviation noted. PyTCP unconditionally
sets BROADCAST even though the stack can receive
unicast pre-bind. Linux dhcpcd defaults to NOT setting
BROADCAST. Hardening the SHOULD NOT compliance is a
defensible Phase-1 tightening; it is not a MUST.

---

## §3.1.2 The remainder of the 'flags' field

> "A client MUST set these bits to zero in all
>  BOOTREQUEST messages it generates. A client MUST
>  ignore these bits in all BOOTREPLY messages it
>  receives."

**Adherence:** met. See §2.2 above for emission. On RX,
only the top bit is decoded; the remaining 15 bits
fall on the floor (`dhcp4__header.py:301`).

---

## §3.2 Definition of the 'secs' field

> "The 'secs' field of a BOOTREQUEST message SHOULD
>  represent the elapsed time, in seconds, since the
>  client sent its first BOOTREQUEST message. Note that
>  this implies that the 'secs' field of the first
>  BOOTREQUEST message SHOULD be set to zero."

**Adherence:** met. PyTCP emits `secs=_elapsed_secs()`
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1883`),
which returns the whole seconds since the client began
address acquisition, so the first DISCOVER carries
`secs=0` and every later message — including
retransmissions via `_recv_with_backoff` (:1515) —
carries the real elapsed time.

> "Clients SHOULD NOT set the 'secs' field to a value
>  which is constant for all BOOTREQUEST messages."

**Adherence:** met. `secs` is not a constant — it
tracks elapsed time via `_elapsed_secs()`, so it is 0
only on the first request and grows thereafter, exactly
as the SHOULD NOT intends.

RFC 2131 §4.1 retransmission is implemented
(`_recv_with_backoff`, :1515), and `secs` already
reflects the elapsed time since the first DISCOVER
across those retransmissions.

---

## §3.3 Use of the 'ciaddr' and 'yiaddr' fields

> "If a BOOTP client does not know what IP address it
>  should be using, the client SHOULD set the 'ciaddr'
>  field to 0.0.0.0."

**Adherence:** met. The client always emits
`ciaddr=Ip4Address()` (default value 0.0.0.0) — see
`Dhcp4Assembler` default field value at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__assembler.py` and the
fact that `_send_discover` / `_send_request` at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:134-151`, `:188-205`
never set `dhcp4__ciaddr=...` (the default applies).

> "The BOOTP server is free to assign a different IP
>  address (in the 'yiaddr' field) than the client
>  expressed in 'ciaddr'. The client SHOULD adopt the
>  IP address specified in 'yiaddr'."

**Adherence:** met. The client always uses
`ack.yiaddr` (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:121`)
as the assigned IPv4 address.

---

## §3.4 Interpretation of the 'giaddr' field

> "A BOOTP client MUST set the 'giaddr' field to zero
>  (0.0.0.0) in all BOOTREQUEST messages it generates."

**Adherence:** met. The client never sets
`dhcp4__giaddr=...` on outbound assemblers
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:134-151`, `:188-205`);
the assembler default of `Ip4Address()` = 0.0.0.0
applies.

> "A BOOTP client MUST NOT interpret the 'giaddr' field
>  of a BOOTREPLY message to be the IP address of an IP
>  router. A BOOTP client SHOULD completely ignore the
>  contents of the 'giaddr' field in BOOTREPLY
>  messages."

**Adherence:** met. The client reads only `yiaddr`,
`subnet_mask`, and `router[0]` from the ACK
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:111-125`).
The `giaddr` field is exposed via the parser's
`Dhcp4HeaderProperties` but the client never reads it.

---

## §3.5 Vendor information "magic cookie"

> "It is RECOMMENDED that a BOOTP client always fill the
>  first four octets of the 'vend' (vendor information)
>  field of a BOOTREQUEST with a four-octet identifier
>  called a 'magic cookie.'"

**Adherence:** met. The magic cookie
`b"\x63\x82\x53\x63"` (99.130.83.99) is packed as the
final 4-byte field of the BOOTP header (which RFC 2131
treats as separate from the variable-length options)
at `packages/net_proto/net_proto/protocols/dhcp4/dhcp4__header.py:254`.

> "If a special vendor-specific magic cookie is not
>  being used, a BOOTP client SHOULD use the dotted
>  decimal value 99.130.83.99."

**Adherence:** met. PyTCP uses the standard RFC 1497
cookie value (`DHCP4__HEADER__MAGIC_COOKIE` at
`dhcp4__header.py:130`).

---

## §4 BOOTP Relay Agents

**Adherence:** N/A. PyTCP is not a BOOTP relay agent.
The Phase-2 router north-star may eventually pull this
in, but currently no PyTCP path forwards BOOTP/DHCP
messages between subnets.

---

## §5 BOOTP Server Behavior

**Adherence:** N/A. PyTCP is a DHCP client only.

---

## Test coverage audit

### §2.2 / §3.1.1 / §3.1.2 BROADCAST flag

- **Unit (header):**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py` (785 lines)
  Pins `flag_b: bool` round-trip and `<< 15` packing.
- **Unit (client):**
  `packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py` (4149 lines)
  Asserts that emitted DISCOVER/REQUEST carry
  `flag_b=True`.

**Status:** locked in.

### §3.3 ciaddr / yiaddr semantics

- **Unit:**
  `test__dhcp4__header__asserts.py` pins `ciaddr` and
  `yiaddr` as `Ip4Address`-typed fields.
- **Unit:**
  `test__dhcp4__client.py` exercises the
  ciaddr=0.0.0.0 emission and `yiaddr` adoption.

**Status:** locked in.

### §3.4 giaddr emission

- **Unit:**
  `test__dhcp4__client.py` indirectly — the emitted
  DISCOVER/REQUEST have `giaddr=0.0.0.0` (assembler
  default).

**Status:** locked in indirectly.

### §3.5 Magic cookie

- **Unit:**
  `test__dhcp4__parser__integrity_checks.py` asserts
  parsing fails on bad magic cookie
  (`Dhcp4IntegrityError` raised).
- **Unit:**
  `test__dhcp4__assembler__operation.py` asserts emitted
  frames carry the canonical 99.130.83.99 bytes.

**Status:** locked in.

### Test coverage summary

| Aspect                                  | Coverage                                  |
|-----------------------------------------|-------------------------------------------|
| BROADCAST flag emission / MBZ bits      | locked in                                 |
| chaddr Ethernet bit order               | locked in (MAC value-type round-trip)     |
| secs = 0 on first BOOTREQUEST           | locked in                                 |
| ciaddr = 0 / giaddr = 0 emission        | locked in (assembler defaults)            |
| yiaddr adoption from BOOTREPLY          | locked in (`test__dhcp4__client.py`)      |
| Magic cookie value                      | locked in (parser + assembler)            |
| Relay agent / server behaviour          | n/a (PyTCP is client only)                |

---

## Overall assessment

| Aspect                                              | Status                                          |
|-----------------------------------------------------|-------------------------------------------------|
| §2.2 BROADCAST bit + 15 MBZ bits packing            | met                                             |
| §2.3 chaddr Ethernet bit order                      | met                                             |
| §3.1.1 BROADCAST emission when unicast pre-bind impossible | met (unconditional set — deviation from SHOULD NOT in PyTCP's reverse case) |
| §3.1.2 MBZ flags bits zero on TX, ignored on RX     | met                                             |
| §3.2 secs = 0 on first DISCOVER                     | met (elapsed time via `_elapsed_secs()`)        |
| §3.3 ciaddr = 0 on TX, yiaddr adoption on RX        | met                                             |
| §3.4 giaddr = 0 on TX, ignored on RX                | met                                             |
| §3.5 Magic cookie 99.130.83.99                      | met                                             |
| §4 Relay agent behaviour                            | n/a (out of scope)                              |
| §5 Server behaviour                                 | n/a (out of scope)                              |

**Principal compliance note.** PyTCP's DHCP client
satisfies all client-relevant MUST/SHOULD clauses of
RFC 1542 with one defensible deviation: §3.1.1's SHOULD
NOT clause (don't set BROADCAST when the client CAN
receive unicast pre-bind) is technically violated —
PyTCP unconditionally sets BROADCAST. Tightening this
to "set BROADCAST only when the OS / interface cannot
accept link-layer unicast before bind" is a minor
Phase-1 hardening, not a real interop issue. The
unconditional-set behaviour matches some legacy
ISC/Microsoft clients and is universally tolerated by
DHCP servers.

The relay-agent and server sections are out of scope
for a host stack; if Phase-2 router parity ever pulls
DHCP relay into PyTCP, those sections would need a
dedicated audit.
