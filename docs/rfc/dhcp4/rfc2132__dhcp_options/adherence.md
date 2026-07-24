# RFC 2132 — DHCP Options and BOOTP Vendor Extensions

| Field       | Value                                       |
|-------------|---------------------------------------------|
| RFC number  | 2132                                        |
| Title       | DHCP Options and BOOTP Vendor Extensions    |
| Category    | Standards Track                             |
| Date        | March 1997                                  |
| Updates     | RFC 1497, RFC 1533                          |
| Source text | [`rfc2132.txt`](rfc2132.txt)                |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 2132. The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly. Sections describing
options PyTCP does not parse and never emits are grouped
under the **Options not implemented** summary table below
rather than receiving individual narrative — RFC 2132 is
an enumeration catalogue of 80+ options, and per-option
"not implemented" entries would not add information
beyond the table.

PyTCP's DHCP option catalogue lives in
`packages/net_proto/net_proto/protocols/dhcp4/options/`. The
`Dhcp4OptionType` enum at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py:56-76`
declares 16 codepoints; any inbound option not in this
set parses into a `Dhcp4OptionUnknown` (preserving the
wire bytes for retransmission but not interpreting the
value).

---

## §2 BOOTP Extension/DHCP Option Field Format

> "DHCP options have the same format as the BOOTP
>  'vendor extensions' ... DHCP options are tagged data
>  items that provide information to a DHCP client. ...
>  The fixed-length data items consisting of an octet,
>  in a fixed sequence, are placed in this field for
>  the option. ... The variable-length data items
>  consist of an octet specifying length followed by the
>  data."

**Adherence:** met. The TLV layout (type byte + length
byte + value bytes) is the canonical option wire shape;
PyTCP's option base class at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py`
uses `DHCP4__OPTION__STRUCT = "! BB"`
(`dhcp4__option.py:52`) for the
common type+length header. Per-option subclasses append
their typed payload.

> "Two special fixed-length options exist that do not
>  follow this rule. These are the 'pad' option (option
>  0) and the 'end' option (option 255). Both have a
>  fixed length of one octet."

**Adherence:** met. `Dhcp4OptionPad` and
`Dhcp4OptionEnd` (at
`options/dhcp4__option__pad.py` and
`options/dhcp4__option__end.py`) are single-byte options
that bypass the type+length header.

> "Options requiring more than 255 octets are split into
>  multiple options, with each having a length of at
>  most 255 octets."

**Adherence:** met (client / receive side).
`Dhcp4Options.from_buffer` concatenates the data of all
same-code instances before invoking the typed codec —
required by RFC 3442 Classless Static Routes (option
121) which routinely splits across the 255-octet
boundary. The implementation lives at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py`
in `_concatenated_classless_static_route_data` (Phase
8.3, shipped 2026-05-25). Server-side splitting on
assembly is a Phase-2 DHCP-server concern and remains
out of scope for the host client.

---

## §3.1 Pad Option (code 0)

**Adherence:** met.
`Dhcp4OptionPad` at
`options/dhcp4__option__pad.py`. Single-byte option;
the parser skips it without consuming a length byte
(`options/dhcp4__options.py` integrity walk handles the
PAD special case).

---

## §3.2 End Option (code 255)

**Adherence:** met. Same shape as Pad; the parser stops
walking on END. Emitted as the last option of every
DISCOVER and REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:149`, `:204`).

> "The last option must always be the 'end' option."

**Adherence (assembler enforcement):** met. The
`Dhcp4Assembler` constructor asserts that when
`dhcp4__options` is non-empty, the last option MUST be
`Dhcp4OptionEnd`. Empty `Dhcp4Options()` is permitted —
the magic cookie alone is the documented options-field
marker, and an explicit terminator is meaningful only
when there is at least one preceding option. Without
this assert a caller who forgets to append `Dhcp4OptionEnd`
would emit a wire frame whose options section ends
mid-stream — a strict receiver may interpret it as
truncation or simply leave the option list unbounded.

Pinned by `TestDhcp4AssemblerOptionsTerminator` at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py`
(three cases: missing-End rejected, empty accepted,
End-as-last accepted).

---

## §3.3 Subnet Mask Option (code 1)

> "The subnet mask option specifies the client's subnet
>  mask as per RFC 950. ... The code for the subnet mask
>  option is 1, and its length is 4 octets."

**Adherence:** met. `Dhcp4OptionSubnetMask` at
`options/dhcp4__option__subnet_mask.py` parses 4-byte
mask. The client at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:114-119`
extracts `ack.subnet_mask` and requires it to be
non-None to proceed (returns None otherwise — a
DHCP ACK without subnet mask cannot be consumed).

> "If both the subnet mask and the router option are
>  specified in a DHCP reply, the subnet mask option
>  MUST be first."

**Adherence:** not enforced. PyTCP does not validate
option ordering between Subnet Mask and Router; both
properties are pulled out individually by `Dhcp4Options`
accessors. Behaviour is correct regardless of order.

**Wire-format hostile-input rejection (parser):** RFC 950
§2.1 requires a subnet mask to consist of high-order ones
followed by low-order zeros. Non-contiguous wire bytes
(e.g. `0xFF00FF00`) are rejected at
`Dhcp4OptionSubnetMask._validate_integrity` BEFORE
`Ip4Mask(buffer[2:6])` construction would otherwise raise
`Ip4MaskFormatError` — the typed
`Dhcp4IntegrityError` carries an RFC 950 §2.1 citation in
the message.

Pinned by
`TestDhcp4ParserSubnetMaskContiguity` at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__integrity_checks.py`
(non-contiguous mask rejected with RFC 950 §2.1 cite;
contiguous /24 mask parses cleanly).

---

## §3.5 Router Option (code 3)

> "The router option specifies a list of IP addresses
>  for routers on the client's subnet. Routers SHOULD be
>  listed in order of preference. ... The code for the
>  router option is 3. The minimum length for the router
>  option is 4 octets, and the length MUST always be a
>  multiple of 4."

**Adherence:** met. `Dhcp4OptionRouter` at
`options/dhcp4__option__router.py` parses N×4-byte
list. The client at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:122-123`
uses only the first router (`ack.router[0]`) as the
default gateway — the SHOULD preference order is
honoured implicitly.

**Wire-format bounds (assembler + parser):** the §3.5
minimum-and-multiple-of-4 length rule is now enforced
at both ends:

- `Dhcp4OptionRouter.__post_init__` asserts
  `1 <= len(routers) <= 63` — catches a programmer
  passing an empty list at construction time, before
  `__buffer__` would emit a spec-violating frame, and
  catches > 63 router IPs before `struct.pack_into`
  overflows the uint8 length byte (63 × 4 = 252; 64 × 4
  = 256 > uint8 ceiling).
- `Dhcp4OptionRouter._validate_integrity` already
  enforced the multiple-of-4 rule; now also rejects
  wire frames whose Length byte is below 4 (the §3.5
  minimum) with a typed `Dhcp4IntegrityError` (not a
  bare AssertionError leaking past the IP RX handler's
  `PacketValidationError` catch).

Pinned by `TestDhcp4OptionRouterBounds` and the new
`test__dhcp4__option__router__wire_len_below_minimum`
case at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__router.py`.

---

## §3.14 Host Name Option (code 12)

> "This option specifies the name of the client. ... The
>  code for this option is 12, and its minimum length
>  is 1."

**Adherence:** met. `Dhcp4OptionHostName` at
`options/dhcp4__option__host_name.py`. The client emits
`Dhcp4OptionHostName("PyTCP")` in both DISCOVER and
REQUEST (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:148`,
`:203`).

**Wire-format self-consistency (assembler):**
`Dhcp4OptionHostName` computes the wire-format length byte
from the **byte count** of the UTF-8-encoded host name, not
from the Python character count. Without this distinction
a host name containing non-ASCII characters would produce
a self-inconsistent wire frame — the length byte would say
"N bytes follow" while N+k bytes actually trailed (k = the
multi-byte-encoding overhead).

The wire length byte is a single octet, so the encoded
host name must fit in 255 bytes. The dataclass
`__post_init__` asserts this at construction.

**Wire-format bounds (assembler + parser):** the §3.14
"minimum length 1" rule is enforced at both ends:

- `Dhcp4OptionHostName.__post_init__` asserts the
  UTF-8-encoded byte count is `>= 1` — catches a
  programmer constructing `Dhcp4OptionHostName("")`
  before it would emit a spec-violating `\x0c\x00`
  frame.
- `Dhcp4OptionHostName._validate_integrity` rejects wire
  frames whose Length byte is 0 with a typed
  `Dhcp4IntegrityError`.

Pinned by `TestDhcp4OptionHostNameWireConsistency` (UTF-8
byte-count self-consistency + over-255-byte rejection)
and `TestDhcp4OptionHostNameBounds` (empty rejected at
construction; 1-byte boundary accepted) at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__host_name.py`.

---

## §9.1 Requested IP Address (code 50)

> "This option is used in a client request (DHCPDISCOVER)
>  to allow the client to request that a particular IP
>  address be assigned. ... The code for this option is
>  50, and its length is 4."

**Adherence:** met (in REQUEST only). The client emits
`Dhcp4OptionReqIpAddr(yiaddr)` in REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:202`),
sourced from the OFFER's `yiaddr`. PyTCP does NOT use
this option in DISCOVER — RFC 2131 §3.5 marks it MAY
for DISCOVER, so omission is compliant. The
`Dhcp4OptionReqIpAddr` codec at
`options/dhcp4__option__req_ip_addr.py` handles the
4-byte address.

---

## §9.2 IP Address Lease Time (code 51)

> "This option is used in a client request (DHCPDISCOVER
>  or DHCPREQUEST) to allow the client to request a
>  lease time for the IP address. In a server reply
>  (DHCPOFFER), a DHCP server uses this option to
>  specify the lease time it is willing to offer."

**Adherence:** met. `Dhcp4OptionLeaseTime` at
`options/dhcp4__option__lease_time.py` parses 4-byte
uint32 lease time. The client emits a lease-time hint
in DISCOVER (`Dhcp4OptionLeaseTime(lease_time_hint)` in
`_send_discover`,
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1776`)
and consumes `ack.lease_time` from the ACK (:1469, :1508;
the INIT path at :734/:746), storing it as
`Dhcp4Lease.lease_time__sec` and deriving the T1/T2
renew/rebind deadlines and the hard expiry from it. An
ACK without option 51 is rejected (:1469) since there is
no lease time to schedule against.

---

## §9.4 TFTP server name (code 66)

**Adherence:** not implemented. PXE-relevant; out of
scope for PyTCP host parity.

## §9.5 Bootfile name (code 67)

**Adherence:** not implemented. Same scope.

---

## §9.6 DHCP Message Type (code 53)

> "This option is used to convey the type of the DHCP
>  message. The code for this option is 53, and its
>  length is 1. Legal values for this option are:
>  Value Message Type
>  1     DHCPDISCOVER
>  2     DHCPOFFER
>  3     DHCPREQUEST
>  4     DHCPDECLINE
>  5     DHCPACK
>  6     DHCPNAK
>  7     DHCPRELEASE
>  8     DHCPINFORM"

**Adherence:** met. `Dhcp4MessageType` at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__enums.py:58-95`
declares all 8 codepoints (DISCOVER=1 through
INFORM=8). The `Dhcp4OptionMessageType` codec at
`options/dhcp4__option__message_type.py` carries the
single byte. The client emits DISCOVER and REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:140`, `:194`)
and accepts OFFER and ACK on RX
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:167-172`,
`:222-227`).

DECLINE (`_send_decline`,
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1828`)
and RELEASE (`_send_release`, :1216) are emitted, and NAK
is handled on RX (the receive loop returns the
`_NAK_RESTART` sentinel and the FSM falls back to INIT,
`_recv_within_window` :1644). Only INFORM is neither
emitted nor handled.

**Presence requirement (parser sanity):** RFC 2131 §3
mandates "DHCP messages MUST contain a 'DHCP message
type' option that specifies the type of message". A
magic-cookie-bearing BOOTP frame without option 53 is
structurally well-formed but cannot be classified as a
DHCP message. `Dhcp4Parser._validate_sanity` rejects
such frames with `Dhcp4SanityError`. The DHCPv4 client
catches both `Dhcp4IntegrityError` and `Dhcp4SanityError`
in the inbound wait loop at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1427`,
so a hostile or malformed server response is dropped
rather than crashing the client thread.

Pinned by
`TestDhcp4ParserSanityMessageTypePresence` at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__sanity_checks.py`
(absent → rejected with RFC-cited message; present →
parses cleanly).

**Required-options-per-message-type (parser sanity):**
RFC 2131 §3 Table 3 / §4.3.6 mandate that server-emitted
DHCPOFFER, DHCPACK, and DHCPNAK MUST carry the Server
Identifier option (54); DHCPOFFER MUST additionally carry
the IP Address Lease Time option (51). The parser's
`_validate_sanity` raises `Dhcp4SanityError` when any of
these required options is absent for the corresponding
message type. Client-emitted message types (DISCOVER /
REQUEST / DECLINE / RELEASE / INFORM) are not checked at
the parser layer — their per-state required-options
constraints (RFC 2131 §3.1 / §3.2 step semantics) live
in the client state machine.

Lease Time on DHCPACK is RFC-MUST when the ACK responds
to a DHCPREQUEST but RFC-MUST-NOT when the ACK responds
to a DHCPINFORM. The parser has no request/reply
correlation and the PyTCP client does not emit INFORM,
so the lease_time MUST is enforced on DHCPOFFER only —
keeping the parser correct for both ACK shapes
without statefulness.

Pinned by
`TestDhcp4ParserSanityRequiredServerResponseOptions` at
the same test file (per-message-type missing-option
rejections + DISCOVER-without-server_id accepted +
NAK-with-server_id-without-lease_time accepted).

The pre-existing client check at
`dhcp4__client.py:1270` (`if srv_id is None: return None`
on the parsed Offer) is now defense-in-depth dead code —
the parser rejects such frames before the client sees
them. Kept for symmetry with the per-state checks the
client makes on other fields (subnet_mask).

---

## §9.7 Server Identifier (code 54)

> "DHCP clients use the contents of the 'server
>  identifier' field as the destination address for any
>  DHCP messages unicast to the DHCP server. DHCP
>  clients also indicate which of several lease offers
>  is being accepted by including this option in a
>  DHCPREQUEST message. ... The code for this option is
>  54, and its length is 4."

**Adherence:** met (for REQUEST emit). The client
includes `Dhcp4OptionServerId(srv_id)` in REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:201`) sourced
from the OFFER's `srv_id` field
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:108`). The
"destination address for unicast" clause is honoured —
in the RENEWING state the client sends a unicast REQUEST
to the recorded Server Identifier (`_do_renewing`, :629).

---

## §9.8 Parameter Request List (code 55)

> "This option is used by a DHCP client to request
>  values for specified configuration parameters. ... A
>  DHCP server is not required to return the requested
>  parameters, but is encouraged to do so."

**Adherence:** met. The client emits
`Dhcp4OptionParamReqList([CLASSLESS_STATIC_ROUTE,
SUBNET_MASK, ROUTER])` in both DISCOVER and REQUEST
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1763`
DISCOVER, `:1811` REQUEST). Only those three parameters
are requested because they are the ones the client
consumes; a richer client (with DNS / NTP / domain-name
support) would extend the list.

**Wire-format bounds (assembler + parser):** the §9.8
"minimum length 1" rule is now enforced at both ends:

- `Dhcp4OptionParamReqList.__post_init__` asserts
  `1 <= len(param_req_list) <= 255` — catches a
  programmer constructing an empty list (which would
  emit a spec-violating `\x37\x00` frame) and catches
  > 255 entries before `struct.pack_into` overflows
  the uint8 Length byte.
- `Dhcp4OptionParamReqList._validate_integrity` now
  rejects wire frames whose Length byte is 0 with a
  typed `Dhcp4IntegrityError` — closes the previously
  silent acceptance of `\x37\x00` (which would have
  parsed to an empty list, violating §9.8).

Pinned by `TestDhcp4OptionParamReqListBounds` and the
new
`test__dhcp4__option__param_req_list__wire_len_zero_rejected`
case at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__param_req_list.py`.

---

## §9.14 Client-identifier (code 61)

> "This option is used by DHCP clients to specify their
>  unique identifier. DHCP servers use this value to
>  index their database of address bindings. This value
>  is expected to be unique for all clients in an
>  administrative domain. ... The code for this option
>  is 61, and its minimum length is 2."

**Adherence:** met. The client emits the option in every
DHCPv4 message it sends — DISCOVER
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:1762`),
REQUEST (:1810), INIT-REBOOT (:1090), RENEW (:1200),
RELEASE (:1238), and DECLINE (:1853) — via the
`_expected_client_id` property. The wire form is the
RFC 4361 §6.1 layout (type byte 0xff + 4-byte IAID +
DUID), built by `build_client_id`; the RFC 2131 legacy
`b"\x01" + bytes(mac)` form is no longer used. RFC 2131
§2 ("use the same identifier in all subsequent messages")
is therefore satisfied. See
[`rfc4361__node_specific_client_id`](../rfc4361__node_specific_client_id/adherence.md)
for the dedicated audit. The `Dhcp4OptionClientId` codec
at `options/dhcp4__option__client_id.py` carries the
identifier bytes.

**Wire-format bounds (assembler + parser):** the
2-byte minimum from RFC 2132 §9.14 is enforced at
both ends:

- `Dhcp4OptionClientId.__post_init__` asserts
  `2 <= len(client_id) <= 255` — catches a programmer
  passing an empty or single-byte identifier at
  construction time, before `__buffer__` would emit a
  spec-violating frame, and catches a > 255-byte
  identifier before `struct.pack_into` overflows the
  uint8 length byte deep inside the wire-serialization
  path.
- `Dhcp4OptionClientId._validate_integrity` rejects
  wire frames whose Length byte is below 2 with a
  typed `Dhcp4IntegrityError` (not a bare AssertionError
  leaking past the IP RX handler's
  `PacketValidationError` catch).

Pinned by `TestDhcp4OptionClientIdBounds` and the new
`test__dhcp4__option__client_id__wire_len_below_minimum`
case at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__client_id.py`.

---

## Wire-format strict-TX enum-domain enforcement

DHCPv4 carries several protocol enums whose wire
codepoints are extensible at parse time via PyTCP's
`ProtoEnum._missing_` hook — an unknown octet
materialises as a `UNKNOWN_<value>` pseudo-member so
that the parser's `_validate_sanity` can surface the
violation as a typed `Dhcp4SanityError` rather than
crashing on lookup. The asymmetric TX-side concern: a
programmer who synthesised `Dhcp4Operation.from_int(99)`
(or `Dhcp4MessageType.from_int(99)`, or a
`Dhcp4OptionType.from_int(99)` element inside the
Parameter Request List) and passed it to the assembler
would otherwise emit a frame with an unknown codepoint
that strict receivers cannot interpret.

**Enforcement:** `Dhcp4Assembler.__init__` at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__assembler.py`
walks the construction-time arguments and rejects any
`UNKNOWN_*` enum member with `AssertionError`:

- `dhcp4__operation` (§RFC 2131 §2 op field —
  BOOTREQUEST=1 / BOOTREPLY=2 only).
- `dhcp4__options[i]` of type `Dhcp4OptionMessageType`
  → its `message_type` (§9.6 values 1..8 only).
- `dhcp4__options[i]` of type `Dhcp4OptionParamReqList`
  → each `param_req_list[j]` element (§9.8 codepoints
  must be a known `Dhcp4OptionType` member).

Dataclass `__post_init__` deliberately stays
parser-tolerant for these enum fields (the parser
materialises UNKNOWN members during `from_buffer` and
needs them to round-trip into `_validate_sanity`); the
strict rejection lives at the assembler boundary,
mirroring the END terminator and sname/file ASCII
checks already there.

Pinned by `TestDhcp4AssemblerUnknownEnumReject` at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__assembler__operation.py`.

---

## Parser integrity contract

`Dhcp4Parser._parse` raises `Dhcp4IntegrityError` (and only
that, plus `Dhcp4SanityError` from `_validate_sanity`) for
every hostile-wire input. No `(AssertionError,
UnicodeDecodeError, NetAddrError)` wrap. The contract is
that every wire-shape problem is caught at the closest
validation boundary:

- **Header-level invariants** (`hrtype == ETHERNET`,
  `hrlen == 6`, `magic_cookie == 0x63825363`) raise
  `Dhcp4IntegrityError` directly from
  `Dhcp4Header.from_buffer`.
- **Per-option wire-shape invariants** (length-byte
  bounds, value-range bounds, contiguity / UTF-8 /
  enum-domain pre-validation) raise `Dhcp4IntegrityError`
  from each option's static `_validate_integrity` called
  at the top of its `from_buffer` — before any dataclass
  construction.
- **Dataclass `__post_init__` asserts** stay as the
  programmer-error guardrail (constructor misuse) and are
  unreachable from the wire-input path; an `AssertionError`
  bubbling out of `Dhcp4Parser._parse` indicates a bug in
  PyTCP, not a hostile wire frame.

When adding a new option, the option author's
responsibility is to mirror every dataclass invariant that
could be tripped by a hostile wire frame into the
option's `_validate_integrity`. Reviewer entitled to
bounce a PR that adds an `__post_init__` assert reachable
from `from_buffer` without the parallel `_validate_integrity`
check.

---

## Per-option assembler-audit summary

The DHCPv4 assembler audit pass (2026-05-20) walked
every per-option file and surfaced the gaps catalogued
in the per-option sections above. The table below
records the audit findings for each option for archaeology:

| Option                       | RFC §  | Bounds gap | UNKNOWN-enum gap | Wire-side leak  |
|------------------------------|--------|------------|------------------|-----------------|
| Pad (0)                      | §3.1   | n/a        | n/a              | n/a             |
| Subnet Mask (1)              | §3.3   | none       | n/a              | **fixed** (Ip4MaskFormatError) |
| Router (3)                   | §3.5   | **fixed** (1..63) | n/a       | none            |
| Host Name (12)               | §3.14  | **fixed** (UTF-8 byte count) | n/a | **fixed** (invalid UTF-8 typed reject) |
| Requested IP Address (50)    | §9.1   | none       | n/a              | none            |
| IP Address Lease Time (51)   | §9.2   | none (full uint32 range valid) | n/a | none |
| Option Overload (52)         | §9.3   | already enforced (value ∈ {1,2,3}) | n/a | already enforced (typed Dhcp4IntegrityError) |
| Message Type (53)            | §9.6   | none       | **fixed** (assembler-strict) | none |
| Server Identifier (54)       | §9.7   | none       | n/a              | none            |
| Parameter Request List (55)  | §9.8   | **fixed** (1..255) | **fixed** (assembler-strict elements) | **fixed** (Length=0 typed reject) |
| Maximum DHCP Message Size (57) | §9.10 | already enforced (≥576) | n/a | **fixed** (below-576 typed reject) |
| Renewal (T1) Time Value (58) | §9.7   | none       | n/a              | none            |
| Rebinding (T2) Time Value (59) | §9.8 | none       | n/a              | none            |
| Client-identifier (61)       | §9.14  | **fixed** (2..255) | n/a        | **fixed** (Length<2 typed reject) |
| End (255)                    | §3.2   | n/a        | n/a              | n/a             |
| Unknown (catch-all)          | n/a    | n/a        | n/a (by-design)  | n/a             |

Plus header-level fixes:
- `Dhcp4Header` non-ASCII sname/file enforced at
  assembler TX (`Dhcp4Assembler.__init__`) per RFC 2131 §2.
- `Dhcp4Assembler` enforces trailing `Dhcp4OptionEnd` per RFC 2132 §3.
- `Dhcp4Assembler` rejects `UNKNOWN_*` `dhcp4__operation`
  per RFC 2131 §2 (BOOTREQUEST/BOOTREPLY only).

---

## Options not implemented

The following RFC 2132 options are not in PyTCP's
catalogue (`Dhcp4OptionType` at
`options/dhcp4__option.py:56-76`). Inbound options
carrying any of these codes parse into a
`Dhcp4OptionUnknown` wrapper that preserves the wire
bytes but exposes no typed accessor.

| Code | Option name                       | RFC §  | Reason                                                |
|------|-----------------------------------|--------|-------------------------------------------------------|
| 2    | Time Offset                       | §3.4   | Timezone — out of scope (no TZ consumer)              |
| 4    | Time Server                       | §3.6   | Out of scope                                          |
| 5    | Name Server (IEN-116)             | §3.7   | Obsolete                                              |
| 6    | Domain Name Server                | §3.8   | DNS not in Phase-1 scope                              |
| 7    | Log Server                        | §3.9   | Out of scope                                          |
| 8    | Cookie Server                     | §3.10  | Out of scope                                          |
| 9    | LPR Server                        | §3.11  | Out of scope                                          |
| 10   | Impress Server                    | §3.12  | Obsolete                                              |
| 11   | Resource Location Server          | §3.13  | Obsolete                                              |
| 13   | Boot File Size                    | §3.15  | PXE — out of scope                                    |
| 14   | Merit Dump File                   | §3.16  | Obsolete                                              |
| 15   | Domain Name                       | §3.17  | DNS                                                   |
| 16   | Swap Server                       | §3.18  | Out of scope                                          |
| 17   | Root Path                         | §3.19  | NFS — out of scope                                    |
| 18   | Extensions Path                   | §3.20  | Obsolete                                              |
| 19   | IP Forwarding Enable/Disable      | §4.1   | Phase-2 router parity                                 |
| 20   | Non-Local Source Routing          | §4.2   | Out of scope                                          |
| 21   | Policy Filter                     | §4.3   | Out of scope                                          |
| 22   | Max Datagram Reassembly Size      | §4.4   | Not consumed                                          |
| 23   | Default IP TTL                    | §4.5   | Not consumed                                          |
| 24   | Path MTU Aging Timeout            | §4.6   | PMTUD — Phase-2 scope                                 |
| 25   | Path MTU Plateau Table            | §4.7   | PMTUD — Phase-2 scope                                 |
| 26   | Interface MTU                     | §5.1   | Not consumed (uses static config)                     |
| 27   | All Subnets Local                 | §5.2   | Out of scope                                          |
| 28   | Broadcast Address                 | §5.3   | Auto-derived from mask                                |
| 29   | Perform Mask Discovery            | §5.4   | ICMP-mask discovery — out of scope                    |
| 30   | Mask Supplier                     | §5.5   | Server-side                                           |
| 31   | Perform Router Discovery          | §5.6   | RFC 1256 router discovery — out of scope              |
| 32   | Router Solicitation Address       | §5.7   | Out of scope                                          |
| 33   | Static Route                      | §5.8   | Obsolete; superseded by RFC 3442 classless variant    |
| 34   | Trailer Encapsulation             | §5.9   | Obsolete                                              |
| 35   | ARP Cache Timeout                 | §5.10  | Not consumed (PyTCP uses sysctl)                      |
| 36   | Ethernet Encapsulation            | §5.11  | RFC 894 default; not negotiated                       |
| 37   | TCP Default TTL                   | §5.12  | Not consumed                                          |
| 38   | TCP Keepalive Interval            | §5.13  | Not consumed                                          |
| 39   | TCP Keepalive Garbage             | §5.14  | Not consumed                                          |
| 40   | Network Information Service Domain | §6.1  | NIS — obsolete                                        |
| 41   | NIS Servers                       | §6.2   | NIS — obsolete                                        |
| 42   | NTP Servers                       | §6.3   | NTP — out of scope                                    |
| 43   | Vendor Specific                   | §6.4   | Out of scope                                          |
| 44   | NetBIOS over TCP/IP Name Server   | §6.5   | NetBIOS — obsolete                                    |
| 45   | NetBIOS over TCP/IP Datagram Dist | §6.6   | NetBIOS — obsolete                                    |
| 46   | NetBIOS over TCP/IP Node Type     | §6.7   | NetBIOS — obsolete                                    |
| 47   | NetBIOS over TCP/IP Scope         | §6.8   | NetBIOS — obsolete                                    |
| 48   | X Window System Font Server       | §6.9   | Obsolete                                              |
| 49   | X Window System Display Manager   | §6.10  | Obsolete                                              |
| 52   | Option Overload                   | §9.3   | met (parsing) — see §9.3 below                        |
| 56   | Message                           | §9.9   | Server-side error string                              |
| 57   | Maximum DHCP Message Size         | §9.10  | met (emitted in DISCOVER + REQUEST; Phase 8.1)        |
| 58   | Renewal Time (T1)                 | §9.11  | Not consumed (no FSM)                                 |
| 59   | Rebinding Time (T2)               | §9.12  | Not consumed (no FSM)                                 |
| 60   | Vendor class identifier           | §9.13  | Not emitted                                           |
| 62   | NetWare/IP Domain Name            | §8.1   | NetWare — obsolete                                    |
| 63   | NetWare/IP information            | §8.2   | NetWare — obsolete                                    |
| 64   | NIS+ Domain                       | §6.13  | Obsolete                                              |
| 65   | NIS+ Servers                      | §6.14  | Obsolete                                              |
| 66   | TFTP Server Name                  | §9.4   | PXE — out of scope                                    |
| 67   | Bootfile Name                     | §9.5   | PXE — out of scope                                    |
| 68   | Mobile IP Home Agent              | §6.15  | Mobile IP — out of scope (north-star non-goal)        |
| 69   | SMTP Server                       | §6.16  | Out of scope                                          |
| 70   | POP3 Server                       | §6.17  | Out of scope                                          |
| 71   | NNTP Server                       | §6.18  | Out of scope                                          |
| 72   | WWW Server                        | §6.19  | Out of scope                                          |
| 73   | Finger Server                     | §6.20  | Out of scope                                          |
| 74   | IRC Server                        | §6.21  | Out of scope                                          |
| 75   | StreetTalk Server                 | §6.22  | Obsolete                                              |
| 76   | StreetTalk Directory Assistance   | §6.23  | Obsolete                                              |

## Option Overload (code 52)

> "This option is used to indicate that the DHCP
>  'sname' or 'file' fields are being overloaded by
>  using them to carry DHCP options. A DHCP server
>  inserts this option if the returned parameters will
>  exceed the usual space allotted for options."

**Adherence:** met (parsing). `Dhcp4OptionOverload` at
`options/dhcp4__option__overload.py` enforces the
`value ∈ {1, 2, 3}` constraint at both
`__post_init__` (assembler-strict) and
`_validate_integrity` (RX-strict, typed
`Dhcp4IntegrityError`). The parser's
`Dhcp4Parser._apply_option_overload` re-extracts the
overloaded 'file' and/or 'sname' bytes from the frame,
runs them through `Dhcp4OptionsProperties.validate_integrity`
(see hostile-blob safety below), parses the sub-block
via `Dhcp4Options.from_buffer`, and merges the result
into the unified `parser.options` view. The
`Dhcp4Header` `from_buffer` uses
`bytes.decode("ascii", errors="replace")` on the raw
'sname' and 'file' bytes so the original wire image is
re-extractable for overlay parsing — the ASCII view is
discarded once overload signalling is detected.

**Wire-format hostile-blob safety (parser):** a hostile
server could embed an option inside the overloaded
'sname' (64 bytes) or 'file' (128 bytes) field whose
Length byte advertises more trailing data than the
slice carries. Without preflight, the sub-block dispatch
in `Dhcp4Options.from_buffer` would walk past the slice
end and either silently truncate or raise an untyped
exception.

`Dhcp4OptionsProperties.validate_integrity` accepts an
`offset` parameter (default 240 for the main option
block; the overload pass calls it with `offset=0`) so
the same TLV walker that protects the main options
block also guards each overloaded sub-block. A
malformed sub-option raises a typed
`Dhcp4IntegrityError` before `from_buffer` dispatches.

Pinned by
`TestDhcp4ParserOptionOverload` (happy path: file-only,
sname-only, both fields merged) and
`TestDhcp4ParserOptionOverloadHostileBlob` (hostile
sname with Length past slice end; hostile file with
missing length byte) at
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__option_overload.py`.

---

## Test coverage audit

### §2 Option wire format

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__options.py` (812 lines)
  Pins container behaviour: composition, ordering,
  serialised length, lookup properties.

**Status:** locked in.

### §3.1 / §3.2 Pad / End

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__pad.py` (235 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__end.py` (235 lines)

**Status:** locked in.

### §3.3 / §3.5 / §3.14 Subnet Mask / Router / Host Name

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__subnet_mask.py` (499 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__router.py` (542 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__host_name.py` (436 lines)

**Status:** locked in.

### §9.1 / §9.2 Requested IP / Lease Time

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__req_ip_addr.py` (499 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__lease_time.py` (432 lines)

**Status:** locked in (wire format). The client consumes
the ACK's lease-time value to drive T1/T2 and lease
expiry, pinned by
`test__dhcp4_client__fetch_returns_lease_time_from_ack`
in `test__dhcp4__client.py`.

### §9.6 / §9.7 / §9.8 / §9.14 Message Type / Server ID / Param Req List / Client ID

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__message_type.py` (461 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__server_id.py` (499 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__param_req_list.py` (510 lines)
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__client_id.py` (409 lines)

**Status:** locked in.

### Unknown option fallthrough

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__unknown.py` (522 lines)
  Pins that unknown codes round-trip as
  `Dhcp4OptionUnknown` preserving wire bytes.

**Status:** locked in.

### §9.3 Option Overload

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__overload.py`
  (10 tests) — codec round-trip for legal values
  (1 / 2 / 3), `includes_file` / `includes_sname`
  decoders, integrity rejections (bad length, bad
  value, wrong option type).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__option_overload.py`
  (6 tests) — parser-side merge of options from BOOTP
  'sname' / 'file' fields for overload=1/2/3, the
  negative case that those fields stay inert without
  option 52, and hostile-blob preflight rejection
  paths.

**Status:** locked in (Phase 8.4).

### Test coverage summary

| Aspect                                          | Coverage                          |
|-------------------------------------------------|-----------------------------------|
| Implemented option wire format (16 codecs)      | locked in (~5 200 unit lines)     |
| Unknown option fallthrough                      | locked in                         |
| Options container ordering / lookup             | locked in                         |
| Option Overload (code 52) parsing               | locked in (16 unit tests)         |
| Maximum DHCP Message Size (57) emission         | locked in (Phase 8.1; 9 codec tests + emit tests) |
| RFC 3396 long-option concatenation              | locked in (Phase 8.3 client/receive side; same-code merge before codec) |
| Lease-time consumption by client                | locked in (drives T1/T2 in FSM)   |

---

## Overall assessment

| Aspect                                       | Status                                                          |
|----------------------------------------------|-----------------------------------------------------------------|
| §2 TLV wire format                           | met                                                             |
| §3.1 / §3.2 Pad / End                        | met (and emitted)                                               |
| §3.3 Subnet Mask (1)                         | met (parsed + consumed)                                         |
| §3.5 Router (3)                              | met (parsed + first router consumed)                            |
| §3.14 Host Name (12)                         | met (emitted as "PyTCP")                                        |
| §9.1 Requested IP Address (50)               | met (emitted in REQUEST)                                        |
| §9.2 IP Address Lease Time (51)              | met (emitted hint + consumed; drives T1/T2)                     |
| §9.3 Option Overload (52)                    | met (parsing — `Dhcp4Parser._apply_option_overload` + hostile-blob preflight) |
| §9.6 DHCP Message Type (53)                  | met (all 8 codepoints declared; DISCOVER/REQUEST emitted)       |
| §9.7 Server Identifier (54)                  | met (echoed in REQUEST)                                         |
| §9.8 Parameter Request List (55)             | met (consistent across DISCOVER/REQUEST)                        |
| §9.10 Maximum DHCP Message Size (57)         | met (emitted in DISCOVER + REQUEST; sysctl-tunable `DHCP4__MAX_MSG_SIZE`; Phase 8.1) |
| §9.11 / §9.12 T1 / T2 (58, 59)               | not consumed (no FSM)                                           |
| §9.13 Vendor class identifier (60)           | not implemented                                                 |
| §9.14 Client Identifier (61)                 | met (RFC 4361 form in every message)                            |
| RFC 3396 long-option concatenation           | met (client / receive — same-code merge in `Dhcp4Options.from_buffer`; Phase 8.3). Server-side splitting deferred to Phase-2 DHCP server. |
| All other 60+ options (DNS, NTP, NIS, ...)   | not implemented (out of host-parity scope)                      |

**Principal compliance note.** Both formerly-open
client-side gaps are now closed:

1. **Client Identifier in every message**
   (RFC 2131 §2 MUST). The client emits the RFC 4361
   form via `_expected_client_id` in DISCOVER, REQUEST,
   INIT-REBOOT, RENEW, RELEASE, and DECLINE — see §9.14
   above.

2. **Lease-time consumed.** The client reads
   `ack.lease_time` from the ACK and plumbs it into the
   RFC 2131 §4.4.5 FSM so the T1/T2 timers drive
   RENEW/REBIND and the hard expiry — see §9.2 above.

Everything else in this RFC is either out of host
scope (NIS, NetBIOS, X11) or wire-format-only with the
codec implemented but no semantic consumer.
