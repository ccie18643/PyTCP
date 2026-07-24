# RFC 791 — Internet Protocol

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 791                                                |
| Title       | Internet Protocol — DARPA Internet Program         |
| Category    | Internet Standard (STD 5)                          |
| Date        | September 1981                                     |
| Updated by  | RFC 1349, 2474, 6864 (and many more)               |
| Source text | [`rfc791.txt`](rfc791.txt)                         |

This document records the PyTCP codebase's adherence to RFC 791
§3.1 (Internet Header Format) and the immediately related
algorithmic sections (§3.2 Fragmentation discussion). The audit
was performed by reading the RFC text fresh and inspecting the
codebase under `packages/net_proto/net_proto/protocols/ip4/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__*.py` directly;
no prior memory or rule-file content was reused. Sections that
contain no normative wire-format / algorithm content
(§1 Introduction, §2 Overview, §3.3 Interfaces process-level
prose, Appendix A examples) are omitted. Wire fields whose
semantics have been wholly redefined by later RFCs (Type of
Service → DSCP+ECN per RFC 2474 / RFC 3168, Identification
uniqueness rules per RFC 6864) are audited under those records
and cross-referenced here.

---

## Top-line adherence

PyTCP **shipped** the RFC 791 wire format and host-side
processing. Header parsing, assembly, on-receive validation,
on-send fragmentation, options framework, and ICMP error
generation on header violations are all in place. Specific
gaps: source-route option processing is gated behind a Linux-
parallel `IP4__ACCEPT_SOURCE_ROUTE` knob (off by default),
forwarding is Phase 2.

| Section | Topic                              | Status      | Implementing file(s) |
|---------|------------------------------------|-------------|----------------------|
| §3.1    | Header format / each wire field    | shipped     | `packages/net_proto/net_proto/protocols/ip4/ip4__header.py` |
| §3.1    | Header checksum                    | shipped     | `packages/net_proto/net_proto/lib/inet_cksum.py` + `ip4__parser.py:108` / `ip4__assembler.py:118` |
| §3.1    | Options framework + nine options   | shipped     | `packages/net_proto/net_proto/protocols/ip4/options/` (10 files) |
| §3.2    | Fragmentation on send              | shipped     | `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__tx.py:288-323` |
| §3.2    | Reassembly on receive              | shipped     | `packages/pytcp/pytcp/protocols/ip/ip_frag.py`, `ip_frag_table.py`, plus RFC 815 audit |
| §3.2    | TTL decrement / TTL=0 drop         | partial     | RX enforces `ttl > 0`; forwarding decrement is Phase 2 |
| Appendix B | Network byte order              | shipped     | `struct` format strings prefixed `! `                |

---

## §3.1 Version

> "Version: 4 bits. The Version field indicates the format of
> the internet header. This document describes version 4."

**Adherence:** shipped. `Ip4Header.ver` is a non-init `IpVersion`
field pinned to `IpVersion.IP4`
(`packages/net_proto/net_proto/protocols/ip4/ip4__header.py:93-97`). The parser
rejects any frame whose first nibble is not 4 at integrity
(`ip4__parser.py:102-105`).

## §3.1 IHL (Internet Header Length)

> "IHL: 4 bits. Internet Header Length is the length of the
> internet header in 32 bit words, and thus points to the
> beginning of the data. Note that the minimum value for a
> correct header is 5."

**Adherence:** shipped. `Ip4Header.hlen` is stored in **bytes**
(not 32-bit words) so the field is uniform with the rest of
the header. Pack/unpack converts via `>> 2` / `<< 2`
(`ip4__header.py:182,217`). `__post_init__` enforces
`20 <= hlen <= 60` and `is_4_byte_alligned(hlen)`
(`ip4__header.py:118-126`). Parser integrity check enforces
`IP4__HEADER__LEN <= hlen <= plen <= len(frame)`
(`ip4__parser.py:116-120`).

## §3.1 Type of Service / DSCP+ECN

> "Type of Service: 8 bits. The Type of Service provides an
> indication of the abstract parameters of the quality of
> service desired."

**Adherence:** shipped, **redefined**. PyTCP follows the modern
DSCP+ECN split (RFC 2474 + RFC 3168) rather than the original
Precedence/D/T/R encoding. The header surfaces two separate
fields `dscp: int` (6 bits) and `ecn: int` (2 bits) which the
pack code combines into the single TOS byte
(`ip4__header.py:183`). The legacy Precedence / Delay /
Throughput / Reliability semantics are not honoured because
they have been deprecated for ~30 years. Cross-references:
DSCP audit (`docs/rfc/ip4/rfc2474__dscp/adherence.md`), ECN
audit (`docs/rfc/ip4/rfc3168__ecn/adherence.md`).

## §3.1 Total Length

> "Total Length: 16 bits. Total Length is the length of the
> datagram, measured in octets, including internet header and
> data. ... All hosts must be prepared to accept datagrams of
> up to 576 octets (whether they arrive whole or in
> fragments)."

**Adherence:** shipped. `Ip4Header.plen` is an unsigned 16-bit
field (`ip4__header.py:101,132-140`). The "576 octet minimum
MTU" floor is asserted at module scope as
`IP4__MIN_MTU = 576` (`ip4__header.py:76`) and consulted by
PMTUD (RFC 1191 audit) and the TX path's MTU comparison
(`packet_handler__ip4__tx.py:232`). Parser enforces
`plen >= IP4__HEADER__LEN` and `plen <= len(frame)`
(`ip4__parser.py:116-120`).

## §3.1 Identification

> "Identification: 16 bits. An identifying value assigned by
> the sender to aid in assembling the fragments of a datagram."

**Adherence:** shipped on the assembler side as a simple
monotonic counter (`self._ip4_id += 1` per fragmented packet
in `packet_handler__ip4__tx.py:193`). Uniqueness rules and
the "atomic datagram" relaxation are audited under RFC 6864
(`docs/rfc/ip4/rfc6864__ip4_id_field/adherence.md`).
RX side: the field is parsed and fed into the reassembly
flow key (`ip_frag.py` / `ip_frag_table.py`); see RFC 815
audit.

## §3.1 Flags (Reserved / DF / MF)

> "Flags: 3 bits. Bit 0: reserved, must be zero. Bit 1: (DF) 0 =
> May Fragment, 1 = Don't Fragment. Bit 2: (MF) 0 = Last
> Fragment, 1 = More Fragments."

**Adherence:** shipped. `flag_df` and `flag_mf` are typed
`bool` on the dataclass; bit 0 ("reserved, must be zero") is
**not** explicitly enforced by the parser — the pack code
hard-wires bit 0 to 0 on TX (no field exists to set it), and
the unpack code masks only bits 1-2 (`ip4__header.py:222-223`),
so a hostile peer setting bit 0 has the bit silently discarded
on parse rather than the packet being rejected. This matches
Linux `net/ipv4/ip_input.c::ip_rcv_core` which likewise does
not reject Reserved=1.

Sanity rules enforced:
`flag_df && flag_mf` → `Ip4SanityError` + ICMP Parameter
Problem (`ip4__parser.py:226-231`), and
`flag_df && offset != 0` → `Ip4SanityError` + ICMP Parameter
Problem (`ip4__parser.py:235-239`). Both are RFC 1122
§3.2.1.4 hardenings; cited in the parser docstring.

## §3.1 Fragment Offset

> "Fragment Offset: 13 bits. This field indicates where in the
> datagram this fragment belongs. The fragment offset is
> measured in units of 8 octets (64 bits). The first fragment
> has offset zero."

**Adherence:** shipped. `Ip4Header.offset` is stored in
**bytes** (8-byte-aligned) so it composes naturally with
payload slicing; pack/unpack converts via `>> 3` / `<< 3`
(`ip4__header.py:186,224`). `__post_init__` enforces
`is_uint13(offset >> 3)` and `is_8_byte_alligned(offset)`
(`ip4__header.py:148-152`). Fragmentation on send slices
the payload at MTU-aligned 8-byte boundaries
(`packet_handler__ip4__tx.py:288-291`, via
`iter_fragment_chunks(max_chunk_bytes=self._if._interface_mtu - ip4_packet_tx.hlen)`).

## §3.1 Time to Live

> "Time to Live: 8 bits. ... If this field contains the value
> zero, then the datagram must be destroyed."

**Adherence:** partial. On RX, `Ip4Parser._validate_sanity`
rejects `ttl == 0` and the handler emits ICMPv4 Parameter
Problem with pointer = 8 (`ip4__parser.py:162-166`,
`packet_handler__ip4__rx.py:309-354`). This is the host-side
"refuse delivery of a TTL=0 datagram" half of the rule.

The forwarding half ("each module decrements TTL by at least
1") is **Phase 2** — PyTCP today is a host stack and never
forwards. Outbound TTL is set to `IP4__DEFAULT_TTL = 64`
(matching Linux's `net.ipv4.ip_default_ttl`) unless the caller
overrides (`packet_handler__ip4__tx.py:100`). `# Phase 2:`
forwarding decrement and ICMP Time Exceeded generation will
land with the router track.

## §3.1 Protocol

> "Protocol: 8 bits. This field indicates the next level
> protocol used in the data portion of the internet datagram."

**Adherence:** shipped. `Ip4Header.proto: IpProto` is a typed
enum (`packages/net_proto/net_proto/lib/enums.py::IpProto`). RX dispatches via
a proto→handler lookup on `self._if._ip4_proto_registry`
(`packet_handler__ip4__rx.py:250`); a registry miss is an
unsupported transport protocol — the packet is
dropped and triggers an ICMPv4 Destination Unreachable code 2
(Protocol Unreachable) subject to the RFC 1122 / RFC 1812
gates and the error rate limiter (`__phrx_ip4__emit_protocol_unreachable`, lines 262-307).

## §3.1 Header Checksum

> "Header Checksum: 16 bits. A checksum on the header only.
> Since some header fields change (e.g., time to live), this
> is recomputed and verified at each point that the internet
> header is processed. ... the 16 bit one's complement of the
> one's complement sum of all 16 bit words in the header."

**Adherence:** shipped. `inet_cksum` is implemented in
`packages/net_proto/net_proto/lib/inet_cksum.py` as the canonical one's-complement
sum. RX integrity check rejects any header where
`inet_cksum(self._frame[:hlen])` evaluates to non-zero
(`ip4__parser.py:127-130`). TX path injects the freshly-
computed checksum into the header `bytearray` just before
appending to the buffer list (`ip4__assembler.py:118`,
`packet_handler__ip4__rx.py:413` for the reassembled-packet
rewrite).

## §3.1 Source / Destination Address

> "Source Address: 32 bits. ... Destination Address: 32 bits."

**Adherence:** shipped. Both stored as `Ip4Address` value-type
instances (`packages/net_addr/net_addr/ip4_address.py`); the parser's
`from_buffer` constructs them via the integer constructor
form (`ip4__header.py:228-229`).

Host-side sanity rules go beyond bare RFC 791, in ascending
address-space order:
- **`src.is_invalid`** (`0.0.0.1`–`0.255.255.255`, the 0.0.0.0/8
  "this network" range minus the DHCP-init 0.0.0.0 unspecified
  source) → reject (RFC 1122 §3.2.1.3(a))
- **`src.is_loopback`** (`127.0.0.0/8`) → reject (RFC 1122
  §3.2.1.3(g) — "127/8 ... MUST NOT appear outside a host")
- **`src.is_multicast`** (`224.0.0.0/4`) → reject (RFC 1122
  §3.2.1.3 — class D is not a host source)
- **`src.is_reserved`** (`240.0.0.0/4` minus `255.255.255.255`) →
  reject (RFC 1122 §3.2.1.3 / RFC 6890)
- **`src.is_limited_broadcast`** (`255.255.255.255`) → reject
  (RFC 1122 §3.2.1.3(c) — limited broadcast MUST NOT be source)

All five raise `Ip4SanityError` with `pointer=12` and trigger
ICMPv4 Parameter Problem
(`ip4__parser.py` `_validate_sanity`,
`packet_handler__ip4__rx.py:309-354`). The `src.is_unspecified`
case (`0.0.0.0` exactly) is deliberately **not** rejected at
parser level so DHCPv4 client discovery (which uses
`src=0.0.0.0` per RFC 2131) can reach the UDP RX path.
TX-side source selection runs the RFC 6724-style rules 1, 2,
and 8 across the owned candidate set
(`packet_handler__ip4__tx.py:477-521`) with a DHCPv4 carve-out
for src=0.0.0.0 (lines 432-443).

## §3.1 Options (framework)

> "Options: variable. ... There may be zero or more options.
> ... Case 1: A single octet of option-type. Case 2: An
> option-type octet, an option-length octet, and the actual
> option-data octets."

**Adherence:** shipped. The `Ip4Options` container at
`packages/net_proto/net_proto/protocols/ip4/options/ip4__options.py` parses the
TLV stream into a typed object per option, then exposes
typed accessors (`options.lsrr`, `options.ssrr`,
`options.router_alert`, etc.). Per-option files cover each
defined kind:

| Type | Length    | Class | Module                          | Status      |
|------|-----------|-------|---------------------------------|-------------|
| 0    | 1         | 0     | `ip4__option__eol.py`           | shipped     |
| 1    | 1         | 0     | `ip4__option__nop.py`           | shipped     |
| 7    | var       | 0     | `ip4__option__rr.py`            | shipped     |
| 130  | 11        | 0     | (Security — deferred; no IETF base) | not implemented (Phase 2/3) |
| 131  | var       | 0     | `ip4__option__lsrr.py`          | shipped (RX echo gated by `IP4__ACCEPT_SOURCE_ROUTE`) |
| 137  | var       | 0     | `ip4__option__ssrr.py`          | shipped (RX echo gated by `IP4__ACCEPT_SOURCE_ROUTE`) |
| 8    | 4         | 0     | (Stream ID — deprecated by RFC 6814) | not implemented |
| 68   | var       | 2     | `ip4__option__timestamp.py`     | shipped     |
| 134  | var       | 0     | `ip4__option__cipso.py`         | shipped (wire codec; semantics deferred) |
| 148  | 4         | 0     | `ip4__option__router_alert.py`  | shipped (RFC 2113 / RFC 6398; we honour it on receive) |
| any  | var       | -     | `ip4__option__unknown.py`       | shipped (preserves wire for unrecognized kinds) |

The "copied flag" semantics on the option-type byte are
**honoured** on fragmentation: when the TX path splits an
oversized packet (`packet_handler__ip4__tx.py:269-323`), the
first fragment carries the full original options and every
subsequent fragment carries only the copy_flag=1 subset
(`options.with_copy_flag(True)` padded to a 4-byte boundary
with NOPs). The `Ip4Option.copy_flag` property in
`packages/net_proto/net_proto/protocols/ip4/options/ip4__option.py` extracts
bit 7 of the option-type byte. RX reassembly preserves the
first fragment's full options per RFC 815 §6 — see the
RFC 815 audit's §6 entry.

> "The options may appear or not in datagrams. They must be
> implemented by all IP modules (host and gateways)."

**Adherence:** shipped on parse. Every defined option from the
list above is parsed into a typed object even if PyTCP does
not act on it; unknown kinds are preserved as
`Ip4OptionUnknown` rather than dropped, so the parser cannot
be made to fail on an option it doesn't recognize. Option
filtering policy (whether to **accept** datagrams with each
option kind) is audited under RFC 7126.

### Per-option parser integrity surface

Each per-option parser carries a `_validate_integrity` static
method that runs against the on-wire buffer before the
dataclass constructor is invoked. Hostile-wire values that
would otherwise trip the dataclass `__post_init__` asserts
(and leak as bare `AssertionError`) are caught here and
re-raised as `Ip4IntegrityError` so the IP4 RX handler's
`PacketValidationError` catch can drop the frame cleanly.

| Option | `_validate_integrity` enforces | RFC clause |
|--------|--------------------------------|------------|
| LSRR (131) | `length ≥ 7`; `(length − 3) % 4 == 0`; `length ≤ buffer`; `pointer ≥ 4`; `(pointer − 4) % 4 == 0` | RFC 791 §3.1 'Loose Source and Record Route' |
| SSRR (137) | same shape as LSRR | RFC 791 §3.1 'Strict Source and Record Route' |
| RR (7)     | `length ≥ 7`; `(length − 3) % 4 == 0`; `length ≤ buffer`; `pointer ≥ 4`; `(pointer − 4) % 4 == 0` | RFC 791 §3.1 'Record Route' |
| Timestamp (68) | `flag ∈ {0, 1, 3}`; `length ≥ 4 + entry_len(flag)`; `(length − 4) % entry_len == 0`; `length ≤ buffer`; `pointer ≥ 5`; `(pointer − 5) % entry_len == 0` | RFC 791 §3.1 'Internet Timestamp' |
| Router Alert (148) | `length == 4`; `length ≤ buffer` | RFC 2113 §2.1 |
| CIPSO (134) | `length ≥ 6`; `length ≤ buffer`; per-tag walk (tag header ≥ 2, tag-len ≥ 2, tag fits) | FIPS-188 §4; Linux `net/ipv4/cipso_ipv4.c::cipso_v4_validate` |
| Unknown    | `length ≤ buffer` (RFC 1122 §3.2.1.8 silent-preserve for unrecognised kinds) | RFC 791 §3.1 (Case-2 TLV) |
| EOL (0) / NOP (1) | type-byte verification only (Case-1 TLV, no length field) | RFC 791 §3.1 'End of Option List' / 'No Operation' |

The pointer-validity checks on LSRR / SSRR / RR / Timestamp
are duplicated in the corresponding dataclass `__post_init__`
asserts — the former is the parser-level integrity gate
(reachable from hostile wire), the latter is the
construction-time invariant for API consumers building an
option object programmatically. The duplication is
deliberate and load-bearing.

## §3.1 Specific Options — Loose / Strict Source Route

> "Loose Source and Record Route (LSRR) ... The loose source
> and record route option provides a means for the source of
> an internet datagram to supply routing information to be
> used by the gateways in forwarding the datagram to the
> destination, and to record the route information."

**Adherence:** wire codec shipped; source-route **processing**
is gated. `Ip4OptionLsrr` / `Ip4OptionSsrr` parse the
type/length/pointer + route-data fields correctly. The RX
handler enforces a Linux-parallel policy gate
(`packet_handler__ip4__rx.py:130-144`): if the
`IP4__ACCEPT_SOURCE_ROUTE` sysctl is False (the default,
matching Linux `net.ipv4.conf.*.accept_source_route=0`) and
the packet carries an LSRR or SSRR option, the packet is
dropped with the `ip4__source_route__drop` counter.

For full source-route semantics (rewriting the destination
field, advancing the pointer, replacing src with our own
address, forwarding) — that's Phase 2 router work. Source-
route deprecation per RFC 6814 §3 is cross-referenced under
that audit; the on-the-wire codec is preserved because
RFC 6814 deprecates the option's *processing*, not its
*recognition*.

## §3.1 Specific Options — Record Route, Timestamp

> "Record Route ... provides a means to record the route of an
> internet datagram." / "Internet Timestamp ..."

**Adherence:** wire codecs shipped (`ip4__option__rr.py`,
`ip4__option__timestamp.py`). Neither option is **acted on**
on receive (the only operation that would matter — appending
the receiver's address into the next pointer slot — is router
work). On send, callers may include them but the stack does
not generate them autonomously. This matches RFC 7126 §4
recommendations for host stacks: parse, do not write, do not
echo blindly.

## §3.1 Specific Options — Router Alert

> "[Router Alert, RFC 2113] ... routers that support this
> option SHOULD examine packets carrying it more closely."

**Adherence:** shipped. `Ip4OptionRouterAlert` parses the
4-byte option. As a host stack PyTCP delivers the packet to
the transport layer normally; the RFC 2113 / RFC 6398
"router examines more closely" requirement is Phase 2.

## §3.1 Specific Options — CIPSO

**Adherence:** wire codec shipped (`ip4__option__cipso.py`).
CIPSO is an IETF draft that never became an RFC; PyTCP
preserves the option on the wire so a CIPSO-enabled deployment
can carry it without rejection, but does not enforce any
labelling semantics. Out of scope for this audit (see
`CLAUDE.md` "Explicit non-goals").

## §3.2 Fragmentation (algorithm — send side)

> "The internet protocol then breaks the datagram into smaller
> pieces (fragments) such that each fragment can pass through
> the next network. ... To fragment a long internet datagram,
> an internet protocol module ... creates n new datagrams and
> copies the contents of the internet header fields from the
> long datagram into all of the new internet headers."

**Adherence:** shipped.
`packet_handler__ip4__tx.py:288-323` slices the payload at
MTU-aligned 8-byte boundaries, assembles one
`Ip4FragAssembler` per slice, copies src / dst / ttl / proto
/ id into each fragment, sets `flag_mf=True` on every fragment
except the last, and writes the `_next_ip4_id()` counter value once
per outbound datagram (line 286).

> "An internet datagram with the Don't Fragment (DF) flag set
> ... may also be discarded ... if it would be fragmented."

**Adherence:** shipped.
`packet_handler__ip4__tx.py:250-257` checks `flag_df` against
the post-assembly length-vs-MTU comparison and drops the
datagram with `DROPPED__IP4__MTU_EXCEED_DF` when DF=1 would
require splitting. The counter
`ip4__mtu_exceed__df_set__drop` is bumped. The PMTUD
ICMPv4-Frag-Needed feedback path is audited under RFC 1191.

## §3.2 Fragmentation (algorithm — receive / reassembly)

> "To assemble the fragments of an internet datagram, an
> internet protocol module ... combines internet datagrams
> that all have the same value for the four fields:
> identification, source, destination, and protocol."

**Adherence:** shipped, audited separately. The four-tuple
flow key is encoded as `IpFragFlowId(src, dst, id, proto)` in
`packages/pytcp/pytcp/protocols/ip/ip_frag.py`; the reassembly state machine
(timer, oversize handling, overlap rejection) is audited
under RFC 815 (`docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`).

## Appendix B — Data Transmission Order

> "The order of transmission of the header and data described
> in this document is resolved to the octet level. ... When
> a multi-octet field is described as an n-octet long field,
> the most significant octet is transmitted first."

**Adherence:** shipped. The `IP4__HEADER__STRUCT` format
string `"! BBH HH BBH L L"` (`ip4__header.py:73`) uses the
`!` (network-order, big-endian) prefix. Every numeric multi-
octet field in PyTCP wire codecs is network-order.

---

## Test coverage audit

### §3.1 Header wire format

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  Constructor boundary asserts on every field (under_min /
  over_max for integer fields, type-mismatch for `flag_df` /
  `flag_mf` / `proto` / `src` / `dst`).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__operation.py`
  Parametrised round-trip matrix covering minimum and
  maximum values for every field plus typical configurations.

**Status:** locked in.

### §3.1 Parser integrity (frame too short, wrong version, hlen/plen, checksum)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__integrity_checks.py`
  Per-branch matrix raising `Ip4IntegrityError` for each
  integrity rule (frame too short, version != 4,
  `hlen < 20` / `hlen > plen` / `plen > len(frame)`, bad
  checksum).

**Status:** locked in.

### §3.1 Parser sanity (TTL=0, src is_invalid/loopback/multicast/reserved/limited-broadcast, DF+MF / DF+offset)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Each `Ip4SanityError` branch covered with its expected
  `pointer` value.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  exercises the ICMPv4 Parameter Problem emission gates and
  rate limiter behaviour.

**Status:** locked in.

### §3.1 Header checksum

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/lib/test__lib__inet_cksum.py`
  one's-complement algorithm against RFC 1071 sample vectors.
- **Integration:** every `Ip4Parser` happy-path round-trip
  test implicitly verifies checksum acceptance and rejection.

**Status:** locked in.

### §3.1 Options framework + per-option parser integrity

- **Unit:** one file per option:
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__option__{eol,nop,rr,lsrr,ssrr,timestamp,router_alert,cipso,unknown}.py`
  Each file's `TestIp4Option<Name>Integrity` class exercises
  every branch of the per-option `_validate_integrity` static
  method including the pointer-base and pointer-alignment
  rejections on LSRR / SSRR / RR / Timestamp (defense-in-depth
  against the hostile-wire `AssertionError` leak that would
  otherwise escape `__post_init__`).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__options.py`
  Container composition + integrity (max length, padding,
  alignment).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__source_route.py`
  exercises the `IP4__ACCEPT_SOURCE_ROUTE` gate (LSRR / SSRR
  drop matrix with and without the override).

**Status:** locked in.

### §3.2 Fragmentation on send

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  contains a fragmentation matrix (DF=0 over MTU produces
  the expected fragment chain; DF=1 over MTU drops with the
  documented counter).

**Status:** locked in.

### §3.2 Reassembly on receive

- **Integration:** see RFC 815 audit
  (`docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`) for the
  per-clause coverage (overlap rejection, timer, header
  rewrite).

**Status:** locked in via the RFC 815 record.

### §3.1 TTL host enforcement

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py::ttl == 0`
  case.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  covers ICMPv4 Parameter Problem emission with `pointer=8`.

**Status:** locked in.

### TX source-address selection (Linux-parallel RFC 6724 application)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  Rule-by-rule selection matrix.

**Status:** locked in.

### §3.1 Options — copy-flag on fragmentation

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__options.py::TestIp4OptionCopyFlag`
  (10 cases — every defined option type plus unknown high-
  bit-set / clear), `TestIp4OptionsWithCopyFlag` (4 cases —
  copy_flag=True / False filter, empty input, non-mutating).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc791OptionCopyFlagOnFragmentation`
  (3 cases — mixed copy-flag fragmentation, copy_flag=0
  only, no-options regression).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rx.py::TestIp4RxRfc791OptionPreservedOnReassembly`
  (2 cases — options preserved on reassembly, no-options
  regression).

**Status:** locked in.

### Phase 2 gaps (forwarding TTL decrement, ICMP Time Exceeded, full source-route processing)

**No test surface — Phase 2.** When the forwarder lands, the
natural tests are:

1. A frame addressed to a non-stack destination → forward path
   decrements TTL by 1; emits ICMPv4 Time Exceeded when TTL
   reaches 0 on decrement.
2. A frame with LSRR `pointer < length` → rewrite dst, update
   route data, decrement TTL, forward.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Header wire fields (every field)                      | locked in |
| Parser integrity branches                             | locked in |
| Parser sanity branches (RFC 1122 derivatives)         | locked in |
| Header checksum (per RFC 1071)                        | locked in |
| Options framework + each defined option codec         | locked in |
| Fragmentation on send (incl. DF=1 drop)               | locked in |
| Reassembly on receive                                 | covered by RFC 815 audit |
| TTL=0 host drop + ICMP Parameter Problem              | locked in |
| RFC 6724-style source-address selection (IPv4 subset) | locked in |
| Source-route gate (`IP4__ACCEPT_SOURCE_ROUTE`)        | locked in |
| Forwarding TTL decrement / Time Exceeded              | n/a (Phase 2) |
| Option copy-bit on fragmentation                      | locked in (shipped) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Version / IHL / Total Length / ID / TTL / Proto  | met    |
| §3.1 Flags (DF, MF) + Fragment Offset                 | met    |
| §3.1 Type of Service (legacy semantics)               | superseded by RFC 2474 + RFC 3168 (audited separately) |
| §3.1 Header Checksum                                  | met    |
| §3.1 Source / Destination Address (host filtering)    | met (with RFC 1122 hardening) |
| §3.1 Options framework + parsing                      | met    |
| §3.1 Options — LSRR / SSRR processing                 | gated off (Linux-parallel) — wire codec met |
| §3.1 Options — copy-bit on fragmentation              | met (shipped) |
| §3.1 Options — Stream ID                              | not implemented (deprecated by RFC 6814) |
| §3.2 Fragmentation on send                            | met    |
| §3.2 Reassembly on receive                            | met (audited under RFC 815) |
| §3.1 / forwarding TTL decrement + Time Exceeded       | not implemented (Phase 2) |
| Appendix B — network byte order                       | met    |

All §3.1 host-side normative requirements are met. The
remaining items are Phase-2 forwarder work tracked under
RFC 1812: forward-path TTL decrement, ICMP Time Exceeded
emission, and full source-route (LSRR/SSRR) pointer
advancement.
