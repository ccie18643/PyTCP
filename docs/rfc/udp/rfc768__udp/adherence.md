# RFC 768 — User Datagram Protocol

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | 768                                  |
| Title       | User Datagram Protocol               |
| Author      | J. Postel                            |
| Category    | Internet Standard (STD 6)            |
| Date        | August 1980                          |
| Updates     | (none — original UDP specification)  |
| Source text | [`rfc768.txt`](rfc768.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 768. The audit was performed by reading the RFC
text fresh and inspecting `packages/net_proto/net_proto/protocols/udp/`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__tx.py`,
and `packages/pytcp/pytcp/runtime/socket/udp__socket.py` directly. Adherence
levels are described in plain language. Sections without
normative content (Introduction, Protocol Application,
References) are omitted.

---

## Top-line adherence

PyTCP **fully meets** the core RFC 768 wire format and
semantics on both the send and receive paths. Two
deviations previously flagged in this audit have been
closed:

- **TX checksum zero-to-all-ones substitution** —
  both serialization paths (`udp__assembler.py::assemble`
  and `udp__base.py::__buffer__`) substitute `0xFFFF`
  for a computed `0x0000`. See §"Fields — Checksum"
  below.
- **RX `sport == 0` acceptance** — the parser no longer
  rejects sport=0; RFC 768 designates the Source Port
  as optional with zero as the "not used" sentinel. See
  §"Fields — Source Port" below.

| Section            | Topic                              | Status |
|--------------------|------------------------------------|--------|
| Format             | 8-byte fixed header wire layout    | met    |
| Fields / Source Port | Optional, zero if absent         | met (TX defaults to 0; RX accepts sport=0) |
| Fields / Destination Port | Per-destination semantics    | met    |
| Fields / Length    | ≥ 8 octets (incl. header)          | met    |
| Fields / Checksum  | One's-complement over pseudo+UDP+data | met (RX + TX compute + TX zero-→-all-ones substitution) |
| Pseudo header      | src+dst+zero+protocol+UDP-length   | met    |
| Checksum-zero RX   | Transmitted 0 = "no checksum"      | met    |
| User Interface     | Create receive ports; recv with source info; send with (data, ports, addresses) | met (BSD socket facade) |
| IP Interface       | UDP module reads src/dst/protocol from IP | met |
| Protocol Number    | IP protocol 17                     | met    |

---

## Format

> "User Datagram Header Format: Source Port (16), Destination
>  Port (16), Length (16), Checksum (16), data octets ..."

**Adherence:** met. The header dataclass at
`packages/net_proto/net_proto/protocols/udp/udp__header.py:54-77` carries the
four 16-bit fields in wire order; `UDP__HEADER__LEN = 8`
and `UDP__HEADER__STRUCT = "! HH HH"` (line 50-51) pin the
big-endian struct format. The ASCII packet diagram at
lines 44-48 mirrors the RFC's diagram verbatim.

---

## Fields — Source Port

> "Source Port is an optional field, when meaningful, it
>  indicates the port of the sending process, and may be
>  assumed to be the port to which a reply should be
>  addressed in the absence of any other information. If
>  not used, a value of zero is inserted."

**Adherence (TX):** met. The assembler at
`packages/net_proto/net_proto/protocols/udp/udp__assembler.py:50-71` defaults
`udp__sport=0`, so a caller that does not care about the
source port emits a datagram with `sport=0` — matching
the RFC's "value of zero" sentinel.

**Adherence (RX):** met. The parser's `_validate_sanity`
at `packages/net_proto/net_proto/protocols/udp/udp__parser.py` no longer
rejects `sport == 0`; only the `dport == 0` rejection
remains (IANA reserves port 0 as unassigned, and Linux
also drops inbound dport=0 — that case is consistent
with the deployed Internet posture rather than a literal
RFC 768 requirement).

Inbound UDP datagrams with `sport=0` parse to completion
and reach the socket-dispatch layer at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`,
where they're delivered to a matching listener via the
normal `(local_addr, local_port, remote_addr,
remote_port=0)` 4-tuple match — the same code path that
handles unconnected receiver sockets.

Pinned by the positive-control test
`TestUdpParserSourcePortOptional::test__udp__parser__source_port_zero_accepted`
at `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py`,
which constructs a sport=0 frame and asserts the parser
runs to completion with `parser.sport == 0` and
`packet_rx.udp` installed.

---

## Fields — Destination Port

> "Destination Port has a meaning within the context of a
>  particular internet destination address."

**Adherence:** met. The RX dispatch path at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:186-219`
constructs a `UdpMetadata` keyed by
`(ip__local_address, udp__local_port)` and walks the
socket table for a matching listener — so the same dport
value can resolve to different sockets depending on the
destination IP.

PyTCP also rejects inbound `dport == 0`
(`udp__parser.py:116-119`). RFC 768 itself does not
forbid this; the IANA registry reserves port 0 as
"unassigned" but Linux conventionally drops dport=0 on
RX as well. The behaviour is consistent with the
deployed Internet posture, just not pinned by RFC 768
itself.

---

## Fields — Length

> "Length is the length in octets of this user datagram
>  including this header and the data. (This means the
>  minimum value of the length is eight.)"

**Adherence:** met. The parser integrity check at
`packages/net_proto/net_proto/protocols/udp/udp__parser.py:76-89` rejects
any datagram where `plen < UDP__HEADER__LEN = 8` and
additionally cross-validates `plen == ip__payload_len`:

```python
if not (UDP__HEADER__LEN <= self._ip__payload_len <= len(self._frame)):
    raise UdpIntegrityError(...)
plen = int.from_bytes(self._frame[4:6])
if not (UDP__HEADER__LEN <= plen == self._ip__payload_len <= len(self._frame)):
    raise UdpIntegrityError(...)
```

The cross-check between `plen` and the IP layer's
payload-length advisory closes an out-of-bounds parse
that the bare-RFC minimum check would miss.

On TX, `udp__assembler.py:69` computes
`plen = UDP__HEADER__LEN + len(self._payload)`, so a
zero-payload datagram emits `plen = 8` (the RFC minimum).

---

## Fields — Checksum

> "Checksum is the 16-bit one's complement of the one's
>  complement sum of a pseudo header of information from
>  the IP header, the UDP header, and the data, padded
>  with zero octets at the end (if necessary) to make a
>  multiple of two octets."

**Adherence:** met. The 16-bit one's-complement sum is
computed by `packages/net_proto/net_proto/lib/inet_cksum.py:39-78` over all
buffers passed in. The UDP TX path at
`packages/net_proto/net_proto/protocols/udp/udp__assembler.py:102-103` calls:

```python
cksum = inet_cksum(header, self._payload, init=self.pshdr_sum)
header[6:8] = (cksum or 0xFFFF).to_bytes(2)
```

where `pshdr_sum` is the precomputed IP pseudo-header
contribution (the IPv4 / IPv6 TX paths populate it).

The RX path at `udp__parser.py:111-140` verifies:

```python
raw_cksum = int.from_bytes(self._frame[6:8])

if raw_cksum == 0:
    ...
    return

if inet_cksum(self._frame[: self._ip__payload_len], init=self._ip__pshdr_sum):
    raise UdpIntegrityError("The packet checksum must be valid.")
```

The `raw_cksum == 0` early-return handles the "no
checksum" sentinel (and the RFC 8200 §8.1 IPv6 discard);
the subsequent unconditional `inet_cksum(...)` returns 0
when the data + pseudo-header sum to all-ones (the one's-
complement zero), so a valid inbound packet passes the
predicate.

> "If the computed checksum is zero, it is transmitted as
>  all ones (the equivalent in one's complement
>  arithmetic). An all zero transmitted checksum value
>  means that the transmitter generated no checksum (for
>  debugging or for higher level protocols that don't
>  care)."

**Adherence (RX zero-skip):** met. The `raw_cksum == 0`
early-return guard at `udp__parser.py:111-113` ensures a
wire value of `0x0000` bypasses checksum validation,
treating the datagram as "sender did not generate a
checksum."

**Adherence (TX zero-→-all-ones substitution):** met.
Both UDP serialization paths apply the substitution
after computing the one's-complement sum:

- `packages/net_proto/net_proto/protocols/udp/udp__assembler.py::assemble`
  (multi-buffer path used by the per-protocol TX
  pipeline).
- `packages/net_proto/net_proto/protocols/udp/udp__base.py::__buffer__`
  (single-buffer path used by `bytes(udp)` and any
  caller that needs a contiguous wire image).

Both use the idiomatic Python short-circuit:

```python
cksum = inet_cksum(header, self._payload, init=self.pshdr_sum)
header[6:8] = (cksum or 0xFFFF).to_bytes(2)
```

`cksum or 0xFFFF` evaluates to `0xFFFF` when the
computed sum is `0` (the only one's-complement zero
representation that would collide with the
"no-checksum" sentinel) and passes any non-zero value
through verbatim.

Pinned by four unit tests at
`packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py::TestUdpAssemblerMisc`
covering both serialization paths × both branches
(zero → substituted, non-zero → pass-through), each
patching `inet_cksum` to drive the predicate
deterministically.

---

## Pseudo header

> "The pseudo header conceptually prefixed to the UDP
>  header contains the source address, the destination
>  address, the protocol, and the UDP length. This
>  information gives protection against misrouted
>  datagrams. This checksum procedure is the same as is
>  used in TCP."

**Adherence:** met. The IPv4 TX path populates the
pseudo-header sum in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__tx.py`
before invoking the UDP assembler; the IPv6 TX path
populates it in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py`.
The `pshdr_sum: int = 0` attribute on `Udp` base
(`packages/net_proto/net_proto/protocols/udp/udp__base.py:49`) is overwritten
per-instance. The RX side mirrors via
`packet_rx.ip.pshdr_sum` and feeds it into `inet_cksum`'s
`init=` argument so the verifier folds the pseudo-header
contribution into the computed sum.

The pseudo-header layout (src/dst + zero + protocol +
length) matches the diagram in RFC 768 page 2 verbatim;
the IPv4 layer constructs it per RFC 791 + RFC 1122
§3.2.1.2, the IPv6 layer per RFC 8200 §8.1.

---

## User Interface

> "A user interface should allow the creation of new
>  receive ports, receive operations on the receive ports
>  that return the data octets and an indication of source
>  port and source address, and an operation that allows a
>  datagram to be sent, specifying the data, source and
>  destination ports and addresses to be sent."

**Adherence:** met. The BSD-socket facade at
`packages/pytcp/pytcp/runtime/socket/udp__socket.py` exposes the full UDP user
interface:

- `bind(address)` at `udp__socket.py:202` — create a
  receive port.
- `recvfrom(bufsize, timeout)` at `udp__socket.py:448` —
  return data octets plus `(source_address, source_port)`
  tuple, satisfying the "indication of source port and
  source address" requirement.
- `sendto(data, address)` at `udp__socket.py:350` —
  specify data + destination, the source address/port
  picked from the bound state.
- `recvmsg(bufsize, ancbufsize, flags, ...)` in
  `udp__socket.py` — the richer receive form: returns the
  data octets, the source `(address, port)` (a 4-tuple for
  IPv6), and ancillary control data (IP_OPTIONS / IP_TOS /
  IPV6_TCLASS cmsgs, and the IP_RECVERR error queue under
  `MSG_ERRQUEUE`), satisfying the "indication of source"
  requirement with the full cmsg surface.
- `sendmsg(buffers, ancdata, flags, address=None)` in
  `udp__socket.py` — the scatter-gather send: concatenates
  the buffer list into one datagram and sends like
  `send` (connected) or `sendto` (when `address` given);
  ancillary data is accepted and Phase-1 ignored (Linux
  silently ignores unhandled cmsgs).
- `recv` / `send` / `connect` / `close` follow the BSD
  conventions for connected and unconnected use.

The socket-API plane is the canonical user surface per
the project's Phase-3 north-star design (BSD socket
factory `socket(AF_INET\|AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`
returns a `UdpSocket`).

---

## IP Interface

> "The UDP module must be able to determine the source
>  and destination internet addresses and the protocol
>  field from the internet header."

**Adherence:** met. The RX path reads `packet_rx.ip.src`,
`packet_rx.ip.dst`, `packet_rx.ip.pshdr_sum`, and
`packet_rx.ip.payload_len` from the parent IP parser
(IPv4 or IPv6) — see
`packet_handler__udp__rx.py:129-137` for the metadata
construction. The TX path injects the pseudo-header sum
via the IP-layer assembler hooks (the IPv4 / IPv6 TX
mixin sets `udp_packet_tx.pshdr_sum` before calling
`assemble`).

> "One possible UDP/IP interface would return the whole
>  internet datagram including all of the internet header
>  in response to a receive operation."

**Adherence:** met as an optional surface via
`RawSocket(AF_INET, SOCK_RAW, IPPROTO_UDP)` /
`SOCK_RAW + IPPROTO_RAW`, which receives the full IP
header plus payload. The normative requirement is only
that such an interface be "possible"; PyTCP exposes it.

---

## Protocol Number

> "This is protocol 17 (21 octal) when used in the
>  Internet Protocol."

**Adherence:** met. `IpProto.UDP = 17` lives in
`packages/net_proto/net_proto/lib/enums.py` (the canonical IANA codepoint).
The IPv4 and IPv6 RX dispatchers use this codepoint to
route inbound packets to `_phrx_udp`.

---

## Parser integrity & sanity surface

PyTCP's UDP parser exposes two staged checks:
`_validate_integrity` (structural pre-parse — buffer
bounds, length consistency, one's-complement checksum,
RFC 8200 §8.1 IPv6 zero-cksum default-discard) and
`_validate_sanity` (post-parse field semantics). Unlike
the wider TCP / ICMP / IP families, UDP has no per-option
files and no `__post_init__` AssertionError leak surface:
every `UdpHeader` field is wire-derived via
`struct.unpack("! HH HH")` which guarantees uint16 by
construction.

### UDP base parser (`udp__parser.py`)

| Phase | Check | RFC clause |
|-------|-------|------------|
| Integrity | `8 <= ip__payload_len <= len(frame)` | RFC 768 "Format" (header floor); IP-bounded |
| Integrity | `8 <= plen == ip__payload_len <= len(frame)` | RFC 768 "Fields — Length" (≥ 8; wire matches IP-declared payload) |
| Integrity | `raw_cksum == 0 and ip6 and not accept_zero_cksum_ip6` → `UdpZeroCksumIp6Error` | RFC 8200 §8.1 / RFC 6935 §5 / RFC 6936 §4 |
| Integrity | `inet_cksum(frame, init=pshdr_sum) == 0` | RFC 768 "Fields — Checksum" (one's-complement over pseudo-header + UDP header + data); RFC 1071 algorithm |
| Sanity | `dport != 0` | RFC 768 + IANA (port 0 reserved); Linux parity |

The deliberate non-rejection of `sport == 0` is RFC 768
"Source Port" optional-field semantics (the wire value 0
is the documented "not used" sentinel; receivers MUST
deliver normally). The deliberate IPv4 `cksum == 0`
non-rejection is RFC 768 "If the computed checksum is
zero ... An all zero transmitted checksum value means
that the transmitter generated no checksum (for debugging
or for higher level protocols that don't care)" — that
sentinel is only forbidden on IPv6 per RFC 8200 §8.1.

PyTCP has **no `__post_init__` wire-AssertionError leak**
in UDP because the header has no derived fields and no
options.

---

## Beyond RFC 768 (clarifications inherited from other RFCs)

RFC 768 predates IPv6 by 16 years and does not address
several modern operational concerns. The relevant
clarifications come from:

- **RFC 1122 §4.1.3.4 ICMP messages**: a UDP receiver
  with no matching socket SHOULD emit ICMP Port
  Unreachable. PyTCP wires this at
  `packet_handler__udp__rx.py:260-303` with rate-limiting
  via `try_emit_icmp_error` and counters
  `udp__no_socket_match__respond_icmp4_unreachable` /
  `udp__no_socket_match__respond_icmp6_unreachable`.
- **RFC 8200 §8.1** (IPv6 UDP): the IPv6 receiver MUST
  discard UDP packets with cksum=0 (except for tunnel
  protocols per RFC 6935). PyTCP now satisfies this: the
  parser distinguishes the IP version on the cksum=0
  path, raises `UdpZeroCksumIp6Error` for IPv6, and the
  packet handler converts it to a silent drop with the
  `udp__ip6_zero_cksum__drop` counter bumped. The
  per-port `UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`
  socket-option opt-in remains a Phase-3 socket-parity
  item. Full discussion in
  [`docs/rfc/udp/rfc6935__udp_zero_cksum_ipv6/adherence.md`](../rfc6935__udp_zero_cksum_ipv6/adherence.md).

These are not RFC-768 conformance gaps in the strict
sense — RFC 768 itself is silent on IPv6 and on the
ICMP-Unreachable-on-no-socket behaviour — but they are
the natural follow-ups when a reader extends the audit.

---

## Test coverage audit

### Header wire format

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py`
  — pins the 8-byte fixed shape, per-field uint16
  bounds, and the `__post_init__` assertions on every
  field.

**Status:** locked in.

### Assembler operation

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py`
  — pins assembler `__bytes__`, `__len__`, `__str__`,
  `__repr__`, payload concatenation, and per-aspect
  reflection across the parametric matrix.

**Status:** locked in.

### Parser integrity checks

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py`
  — pins the `UDP__HEADER__LEN <= ip__payload_len <=
  len(frame)` constraint, the `plen == ip__payload_len`
  cross-check, and the checksum-zero RX bypass; also the
  boundary-accepted minimum-length frame.

**Status:** locked in.

### Parser sanity checks

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py::TestUdpParserSanityChecks`
  — pins the rejection of `dport == 0`.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py::TestUdpParserSourcePortOptional`
  — pins the RFC 768 source-port-optional acceptance of
  `sport == 0` frames.

**Status:** locked in.

### Parser operation

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__operation.py`
  — pins parser `header`, `payload`, `packet_rx.udp`
  installation, and frame-advance behaviour across the
  parametric matrix.

**Status:** locked in.

### Packet handler RX (no-socket → ICMP Unreachable)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py`
  — pins the RX dispatch including socket lookup and
  the ICMP-Unreachable emission when no socket matches
  (both IPv4 and IPv6 paths). Also pins the
  `udp__pre_parse` / `udp__socket_match` /
  `udp__no_socket_match__*` counters.

**Status:** locked in.

### Packet handler TX

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__tx.py`
  — pins outbound wire format across IPv4 and IPv6
  parametric cases with and without payload.

**Status:** locked in.

### BSD socket facade

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/socket/test__runtime__socket__udp__socket.py`
  — pins `bind` / `connect` / `send` / `sendto` / `recv`
  / `recvfrom` / `recvmsg` / `close` plus the
  `setsockopt`/`getsockopt` plumbing.
  `TestUdpSocketSendmsg` pins `sendmsg` scatter-gather
  concatenation, the `address=` (unconnected) path, and
  ancillary-data accept-and-ignore / malformed-cmsg
  rejection.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__socket_api.py::TestUdpSocketApiSendmsg`
  — pins a `sendmsg` round-trip through the real TX path
  (buffers concatenated land on the wire intact).

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Header wire format (8-byte, big-endian)             | locked in |
| Length minimum = 8 octets                           | locked in |
| Cross-check `plen == ip__payload_len`               | locked in |
| Checksum compute (TX) / verify (RX)                 | locked in |
| Checksum-zero RX skip                               | locked in |
| Checksum-zero TX → all-ones substitution            | locked in |
| Source Port optional / `sport == 0` accepted on RX  | locked in (`TestUdpParserSourcePortOptional`) |
| Destination port semantics (per-IP socket dispatch) | locked in |
| ICMP Unreachable on no matching socket              | locked in |
| BSD user interface (bind/recv/send/close)           | locked in |
| Pseudo-header construction (IPv4 + IPv6)            | locked in |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| Format / 8-byte fixed header                          | met    |
| Source Port optional (TX defaults to 0)               | met    |
| Source Port `== 0` accepted on RX                     | met (parser delivers sport=0 frames per RFC 768) |
| Destination Port per-IP semantics                     | met    |
| Length ≥ 8 octets                                     | met    |
| Length cross-check vs IP payload-length advisory      | met (stronger than RFC) |
| Checksum compute over pseudo + UDP + data             | met    |
| Checksum-zero RX = "no checksum, skip"                | met    |
| Checksum compute-zero TX → all-ones substitution      | met (both serialization paths apply the substitution) |
| Pseudo-header layout (src + dst + 0 + proto + UDP-len) | met   |
| User interface (BSD socket facade)                    | met    |
| IP interface (UDP reads src/dst/proto from IP)        | met    |
| Protocol Number = 17                                  | met    |

PyTCP **fully conforms** to RFC 768. Both deviations
previously flagged in this audit are now closed: the
parser accepts `sport == 0` per the source-port-optional
rule, and both UDP TX serialization paths substitute
`0xFFFF` for a computed `0x0000` per the all-ones rule.

---

## Cross-references

- IPv4 datagram framing: [`../../ip4/rfc791__ip4/adherence.md`](../../ip4/rfc791__ip4/adherence.md)
- IPv4 host requirements (incl. UDP §4.1): [`../../ip4/rfc1122__host_requirements_ip4/adherence.md`](../../ip4/rfc1122__host_requirements_ip4/adherence.md)
- IPv6 UDP checksum-mandatory rule: [`../../ip6/rfc8200__ipv6/adherence.md`](../../ip6/rfc8200__ipv6/adherence.md)
- ICMP Port Unreachable on no matching socket: [`../../icmp4/rfc792__icmp4/adherence.md`](../../icmp4/rfc792__icmp4/adherence.md) and [`../../icmp6/rfc4443__icmp6/adherence.md`](../../icmp6/rfc4443__icmp6/adherence.md)
- PyTCP UDP socket facade lives at `packages/pytcp/pytcp/runtime/socket/udp__socket.py`; broader socket-API parity audit at `docs/refactor/socket_linux_parity_audit.md`.
