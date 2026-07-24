# RFC 6935 / 6936 — IPv6 UDP Zero-Checksum for Tunneled Packets

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6935 (spec update) + 6936 (applicability)      |
| Title       | RFC 6935: IPv6 and UDP Checksums for Tunneled Packets; RFC 6936: Applicability Statement for the Use of IPv6 UDP Datagrams with Zero Checksums |
| Authors     | M. Eubanks, P. Chimento, M. Westerlund (6935); G. Fairhurst, M. Westerlund (6936) |
| Category    | Standards Track                                |
| Date        | April 2013                                     |
| Updates     | RFC 2460 (via 6935)                            |
| Source text | [`rfc6935.txt`](rfc6935.txt) / [`rfc6936.txt`](rfc6936.txt) |

RFC 6935 amends the RFC 2460 §8.1 "IPv6 receivers MUST
discard UDP packets containing a zero checksum"
requirement by allowing a per-port opt-in. RFC 6936 is
the companion applicability statement spelling out the
ten implementation constraints (§4) and ten usage
requirements (§5) that a stack supporting the opt-in
must satisfy.

This audit treats the pair as one unit. The two
documents are inseparable in practice — RFC 6935 §5
states "Any node implementing zero-checksum mode MUST
follow the node requirements specified in Section 4 of
[RFC6936]."

**Headline finding closed.** PyTCP conforms to the
default-disabled IPv6 RX rule (RFC 6936 §4, constraint
5) AND now supports the RFC 6935 §5 alternative-mode
per-port opt-in. The UDP parser at `udp__parser.py`
distinguishes IPv4 from IPv6 on the cksum=0 path: IPv4
continues to accept (RFC 768 "no checksum"); IPv6
raises a dedicated `UdpZeroCksumIp6Error` (subclass of
`UdpIntegrityError`) that the packet handler catches.
The handler then consults the per-port opt-in: if any
socket bound to the destination port has
`UDP_NO_CHECK6_RX` set (via `setsockopt(SOL_UDP,
UDP_NO_CHECK6_RX, 1)`), the parser retries with the
bypass enabled and delivers; otherwise the silent drop
fires with the `udp__ip6_zero_cksum__drop` counter
bumped. The symmetric `UDP_NO_CHECK6_TX` makes
`UdpAssembler` emit the literal `0x0000` on the wire
instead of the RFC 768 zero-to-all-ones substitution.

The setsockopt level uses Linux's numbering
(`SOL_UDP=17`, `UDP_NO_CHECK6_TX=101`,
`UDP_NO_CHECK6_RX=102`) so a program written for stdlib
`socket` runs unchanged against `pytcp.socket`.

---

## §1-§4 of RFC 6935 (Introduction, Discussion, Tunnel
## Limitation, Middleboxes)

These sections are background and rationale (corruption
analysis, tunnel-protocol constraints, middlebox
behaviour). No normative obligations on a host UDP
stack. Skipped.

---

## §5 of RFC 6935 — The Zero UDP Checksum Update

RFC 6935 §5 replaces the RFC 2460 §8.1 fourth bullet
with a longer one specifying a per-port mode model.

> "An IPv6 node associates a mode with each used UDP
>  port (for sending and/or receiving packets)."

**Adherence:** met — PyTCP supports both modes. The
**default mode** runs for every port unless opted out
(TX always computes; RX requires cksum on IPv6). The
**alternative mode** is exposed via the Linux-numbered
`UDP_NO_CHECK6_TX=101` and `UDP_NO_CHECK6_RX=102`
setsockopt options at level `SOL_UDP=17`. Applications
implementing a tunnel encapsulation opt the sending
socket into emitting cksum=0 on the wire via
`UDP_NO_CHECK6_TX`, and opt the receiving socket into
accepting inbound cksum=0 IPv6 datagrams via
`UDP_NO_CHECK6_RX`. Both flags default off so the
RFC 8200 §8.1 default conformance is the as-shipped
behaviour.

> "Whenever originating a UDP packet for a port in the
>  default mode, an IPv6 node MUST compute a UDP
>  checksum over the packet and the pseudo-header, and,
>  if that computation yields a result of zero, the
>  checksum MUST be changed to hex FFFF for placement in
>  the UDP header, as specified in [RFC2460]."

**Adherence (compute):** met — PyTCP always computes the
UDP cksum on TX.

**Adherence (zero-to-all-ones substitution):** met —
both UDP serialization paths apply the substitution per
RFC 768 / RFC 2460 / RFC 6935. See
[RFC 768 audit](../rfc768__udp/adherence.md) §"Fields —
Checksum" for the implementation details and the
locking unit tests at
`packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py::TestUdpAssemblerMisc`.

> "IPv6 receivers MUST by default discard UDP packets
>  containing a zero checksum and SHOULD log the error."

**Adherence:** met. The parser at
`packages/net_proto/net_proto/protocols/udp/udp__parser.py` distinguishes
the IP version on the cksum=0 path:

```python
raw_cksum = int.from_bytes(self._frame[6:8])
if raw_cksum == 0:
    if self._ip__ver is IpVersion.IP6:
        raise UdpZeroCksumIp6Error(
            "IPv6 UDP datagram with zero checksum on a port "
            "not configured for RFC 6935 zero-checksum mode.",
        )
    # RFC 768: IPv4 cksum=0 means "sender did not compute
    # a checksum"; accept and skip validation.
    return
```

`UdpZeroCksumIp6Error` is a dedicated subclass of
`UdpIntegrityError` so the existing
`PacketValidationError` catches continue to drop the
packet correctly. The UDP RX handler at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`
catches it specifically to bump the dedicated
`udp__ip6_zero_cksum__drop` counter — separating the
RFC-6935 discard path from generic UDP parse failures
for operational observability.

The default-discard is silent — no ICMPv6 Parameter
Problem is emitted, matching RFC 6936 §4 #8/9 which
treat zero-cksum logging as optional for the
default-mode discard.

> "As an alternative, certain protocols that use UDP as
>  a tunnel encapsulation MAY enable zero-checksum mode
>  for a specific port (or set of ports) for sending
>  and/or receiving."

**Adherence:** met — PyTCP exposes the Linux-numbered
`UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX` setsockopt
options at level `SOL_UDP`. The "MAY enable" half is
the application's choice; the stack provides the API.

> "Any node implementing zero-checksum mode MUST follow
>  the node requirements specified in Section 4 of
>  [RFC6936]."

See per-clause audit of RFC 6936 §4 below.

> "Any protocol that enables zero-checksum mode for a
>  specific port or ports MUST follow the usage
>  requirements specified in Section 5 of [RFC6936]."

**N/A** — PyTCP does not implement any protocol that
enables zero-cksum mode (no LISP, no MPLS-in-UDP, no
GUE, etc.). The §5 usage requirements apply to
**transported protocols** layered on top of UDP, which
is application-side responsibility.

> "Middleboxes supporting IPv6 MUST follow requirements
>  9, 10, and 11 of the usage requirements specified in
>  Section 5 of [RFC6936]."

**N/A** — PyTCP is not a middlebox.

---

## RFC 6936 §4 — Implementation Constraints

RFC 6936 §4 enumerates ten requirements on IPv6 nodes
that **support** zero-cksum mode. PyTCP supports it — the
per-port opt-in landed via `UDP_NO_CHECK6_TX` /
`UDP_NO_CHECK6_RX` at level `SOL_UDP` (see the Phase-2 fix
history below) — so this section is a per-constraint audit
of the shipped implementation. Constraints 3, 4, 5, 6 are
met; only constraint 8 (the SHOULD-log discipline on the
discard path) remains unimplemented.

| #   | Requirement                                                                                              | PyTCP status |
|-----|----------------------------------------------------------------------------------------------------------|--------------|
| 1   | Sending node MAY use a calculated checksum for all datagrams                                             | met (vacuous — PyTCP always computes) |
| 2   | IPv6 nodes SHOULD, by default, NOT allow zero-cksum TX                                                   | met (no opt-out exists) |
| 3   | MUST provide a way for app to enable zero-cksum TX on specific port set (socket API call or similar)     | met — `setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1)` flips the per-socket flag |
| 4   | MUST provide a way for app to indicate that a particular datagram is required to be sent with a cksum    | met (per-socket granularity — `UDP_NO_CHECK6_TX=0` is the per-socket "cksum required" override) |
| 5   | Default RX behavior MUST be to discard zero-cksum UDP                                                    | met — `UdpZeroCksumIp6Error` raised; `udp__ip6_zero_cksum__drop` counter bumped |
| 6   | MUST provide a way for app to enable zero-cksum RX on specific port set                                  | met — `setsockopt(SOL_UDP, UDP_NO_CHECK6_RX, 1)` flips the per-socket flag |
| 7   | MUST also allow reception using calculated checksum on zero-cksum-enabled ports                          | met (the opt-in only relaxes the cksum=0 drop; non-zero cksum continues to be validated normally) |
| 8   | RFC 2460 SHOULD log received zero-cksum datagrams; zero-cksum-enabled port MUST NOT log solely on that   | not implemented (PyTCP has no log facility for cksum=0 RX in either direction) |
| 9   | MAY separately identify discarded zero-cksum datagrams                                                   | met — `udp__ip6_zero_cksum__drop` counter is the dedicated identification |
| 10  | ICMPv6 referring to zero-cksum packets MUST be consistency-checked before acting on                       | met (general ICMP demux validates embedded datagram per the [RFC 5927 audit](../../tcp/rfc5927__icmp_tcp_attacks/adherence.md)) |

**Constraints 3, 4, 5, 6 are closed.** Constraint 8 remains
"feature not implemented" — PyTCP has no SHOULD-log
facility on the discard path. All other normative MUSTs
are met.

---

## RFC 6936 §5 — Usage Requirements

These are constraints on **transported protocols** (the
tunnel encapsulations that ride on UDP and use the
zero-cksum mode). They do not apply to PyTCP as a UDP
stack — they apply to applications that would be the
"app" in `UDP_NO_CHECK6_*` setsockopt calls.

PyTCP does not implement any zero-cksum-using transported
protocol (no LISP, no MPLS-in-UDP, no Geneve, no GTP
tunneling). Section §5 is **N/A**.

---

## Phase-1 fix history

The Phase-1 fix that closed constraint 5 landed in a
single commit:

1. **IP version plumbed into the UDP parser.** The
   parser now reads `packet_rx.ip.ver` alongside
   `payload_len` and `pshdr_sum`.
2. **IPv6 cksum=0 raises `UdpZeroCksumIp6Error`.** The
   new exception is a subclass of `UdpIntegrityError`
   so existing `PacketValidationError` catches still
   work; the dedicated subclass lets the RX packet
   handler distinguish the RFC-6935 drop path from
   generic UDP parse failures.
3. **TX zero-to-all-ones substitution** — already
   landed earlier; see
   [RFC 768 audit](../rfc768__udp/adherence.md)
   §"Fields — Checksum".
4. **New RX stat counter** `udp__ip6_zero_cksum__drop`
   bumped by the packet handler when the new exception
   fires — gives operators a greppable observability
   signal separate from `udp__failed_parse__drop`.

## Phase-2 fix history

The RFC 6935 §5 alternative-mode per-port opt-in landed
in May 2026:

1. **`UdpOption(IntEnum)`** + bare aliases for stdlib
   parity in `packages/pytcp/pytcp/socket/__init__.py`: `SOL_UDP=17`,
   `UDP_NO_CHECK6_TX=101`, `UDP_NO_CHECK6_RX=102`.
2. **`UdpSocket._udp_no_check6_tx` / `_udp_no_check6_rx`**
   flags + `_sol_udp_setsockopt` / `_sol_udp_getsockopt`
   dispatchers.
3. **`UdpAssembler(udp__no_cksum=False)`** kwarg makes
   `assemble()` and `Udp.__buffer__` emit the literal
   `0x0000` on the wire (bypassing the RFC 768 zero-to-
   all-ones substitution).
4. **`_phtx_udp(udp__no_cksum=...)`** and
   `send_udp_packet(udp__no_cksum=...)` thread the flag
   from `UdpSocket.send` / `sendto` through to the
   assembler.
5. **`UdpParser(accept_zero_cksum_ip6=False)`** kwarg
   bypasses the `UdpZeroCksumIp6Error` raise when the
   RX handler retries after finding a matching socket
   with `UDP_NO_CHECK6_RX` set.
6. **`PacketHandlerUdpRx.__phrx_udp__retry_zero_cksum_ip6`**
   peeks the raw destination port from the UDP header
   (bytes 2-3, parser raised pre-`_parse`), enumerates
   matching socket IDs, and retries the parse with the
   bypass when an opted-in socket is found.

---

## Test coverage audit

### RFC 6935 §5 / RFC 6936 §4 constraint 5 — default-discard

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py::TestUdpParserIntegrityZeroCksumIp6::test__udp__parser__integrity__ipv6_zero_cksum_rejected`
  — constructs a UDP frame with cksum=0, stubs the IP
  layer with `ver=IpVersion.IP6`, asserts
  `UdpZeroCksumIp6Error` is raised and that it
  subclasses `UdpIntegrityError`.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py::TestUdpParserIntegrityBoundary::test__udp__parser__integrity__zero_cksum_skips_validation_ipv4`
  — companion positive-control test that the IPv4
  cksum=0 acceptance still works (RFC 768 compatibility).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py::TestPacketHandlerUdpRxIp6ZeroCksumDrop`
  — drives an Ethernet/IPv6/UDP frame with cksum=0
  through the full RX path; asserts: no TX frame
  emitted, `udp__ip6_zero_cksum__drop` counter bumps
  exactly once, `udp__failed_parse__drop` stays at
  zero (the dedicated counter takes precedence), and
  the packet does not reach the socket-dispatch layer.

**Status:** locked in.

### RFC 6935 §5 — alternative-mode per-port opt-in

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__no_check6.py`
  covers six pins: setsockopt/getsockopt round-trip for
  both TX and RX optnames; opt-in TX emits literal
  `0x0000` cksum on the wire; default TX emits a
  computed non-zero cksum (RFC 8200 §8.1); opt-in RX
  delivers an inbound cksum=0 IPv6 datagram to the
  socket; default RX drops the same frame and bumps
  `udp__ip6_zero_cksum__drop`.

**Status:** locked in.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| Default IPv6 cksum=0 RX → discard                     | locked in |
| IPv4 cksum=0 RX → accept (RFC 768 compatibility)      | locked in |
| Default IPv6 cksum=0 TX → never emitted (compute on)  | locked in |
| Zero-compute → all-ones substitution                  | locked in (see RFC 768 audit) |
| Per-port zero-cksum opt-in (`UDP_NO_CHECK6_*`)        | locked in (six end-to-end pins in `test__udp__no_check6.py`) |
| RFC 6936 §4 constraints 3/4/6 (opt-in mechanism)      | locked in (same file) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| RFC 6935 §5: per-port mode association                | met (default + alternative both wired) |
| RFC 6935 §5: default-mode TX MUST compute cksum       | met |
| RFC 6935 §5: zero-compute → 0xFFFF substitution       | met (inherits the RFC 768 fix) |
| RFC 6935 §5: IPv6 RX default MUST discard zero-cksum  | met (`UdpZeroCksumIp6Error` + dedicated counter) |
| RFC 6935 §5: per-port alternative-mode opt-in         | met (`UDP_NO_CHECK6_TX` / `UDP_NO_CHECK6_RX` at level `SOL_UDP`) |
| RFC 6936 §4 #1: MAY always compute (off-load wording) | met (vacuous) |
| RFC 6936 §4 #2: default SHOULD NOT allow zero-cksum TX | met |
| RFC 6936 §4 #3: app-enable zero-cksum TX              | met (`UDP_NO_CHECK6_TX`) |
| RFC 6936 §4 #4: app-override per-datagram cksum-on    | met (per-socket granularity) |
| RFC 6936 §4 #5: default RX MUST discard zero-cksum    | met |
| RFC 6936 §4 #6: app-enable zero-cksum RX              | met (`UDP_NO_CHECK6_RX`) |
| RFC 6936 §4 #7: zero-cksum-enabled port MUST also accept calculated | met |
| RFC 6936 §4 #8: logging discipline                    | not implemented (PyTCP has no SHOULD-log on the discard path) |
| RFC 6936 §4 #9: dedicated counter for discarded zero-cksum | met (`udp__ip6_zero_cksum__drop`) |
| RFC 6936 §4 #10: ICMPv6 consistency check             | met (general ICMP demux validates embedded datagram) |
| RFC 6936 §5: transported-protocol usage constraints   | N/A (no consumer) |

PyTCP **meets every constraint that applies to an IPv6
UDP stack, in both default and alternative modes**. The
per-port opt-in machinery for tunnel encapsulations
(constraints 3, 4, 6) is shipped via `UDP_NO_CHECK6_TX` /
`UDP_NO_CHECK6_RX`. The only remaining "not implemented"
row is constraint 8 (the SHOULD-log discipline on the
zero-cksum discard path).

**Why this was greppable:** the IPv6 zero-cksum default
gap was referenced from four audits — RFC 768, RFC 1122
§4.1, RFC 8085, and this one. Closing it flipped all
four to "met."

---

## Cross-references

- Base UDP spec: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md) — §"Fields — Checksum" flags the same TX zero-to-all-ones gap
- UDP host requirements: [`../rfc1122__host_requirements_udp/adherence.md`](../rfc1122__host_requirements_udp/adherence.md) — §4.1.3.4 cross-references RFC 6935
- UDP usage guidelines: [`../rfc8085__udp_usage_guidelines/adherence.md`](../rfc8085__udp_usage_guidelines/adherence.md) — §3.4.1 directly invokes RFC 6935/6936
- IPv6 base spec: [`../../ip6/rfc8200__ipv6/adherence.md`](../../ip6/rfc8200__ipv6/adherence.md) — RFC 2460's §8.1 is the rule RFC 6935 amends
- ICMP demux for embedded-datagram consistency: `packages/pytcp/pytcp/protocols/icmp/icmp__error_demux.py` + [RFC 5927 audit](../../tcp/rfc5927__icmp_tcp_attacks/adherence.md)
- Socket-API parity (`UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`): `docs/refactor/socket_linux_parity_audit.md`
