# RFC 1122 §3.2.2 — Host Requirements (ICMP)

| Field       | Value                                                                    |
|-------------|--------------------------------------------------------------------------|
| RFC number  | 1122                                                                     |
| Title       | Requirements for Internet Hosts -- Communication Layers                  |
| Section     | §3.2.2 (Internet Control Message Protocol -- ICMP)                       |
| Category    | Internet Standard (STD 3)                                                |
| Date        | October 1989                                                             |
| Source text | [`rfc1122.txt`](../../tcp/rfc1122__host_requirements/rfc1122.txt) §3.2.2 |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 1122
§3.2.2 (the ICMP host requirements). The §3.2.2 sub-sections are
audited individually. The §4 TCP sub-sections of RFC 1122 are
audited under
[`docs/rfc/tcp/rfc1122__host_requirements/`](../../tcp/rfc1122__host_requirements/adherence.md).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.
Adherence levels use the canonical descriptive language: **met**,
**not met**, **partial**, **not implemented**, **vacuous**, or
**deliberate non-implementation** (for paragraphs whose subject was
deprecated by a later RFC and whose absence is intentional).

Sections without normative content (Introduction, headings,
Discussion / Implementation commentary) are skipped; the per-section
audit lists only the normative statements that apply to a host stack
PyTCP currently models.

---

## §3.2.2 — General ICMP rules

> "If an ICMP message of unknown type is received, it MUST be
> silently discarded."

**Adherence:** **met**. `Icmp4Parser._message_class()` resolves
unknown type bytes to `Icmp4MessageUnknown`
(`packages/net_proto/net_proto/protocols/icmp4/icmp4__parser.py`),
whose `validate_sanity` unconditionally raises `Icmp4SanityError`
(`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__unknown.py`).
The packet handler catches `PacketValidationError` and bumps
`icmp4__failed_parse__drop`; no reply is emitted. Per-message
`validate_sanity` also rejects unknown `code` values within the five
known types (Echo Req/Reply, Destination Unreachable, Time Exceeded,
Parameter Problem) — the IANA-assigned code sets are pinned in each
message's enum and `code.is_unknown` triggers `Icmp4SanityError`. The
older packet-handler `__phrx_icmp4__unknown` dispatch path is now
unreachable; the `icmp4__unknown` counter is retained on
`PacketStatsRx` as a no-op pending broader cleanup.

> "Every ICMP error message includes the Internet header and at
> least the first 8 data octets of the datagram that triggered the
> error; more than 8 octets MAY be sent; this header and data MUST
> be unchanged from the received datagram."

**Adherence:** **met**. The `Icmp4MessageDestinationUnreachable`
dataclass truncates `data` to
`IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__DESTINATION_UNREACHABLE__LEN`
= 548 bytes
(`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__destination_unreachable.py:163-168`),
which is the full original IP header + at least 8 octets of payload
up to the 576-byte MIN_MTU cap mandated by RFC 1812 §4.3.2.3. The
UDP closed-port emitter passes `packet_rx.ip.packet_bytes`
verbatim, so the bytes are unchanged
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:310`).

> "In those cases where the Internet layer is required to pass an
> ICMP error message to the transport layer, the IP protocol number
> MUST be extracted from the original header and used to select the
> appropriate transport protocol entity to handle the error."

**Adherence:** **met** for all three carrier message types
(Destination Unreachable, Time Exceeded, Parameter Problem) on
both v4 and v6. The shared embedded-L4 demux at
`packages/pytcp/pytcp/protocols/icmp/icmp__error_demux.py::parse_embedded_l4`
extracts the L4 protocol from the embedded IP header and routes
UDP to `UdpSocket.notify_*` and TCP via
`TcpSession.tcp_fsm(icmp=IcmpMetadata(...))`, which dispatches
through `FSM_ICMP_HANDLERS` to the per-state ICMP handlers in
`packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__<state>.py` (see RFC 5927 §6
hard-vs-soft semantics in
`docs/rfc/tcp/rfc5927__icmp_tcp_attacks/adherence.md`).

> "An ICMP error message SHOULD be sent with normal (i.e., zero)
> TOS bits."

**Adherence:** **vacuous**. PyTCP does not model TOS variation on
outbound ICMP errors; the IPv4 TX path emits TOS=0 by default
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__tx.py:126-131`,
delegating to `_phtx_ip4` without a non-zero `ip4__ecn` /
`ip4__dscp`).

> "An ICMP error message MUST NOT be sent as the result of
> receiving:
> - an ICMP error message, or
> - a datagram destined to an IP broadcast or IP multicast address, or
> - a datagram sent as a link-layer broadcast, or
> - a non-initial fragment, or
> - a datagram whose source address does not define a single host -- e.g., a zero address, a loopback address, a broadcast address, a multicast address, or a Class E address."

**Adherence:** **met** (post-α1.1). The five gates are encoded as
`IcmpErrorBlockReason` values and applied via `should_emit_icmp_error()`
+ `try_emit_icmp_error()` in
`packages/pytcp/pytcp/protocols/icmp/icmp__error_emitter.py`. The inbound classifier
at `packages/pytcp/pytcp/protocols/icmp/icmp__inbound_classifier.py::classify_inbound`
extracts the IP-layer state (limited-broadcast destination,
multicast destination, loopback/multicast/Class-E source, non-
initial fragment) into an `IcmpErrorContext`. The UDP closed-port
Port-Unreachable emitter routes through the gate at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:264`.
The "datagram sent as a link-layer broadcast" sub-rule is not
explicitly modeled — the closest proxy is `is_limited_broadcast` on
the IP destination, since the test harness and the production stack
both deliver L2-broadcast frames to the IP layer with the broadcast
IP destination preserved. The "ICMP error in response to ICMP
error" sub-rule is currently latent: today the only ICMP error
emitter is the UDP closed-port path, which never fires for an
inbound ICMP error (the inbound was UDP). The gate is wired and
will fire correctly when future error generators (§3.2.2.4 /
§3.2.2.5) are added.

---

## §3.2.2.1 — Destination Unreachable

> "The following additional codes are hereby defined: 6-12 ..."

**Adherence:** **met**. `Icmp4DestinationUnreachableCode` enum
covers all 16 codes (0-15)
(`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__destination_unreachable.py:79-99`),
including the seven RFC 1122 additions (NETWORK_UNKNOWN,
HOST_UNKNOWN, SOURCE_HOST_ISOLATED, NETWORK_PROHIBITED,
HOST_PROHIBITED, NETWORK_TOS, HOST_TOS) plus the RFC 1812
extensions (COMMUNICATION_PROHIBITED, HOST_PRECEDENCE,
PRECEDENCE_CUTOFF).

> "A host SHOULD generate Destination Unreachable messages with
> code: 2 (Protocol Unreachable), when the designated transport
> protocol is not supported"

**Adherence:** **met**. The IPv4 RX path drops packets of unknown
protocol with `ip4__no_proto_support__drop` and then emits an
ICMPv4 Destination Unreachable code 2 via
`__phrx_ip4__emit_protocol_unreachable`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py`), routed
through `try_emit_icmp_error()` so the §3.2.2 host-requirements
gates and RFC 1812 §4.3.2.8 rate limit apply uniformly with the
other ICMP error generators.

The IPv6 mirror is RFC 4443 §3.4 Parameter Problem code 1
("Unrecognized Next Header type"), not Destination Unreachable —
the v6 wire format expresses the same semantic via Param Problem.
Wired symmetrically at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py::__phrx_ip6__emit_parameter_problem_unrecognized_next_header`
per RFC 8200 §4.

> "A host SHOULD generate Destination Unreachable messages with
> code: 3 (Port Unreachable), when the designated transport
> protocol (e.g., UDP) is unable to demultiplex the datagram"

**Adherence:** **met**. `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py:306-310`
emits `Icmp4DestinationUnreachableCode.PORT` when no UDP socket
matches, subject to the §3.2.2 gates above.

> "A Destination Unreachable message that is received MUST be
> reported to the transport layer."

**Adherence:** **met**.
`__phrx_icmp4__destination_unreachable` parses the embedded L4 and
routes to either `UdpSocket.notify_*` or
`TcpSession.tcp_fsm(icmp=IcmpMetadata(category=DEST_UNREACHABLE,
...))`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py`).

> "A transport protocol that has its own mechanism for notifying
> the sender that a port is unreachable (e.g., TCP, which sends RST
> segments) MUST nevertheless accept an ICMP Port Unreachable for
> the same purpose."

**Adherence:** **met**. ICMPv4 Type 3 Code 3 (Port Unreachable)
in SYN_SENT routes through `tcp_fsm(icmp=...)` →
`fsm__syn_sent__icmp` (RFC 5927 §5.2 hard-error path), which
surfaces `ConnError.REFUSED` to the socket layer
(`packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__syn_sent.py`); the
`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py`
suite pins this behaviour.

> "A Destination Unreachable message that is received with code
> 0 (Net), 1 (Host), or 5 (Bad Source Route) may result from a
> routing transient and MUST therefore be interpreted as only a
> hint, not proof, that the specified destination is unreachable."

**Adherence:** **met** (post FSM-dispatch refactor). The per-state
ICMP handlers explicitly distinguish hard codes (v4 Code 2/3, v6
Code 1/4) from soft codes (v4 Code 0=Net / 1=Host / 5=BadSrcRoute,
v6 Code 0/3) per RFC 5927 §5.2. In SYN_SENT, soft codes set
`HOST_UNREACHABLE` / `NET_UNREACHABLE` and release the blocked
CONNECT but do NOT abort the FSM. In synchronized states all
codes are downgraded to advisory (log only). The "MUST NOT be
used as proof of a dead gateway" sub-rule is moot because PyTCP
does not implement gateway-deadness tracking (see §3.3.1). See
`docs/rfc/tcp/rfc5927__icmp_tcp_attacks/adherence.md` §5.2 for
the full per-state taxonomy.

---

## §3.2.2.2 — Redirect

> "A host SHOULD NOT send an ICMP Redirect message; Redirects are
> to be sent only by gateways."

**Adherence:** **met** (deliberate). PyTCP does not generate ICMPv4
Redirect messages. There is no Redirect TX path.

> "A host receiving a Redirect message MUST update its routing
> information accordingly."

**Adherence:** **not implemented**. ICMPv4 type 5 (Redirect) is not
declared in `Icmp4Type`; inbound Redirects route to
`Icmp4MessageUnknown` and are silently dropped without updating
any routing state. PyTCP's routing model is single-gateway per
host, so the missing Redirect handler does not currently violate
correctness in the deployments PyTCP targets, but the SHOULD-
support rule is not met.

> "A Redirect message SHOULD be silently discarded if the new
> gateway address it specifies is not on the same connected
> (sub-) net through which the Redirect arrived [...] or if the
> source of the Redirect is not the current first-hop gateway"

**Adherence:** **vacuous** (not implemented). Inherits the §3.2.2.2
non-implementation above.

---

## §3.2.2.3 — Source Quench

> "A host MAY send a Source Quench message [...]"
> "If a Source Quench message is received, the IP layer MUST
> report it to the transport layer."

**Adherence:** **deliberate non-implementation**. RFC 6633
deprecated Source Quench in 2012. PyTCP does not generate Source
Quench, and inbound Source Quench (ICMPv4 type 4) routes to
`Icmp4MessageUnknown` and is silently dropped — consistent with
RFC 6633 §1 ("the only acceptable behaviour is to ignore [Source
Quench] messages"). The non-implementation is intentional, not a
gap.

---

## §3.2.2.4 — Time Exceeded

> "An incoming Time Exceeded message MUST be passed to the transport
> layer."

**Adherence:** **met** (post Phase β.2). ICMPv4 type 11 routes
through `Icmp4MessageTimeExceeded` parsing
(`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__time_exceeded.py`),
and the `__phrx_icmp4__time_exceeded` packet-handler arm
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py:346`)
runs `parse_embedded_l4` on the carried original-datagram bytes
and dispatches to either
`TcpSession.tcp_fsm(icmp=IcmpMetadata(category=TIME_EXCEEDED, ...))`
or `UdpSocket.notify_time_exceeded` based on the embedded L4
protocol. The TCP demux applies the RFC 5927 §4 sequence-in-window
guard before notifying the session.

Per RFC 5927 §6, Time Exceeded is a soft error: the per-state
ICMP handlers (in
`packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__<state>.py`) log the
diagnostic and return without mutating FSM state or ConnError.
The existing retransmission machinery handles the actual loss
reported by the message; the notification's value is purely
observability + future MSG_ERRQUEUE delivery.

---

## §3.2.2.5 — Parameter Problem

> "A host SHOULD generate Parameter Problem messages."

**Adherence:** **shipped** (SHOULD #2). The IPv4 parser carries
the offending field's byte offset on `Ip4SanityError.pointer`;
`PacketHandlerIp4Rx._phrx_ip4` catches `Ip4SanityError` separately
from other validation errors and (when `pointer` is set) calls
`__phrx_ip4__emit_parameter_problem`, which routes through
`try_emit_icmp_error` (host-requirements gates + RFC 1812 §4.3.2.8
rate limiter) and emits ICMPv4 Type 12 Code 0 (pointer indicates
error) with the canonical pointer value. Pointers per
`packages/net_proto/net_proto/protocols/ip4/ip4__header.py`:

| Sanity branch                          | Pointer |
| -------------------------------------- | :-----: |
| TTL == 0                               |    8    |
| src is multicast / reserved / limited-broadcast | 12      |
| DF + MF set simultaneously             |    6    |
| DF + non-zero fragment offset          |    6    |

DHCP-client mode (no configured unicast IPv4) suppresses emit.
Counters: `ip4__sanity_error__respond_icmp4_param_problem` and
`ip4__sanity_error__icmp4_param_problem_suppressed`.

> "An incoming Parameter Problem message MUST be passed to the
> transport layer, and it MAY be reported to the user."

**Adherence:** **met** (post Phase β.3). ICMPv4 type 12 routes
through `Icmp4MessageParameterProblem` parsing
(`packages/net_proto/net_proto/protocols/icmp4/message/icmp4__message__parameter_problem.py`),
and the `__phrx_icmp4__parameter_problem` packet-handler arm runs
`parse_embedded_l4` on the carried original-datagram bytes and
dispatches to either
`TcpSession.tcp_fsm(icmp=IcmpMetadata(category=PARAM_PROBLEM, ...))`
or `UdpSocket.notify_parameter_problem` based on the embedded L4
protocol. The TCP demux applies the RFC 5927 §4 sequence-in-window
guard before notifying the session.

Per RFC 5927 §6, Parameter Problem is a soft error: same shape as
Time Exceeded — diagnostic only, no FSM mutation. The
"MAY be reported to the user" sub-clause is a future MSG_ERRQUEUE /
IP_RECVERR feature; current behaviour is observability via
packet_stats counter and log line.

---

## §3.2.2.6 — Echo Request/Reply

> "Every host MUST implement an ICMP Echo server function that
> receives Echo Requests and sends corresponding Echo Replies."

**Adherence:** **met**.
`__phrx_icmp4__echo_request`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py:621`)
emits an `Icmp4MessageEchoReply` for every accepted Echo Request.

> "An ICMP Echo Request destined to an IP broadcast or IP multicast
> address MAY be silently discarded."

**Adherence:** **met** (we exercise the MAY as a drop *by default*).
The Smurf-mitigation gate in `__phrx_icmp4__echo_request` calls
`packages/pytcp/pytcp/protocols/icmp4/icmp4__echo_gate.py::should_emit_echo_reply`
with the destination's broadcast/multicast flags. The drop is the
default and matches the MUST form of this rule (RFC 1812 §4.3.3.6),
applied even though PyTCP is a host because the same Smurf-amplification
vector applies. It is operator-tunable via the Linux-style
`icmp4.echo_ignore_broadcasts` sysctl (default `1` = drop, matching
`net.ipv4.icmp_echo_ignore_broadcasts`); setting it to `0` answers
broadcast/multicast Echo Requests.

> "The IP source address in an ICMP Echo Reply MUST be the same as
> the specific-destination address of the corresponding ICMP Echo
> Request message."

**Adherence:** **met**. For a unicast Echo Request the reply source is
the request destination — the specific-destination address. For a
broadcast/multicast Echo Request answered with
`icmp4.echo_ignore_broadcasts=0`, `__phrx_icmp4__echo_request` sources
the reply from the interface's unicast address instead (a group /
broadcast address cannot source a datagram); per RFC 1122 the
specific-destination address of a datagram sent to a multicast /
broadcast address is the receiving interface's own (unicast) address,
so this remains conformant.

> "Data received in an ICMP Echo Request MUST be entirely included
> in the resulting Echo Reply."

**Adherence:** **met**. The Reply construction copies
`packet_rx.icmp4.message.data` verbatim
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp4__rx.py:657`).

> "However, if sending the Echo Reply requires intentional
> fragmentation that is not implemented, the datagram MUST be
> truncated to maximum transmissible size and sent."

**Adherence:** **vacuous**. PyTCP's IPv4 TX path supports outbound
fragmentation (post the RFC 791 §3.1 DF-honoring change in commit
`08c6776c`), so the truncation fallback is not required.

> "An Echo Reply MUST be returned with the same Data field as
> received in the Echo Request. [...] An ICMP Echo Reply SHOULD
> echo all options received in the Echo Request."

**Adherence:** **shipped** (SHOULD #4). Data is echoed verbatim;
IPv4 options are also echoed via
`packages/pytcp/pytcp/protocols/icmp4/icmp4__echo_options.py::echo_reply_options`,
which `__phrx_icmp4__echo_request` calls before threading the
result into `_phtx_icmp4(..., ip4__options=...)`. The helper:

- **Reverses LSRR / SSRR** (`Ip4OptionLsrr` / `Ip4OptionSsrr`,
  RFC 791 §3.1) — route slots in flipped order, pointer reset to
  4. This satisfies the §3.2.2.6 "MUST be reversed" rule for
  source-route options on Echo Reply.
- **Echoes everything else verbatim** (NOP / EOL / Record Route /
  Timestamp / Security / Unknown). Echo Reply is not a forwarded
  packet, so Record Route slots and Timestamp entries are
  preserved as-is.

The first-class option types `Ip4OptionLsrr` and `Ip4OptionSsrr`
land in commit `00a0ee7b` per CLAUDE.md option layout (full
unit-test matrix; integrity checks for under-min length /
misaligned route data / length > buffer). Other option types
(Record Route, Timestamp) continue to round-trip as
`Ip4OptionUnknown` — adequate for verbatim echo, but a follow-up
could elevate them as well for first-class accessor surface.

A separate IP-layer gate `stack.IP4__ACCEPT_SOURCE_ROUTE`
(default `False`) silently drops inbound IPv4 packets carrying
LSRR or SSRR options at `_phrx_ip4` — the LSRR/SSRR echo
machinery only runs when an operator explicitly opts in. This
matches Linux's `net.ipv4.conf.*.accept_source_route=0`
default and closes the attack surface the echo support would
otherwise widen. Counter:
`ip4__source_route__drop`.

---

## §3.2.2.7 — Information Request/Reply

> Information Request/Reply (RFC 792) is obsolete per RFC 1122
> §3.2.2.7 ("A host SHOULD NOT implement these messages.").

**Adherence:** **deliberate non-implementation**. PyTCP does not
implement Information Request/Reply (ICMPv4 types 15/16). Inbound
messages route to `Icmp4MessageUnknown` and are silently dropped.
Both types were also formally deprecated en block by RFC 6918
§2.2/§2.3 — see
[`../rfc6918__deprecate_icmp_types/adherence.md`](../rfc6918__deprecate_icmp_types/adherence.md).

---

## §3.2.2.8 — Timestamp and Timestamp Reply

> "A host MAY implement Timestamp and Timestamp Reply."

**Adherence:** **deliberate non-implementation**. RFC 1122 §3.2.2.8
makes Timestamp / Timestamp Reply a MAY (not a MUST), and PyTCP
chooses not to implement types 13/14. Inbound messages route to
`Icmp4MessageUnknown` and are silently dropped. Note: ICMPv4
Timestamp is NOT formally deprecated by either RFC 6633 (which
covers only Source Quench, Type 4) or RFC 6918 (which covers
Types 6, 15-18, 30-39). The non-implementation is purely a scope
choice — in particular, Linux historically had a sysctl
(`net.ipv4.icmp_echo_ignore_broadcasts` adjacent) controlling
this, and modern Linux defaults to dropping inbound Timestamps
silently as well.

---

## §3.2.2.9 — Address Mask Request/Reply

> "A host MUST support the first, and MAY implement all three of the
> following methods for determining the address mask(s) [...]"

**Adherence:** **deliberate non-implementation** for ICMP-based
mask discovery (types 17/18). RFC 6918 §2.4/§2.5 formally
deprecated Address Mask Request and Address Mask Reply,
superseding the optional clause in RFC 1122 §3.2.2.9. PyTCP
obtains its address configuration via DHCPv4 (the "first method"
in the RFC 1122 list — static / boot-server configuration) and
does not implement the ICMP-based mask discovery alternative.
See
[`../rfc6918__deprecate_icmp_types/adherence.md`](../rfc6918__deprecate_icmp_types/adherence.md)
for the deprecation audit.

---

## Test coverage audit

### §3.2.2 General gates (5 MUST NOT rules)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__gates.py::TestShouldEmitIcmpError__Block`
  — 5 parametrized cases, one per gate (`INBOUND_WAS_ICMP_ERROR`,
  `INBOUND_DST_IS_BROADCAST`, `INBOUND_DST_IS_MULTICAST`,
  `INBOUND_SRC_INVALID`, `INBOUND_NON_INITIAL_FRAGMENT`), pinning
  the verdict reason returned by `should_emit_icmp_error()`.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__try_emit.py::TestTryEmitIcmpError__GateBlock`
  — gate-block returns the gate reason, does not consume a
  rate-limiter token.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/icmp/test__icmp__inbound_classifier.py::TestClassifyInbound__Ip4SrcInvalid`,
  `TestClassifyInbound__Ip4DstClassification`,
  `TestClassifyInbound__Ip4Fragment`
  — pin the IP-layer to context-flag mapping.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__error_gates.py::TestIcmp4ErrorGates__Suppressed`
  — drives a forged UDP-to-closed-port frame with broadcast dst /
  loopback src and asserts no Port-Unreachable emerges.

**Status:** **locked in** (multiple dedicated tests).

### §3.2.2 Unknown-type silent discard

- **Locked in indirectly** by every parser-roundtrip test: any
  unrecognised type byte routes to `Icmp4MessageUnknown` and the
  `__phrx_icmp4__unknown` handler bumps the counter without
  emitting a reply.

**Status:** **locked in indirectly** (no dedicated dropped-type
test, but the surrounding parser dispatch is fully exercised).

### §3.2.2 Embedded-original-datagram unchanged

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py::TestPacketHandlerUdpRx_*` (golden-frame cases)
  — pin the byte-for-byte content of the emitted Port-Unreachable,
  including the embedded IP header + first 8 octets of the
  triggering UDP segment.

**Status:** **locked in**.

### §3.2.2.1 Destination Unreachable — Code 3 emission

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__udp__rx.py` (the
  v4 closed-port golden) — full byte-equality on the emitted ICMPv4
  Port-Unreachable.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__error_gates.py::TestIcmp4ErrorGates__CleanUnicast`
  — pins that clean unicast still emits Port-Unreachable post-α1.1.

**Status:** **locked in**.

### §3.2.2.1 Destination Unreachable — TCP MUST accept

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py`
  — drives an ICMPv4 Port Unreachable matching a SYN_SENT and pins
  `ConnError.REFUSED`.

**Status:** **locked in**.

### §3.2.2.1 Code 2 (Protocol Unreachable) generation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__protocol_unreachable.py::TestIcmp4ProtocolUnreachable__CleanUnicast`
  — drives an IPv4 datagram with proto=42 and pins that the stack
  emits a Destination Unreachable type 3 / code 2 response with
  the success counter bumped.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__protocol_unreachable.py::TestIcmp4ProtocolUnreachable__GateSuppressed`
  — drives the same probe to a broadcast destination and pins
  that the §3.2.2 host-requirements gate suppresses the emission.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__parameter_problem_unrecognized_next_header.py`
  — IPv6 mirror via Parameter Problem code 1.

**Status:** **locked in**.

### §3.2.2.6 Echo server (unicast)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_request_smurf.py::TestIcmp4EchoSmurf__UnicastRegression`
  — drives a unicast Echo Request and pins that the Echo Reply
  reflects the request id / data.

**Status:** **locked in**.

### §3.2.2.6 Echo Smurf-mitigation drop

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/icmp4/test__icmp4__echo_gate.py::TestShouldEmitEchoReply__Block`
  — 3 cases pinning that broadcast / multicast / both destination
  flags suppress the reply at the gate level.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_request_smurf.py::TestIcmp4EchoSmurf__BroadcastSuppressed`
  — drives a forged limited-broadcast Echo Request and pins that no
  reply is emitted, the suppression counter bumps, and the success
  counter stays zero.

**Status:** **locked in**.

### §3.2.2.4 — Time Exceeded inbound (closed in β.2)

- **Unit (parser):**
  `packages/net_proto/net_proto/tests/unit/protocols/icmp4/test__icmp4__message__time_exceeded__parser.py`
  — pins that type-11 frames route to `Icmp4MessageTimeExceeded`
  rather than `Icmp4MessageUnknown`, with code 0/1 round-tripping
  cleanly.
- **Integration (TCP demux):**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__time_exceeded.py::TestTcpOnTimeExceeded`
  — pins that a Time Exceeded carrying an in-window embedded TCP
  SYN dispatches via `tcp_fsm(icmp=...)` to the per-state ICMP
  handler, bumps the `tcp__notify` counter, and does NOT mutate
  the FSM or ConnError. Out-of-window embedded seq drops at the
  seq-in-window guard.

**Status:** **locked in** (parser + TCP demux). UDP demux is
covered by direct exercise of the `__phrx_icmp4__time_exceeded__dispatch_udp`
arm; a dedicated UDP integration test is a future polish.

### §3.2.2.5 — Parameter Problem inbound (closed in β.3)

- **Unit (parser):**
  `packages/net_proto/net_proto/tests/unit/protocols/icmp4/test__icmp4__message__parameter_problem__parser.py`
  — pins that type-12 frames route to
  `Icmp4MessageParameterProblem`, with codes 0/1 and pointer field
  round-tripping cleanly.
- **Integration (TCP demux):**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__param_problem.py::TestTcpOnParameterProblem`
  — pins that a Parameter Problem carrying an in-window embedded
  TCP SYN dispatches via `tcp_fsm(icmp=...)` to the per-state
  ICMP handler, bumps the `tcp__notify` counter, and does NOT
  mutate FSM/ConnError. Out-of-window embedded seq drops at the
  seq-in-window guard.

**Status:** **locked in** (parser + TCP demux).

### §3.2.2.2 Redirect inbound — gap not yet closed

**No test surface.** PyTCP's single-gateway routing model makes
Redirect handling architecturally optional; deferring without a
test commitment until the routing layer adds multi-gateway
support.

### Test coverage summary

| Aspect                                    | Coverage  |
|-------------------------------------------|-----------|
| §3.2.2 general gates (5 MUST NOT rules)   | locked in |
| §3.2.2 unknown-type silent discard        | indirect  |
| §3.2.2 embedded-datagram unchanged        | locked in |
| §3.2.2.1 Code 3 Port Unreachable emission | locked in |
| §3.2.2.1 Code 2 Protocol Unreachable      | locked in |
| §3.2.2.1 TCP MUST accept Port Unreachable | locked in |
| §3.2.2.6 Echo server (unicast)            | locked in |
| §3.2.2.6 Echo Smurf-mitigation drop       | locked in |
| §3.2.2.4 Time Exceeded inbound            | locked in |
| §3.2.2.5 Parameter Problem inbound        | locked in |
| §3.2.2.2 Redirect inbound                 | n/a (gap) |

---

## Overall assessment

| Aspect                                              | Status                |
|-----------------------------------------------------|-----------------------|
| §3.2.2 unknown-type silent discard                  | met                   |
| §3.2.2 embedded-datagram unchanged                  | met                   |
| §3.2.2 ICMP-error generation gates (5 MUST NOTs)    | met                   |
| §3.2.2 TOS=0 on errors                              | vacuous               |
| §3.2.2.1 Codes 6-12 defined                         | met                   |
| §3.2.2.1 SHOULD generate Code 2 (Protocol Unreach.) | met                   |
| §3.2.2.1 SHOULD generate Code 3 (Port Unreach.)     | met                   |
| §3.2.2.1 MUST report to transport                   | met                   |
| §3.2.2.1 TCP MUST accept Port Unreachable           | met                   |
| §3.2.2.1 Code 0/1/5 hint-not-proof                  | met                   |
| §3.2.2.2 SHOULD NOT generate Redirect               | met (deliberate)      |
| §3.2.2.2 MUST process inbound Redirect              | not implemented       |
| §3.2.2.3 Source Quench                              | deliberate (RFC 6633) |
| §3.2.2.4 MUST pass Time Exceeded to transport       | met                   |
| §3.2.2.5 MUST pass Param Problem to transport       | met                   |
| §3.2.2.5 SHOULD generate Param Problem              | shipped               |
| §3.2.2.6 MUST implement Echo server                 | met                   |
| §3.2.2.6 MAY discard Echo to bcast/mcast            | met (Smurf drop)      |
| §3.2.2.6 src-address selection                      | met                   |
| §3.2.2.6 Data echoed verbatim                       | met                   |
| §3.2.2.6 IP options echoed                          | shipped               |
| §3.2.2.7 Information Req/Reply                      | deliberate (RFC 6918) |
| §3.2.2.8 Timestamp                                  | deliberate (MAY-skip) |
| §3.2.2.9 Address Mask                               | deliberate (RFC 6918) |

The single remaining Phase-1 gap is §3.2.2.2 inbound Redirect
handling, deferred indefinitely as an architectural blocker
(PyTCP's single-gateway routing model — see
`docs/refactor/icmp_remaining_issues.md`). Every other §3.2.2
clause is now either shipped, deliberate non-implementation
with documented rationale, or vacuous. The §3.2.2.4 / §3.2.2.5
inbound demux landed during the FSM-dispatch refactor; §3.2.2.5
outbound Param Problem generation landed in commits `dd68e3ac`
+ `ebbb41f8`; §3.2.2.6 IPv4 option echo (incl. LSRR/SSRR
reversal) landed in commits `00a0ee7b` + `388e035b` +
`19c169de`; §3.2.2.1 Code 0/1/5 hint-not-proof handling landed
with the per-state ICMP handlers' RFC 5927 §5.2 hard-vs-soft
taxonomy.
