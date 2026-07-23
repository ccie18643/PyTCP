# RFC 8085 — UDP Usage Guidelines (BCP 145)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 8085                                           |
| Title       | UDP Usage Guidelines                           |
| Authors     | L. Eggert, G. Fairhurst, G. Shepherd           |
| Category    | Best Current Practice (BCP 145)                |
| Date        | March 2017                                     |
| Obsoletes   | RFC 5405                                       |
| Source text | [`rfc8085.txt`](rfc8085.txt)                   |

RFC 8085 is **guidance for UDP application designers**,
not a protocol specification. The bulk of its content
(congestion control, reliability, middlebox traversal,
message-size discipline at the app layer) is **not stack
behaviour**; it documents how applications-on-top-of-UDP
should be written. PyTCP is a stack and exposes UDP as a
substrate via the BSD socket facade — its conformance
posture is "provide the primitives apps need to follow
RFC 8085, do not undermine them."

This audit walks each numbered section and classifies it
as one of:

- **stack obligation (met / partial / not met)** — the
  clause names a behaviour the stack itself MUST or
  SHOULD perform.
- **application obligation** — the clause names a
  behaviour the application MUST or SHOULD perform; the
  stack's role is to expose the primitive.
- **N/A (informational / discussion)** — not normative.

Sections without normative content (§1 Introduction, §2
Terminology, §6 Security Considerations boilerplate, §7
Summary, §8 References) are omitted.

---

## Top-line summary

| §       | Topic                                       | PyTCP relevance        |
|---------|---------------------------------------------|------------------------|
| §3.1    | Congestion Control Guidelines               | application obligation (stack does not undermine; no CC primitives provided) |
| §3.2    | Message Size Guidelines / PMTU              | partial — stack ships PMTUD per RFCs 1191 / 8201; sets DF=1 on UDP TX; PLPMTUD per RFC 8899 is a deferred Phase-1 polish item |
| §3.3    | Reliability Guidelines                      | application obligation |
| §3.4    | Checksum Guidelines                         | met (TX always cksum; RX verifies non-zero cksum); IPv6 zero-cksum tunneling is covered by RFC 6935/6936 audit (shipped) |
| §3.4.1  | IPv6 Zero UDP Checksum                      | met — default-mode discard in force + per-port opt-in shipped (`UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`) |
| §3.4.2  | UDP-Lite                                    | N/A — UDP-Lite is a separate protocol (proto 136); PyTCP does not implement it |
| §3.5    | Middlebox Traversal Guidelines              | application obligation |
| §3.6    | Limited Applicability / Controlled Envs     | application obligation |
| §4.1    | Multicast Congestion Control                | application obligation |
| §4.2    | Message Size Guidelines for Multicast       | application obligation; PyTCP's multicast TX path is RFC 1112 / RFC 4861 SNMA |
| §5.1    | Using UDP Ports                             | partial — sender SHOULD NOT use sport=0 (raw `_phtx_udp` default violates; parser accepts sport=0 per RFC 768) ; randomized source port now RFC 6056-conformant via `secrets.choice` |
| §5.1.1  | Source-port entropy + IPv6 flow label       | met (RFC 6437 flow-label auto-wire shipped) |
| §5.1.2  | Multiple UDP ports per application          | application obligation |
| §5.2    | ICMP Guidelines                             | met (notify_* socket callbacks deliver ICMP errors; `IP_RECVERR` / `MSG_ERRQUEUE` error-queue API shipped) |

---

## §3.1 Congestion Control Guidelines

> "UDP datagrams may be lost or arrive at high rates ...
>  developers SHOULD implement congestion control ..."

**Classification:** application obligation. The clause is
prefaced with "Application designers SHOULD" and the rest
of §3.1 (rate limiting, application-level back-off, ECN
opt-in, low data-volume guidance) is entirely about how
apps using UDP should behave.

**Stack posture:** PyTCP provides no UDP-layer congestion
control primitives (DCCP-like CC for UDP is not in scope).
ECN at the IP layer is partially wired — see
[RFC 3168 audit](../../ip4/rfc3168__ecn/adherence.md) for
the IPv4 side — but applications would have to opt in via
the (currently unwired) ECN socket options.

---

## §3.2 Message Size Guidelines

> "An application SHOULD NOT send UDP datagrams that
>  result in IP packets that exceed the Maximum
>  Transmission Unit (MTU) along the path."

**Classification:** mixed — the clause is an app SHOULD,
but the stack's job is to expose PMTU.

**Stack posture:**

- **PMTU exposure (RX side):** PyTCP processes inbound
  ICMP "Packet Too Big" (IPv6) / "Fragmentation Needed"
  (IPv4) per RFCs 1191 / 8201 and updates
  `stack.pmtu_cache`. The information is available to the
  TX path. See
  [RFC 8201 audit](../../ip6/rfc8201__pmtud_ip6/adherence.md).
- **DF=1 on outbound UDP IPv4:** the UDP TX path sets
  `ip4__flag_df=True` at
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__tx.py:124-132`,
  which forces ICMP-Frag-Needed feedback rather than
  silent in-network fragmentation.
- **PLPMTUD (RFC 8899) for UDP:** not implemented; a
  Phase-1 polish item.
- **Per-socket PMTU query (`IP_MTU` / `IPV6_MTU`
  getsockopt):** exposed. `getsockopt(IPPROTO_IP, IP_MTU)`
  (and the IPv6 `IPV6_MTU`) returns the discovered path MTU
  from `stack.pmtu_cache`, falling back to the egress
  interface MTU when no PMTU has been learned — the
  RFC 1122 §3.4 `GET_MAXSIZES` surface. See
  `packages/pytcp/pytcp/runtime/socket/__init__.py:1144`
  (IP_MTU) / `:1403` (IPV6_MTU).

**Verdict:** partial — PyTCP exposes PMTU both to itself
and back to the application via `getsockopt(IP_MTU)` /
`IPV6_MTU`. The residual gap is PLPMTUD (RFC 8899), a
deferred Phase-1 polish item.

---

## §3.3 Reliability Guidelines

> "UDP does not retransmit any lost packets ...
>  applications SHOULD implement their own reliability
>  mechanisms when needed."

**Classification:** application obligation. PyTCP correctly
does not add reliability to UDP at the stack layer (that
would make it not-UDP).

---

## §3.4 Checksum Guidelines

> "Applications SHOULD enable UDP checksums [RFC1122].
>  For IPv4, [RFC768] permits an option to disable their
>  use, by setting a zero checksum value."

**Adherence:** met. PyTCP's assembler at
`packages/net_proto/net_proto/protocols/udp/udp__assembler.py:79-83`
unconditionally computes the checksum. There is no socket
option to disable UDP cksum on TX. The "applications
SHOULD enable" is therefore satisfied by construction —
applications cannot opt out.

> "When UDP is used over IPv6, the UDP checksum ... MUST
>  be used as specified in [RFC2460]."

**Adherence:** met on TX. PyTCP always computes the UDP
checksum on outbound IPv6 datagrams; there is no
zero-cksum-mode escape hatch (which the next subsection
RFC 8085 §3.4.1 would allow for tunnel protocols).

On RX side: PyTCP's parser at
`packages/net_proto/net_proto/protocols/udp/udp__parser.py` distinguishes
IPv4 (RFC 768 cksum=0 means "no cksum"; accept) from
IPv6 (RFC 8200 §8.1 / RFC 6935 §5 default-discard;
raise `UdpZeroCksumIp6Error` + bump
`udp__ip6_zero_cksum__drop` counter).

Cross-reference: full discussion in the
[RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md).

### §3.4.1 IPv6 Zero UDP Checksum

> "Use of the UDP checksum with IPv6 MUST be the default
>  configuration for all implementations [RFC6935]. The
>  receiving endpoint MUST only allow the use of UDP
>  zero-checksum mode for IPv6 on a UDP destination port
>  that is specifically enabled."

**Adherence:** met. The MUST default-enabled side is
met on both TX (always cksums unless opted out) and RX
(IPv6 cksum=0 is rejected via `UdpZeroCksumIp6Error`
with the dedicated `udp__ip6_zero_cksum__drop` counter
for observability). The "receiving endpoint MUST only
allow zero-checksum on a specifically-enabled port"
half is met by the per-port opt-in: only a socket that
set `UDP_NO_CHECK6_RX` (via `setsockopt(SOL_UDP,
UDP_NO_CHECK6_RX, 1)`) accepts inbound cksum=0 IPv6
datagrams on its bound port; every other port keeps the
default discard.

Cross-reference: full discussion in the
[RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md).

### §3.4.2 UDP-Lite

**Classification:** N/A. UDP-Lite (RFC 3828) is a
separate transport protocol with its own IP protocol
number (136) and its own wire format ("checksum coverage
length" replaces UDP's "length" field). PyTCP does not
implement UDP-Lite; it has effectively zero deployment
on the internet and is not on the project's roadmap
(see commit log discussion). This subsection of RFC 8085
does not impose any obligation on a UDP-only stack.

---

## §3.5 Middlebox Traversal Guidelines

**Classification:** application obligation. NAT pinhole
keep-alive, ICMP filtering workarounds, port-prediction
mitigations — all app concerns. PyTCP is a host stack
behind whatever middleboxes the operator deploys; the
middlebox behaviour is out of stack scope.

---

## §3.6 Limited Applicability and Controlled Environments

**Classification:** application obligation. Guidance for
apps that should "constrain traffic to an operator
network" (e.g. MPLS-in-UDP per RFC 7510). Not stack
behaviour.

---

## §4 Multicast UDP Usage Guidelines

> "Applications using UDP for multicast SHOULD ..."

**Classification:** application obligation. PyTCP's
multicast TX path (RFC 1112 IPv4 multicasting; RFC 4861
solicited-node MAC for IPv6; MLDv2 group membership
reporting per
[RFC 3810 audit](../../icmp6/rfc3810__mld2/adherence.md))
is the stack-side surface multicast UDP apps build on.
The guidelines in §4.1 (congestion control for
multicast), §4.2 (message size — keep below path MTU,
use the most-restrictive interface MTU when sending to
multicast) are all app concerns.

**Stack provides:** group-join (MLDv2 Report on
membership change; Report-on-Query per §5.1.10), TTL=1
for link-local multicast, source-address selection that
prefers the matching scope. All documented in the IPv4
multicast / IPv6 ND / MLDv2 audits.

---

## §5.1 Using UDP Ports

> "A UDP sender SHOULD NOT use a source port value of
>  zero."

**Adherence:** **not met (TX default)**.

The assembler at
`packages/net_proto/net_proto/protocols/udp/udp__assembler.py:50-71`
defaults `udp__sport=0`. The UDP TX path
(`packet_handler__udp__tx.py:101-106`) does NOT impose a
non-zero source port — it passes whatever the caller
hands it. So a caller that omits the source port (or
uses `_phtx_udp` directly with `udp__sport=0`) emits a
datagram with `sport=0`, violating §5.1's SHOULD NOT.

The **BSD socket facade saves this in practice**: when
an application uses `socket.sendto(...)` on an unbound
socket, the socket layer calls `pick_local_port()`
(`packages/pytcp/pytcp/socket/udp__socket.py:266`) to assign an
ephemeral port. So end-user UDP traffic goes out with
sport != 0. But the bare `_phtx_udp` API allows the
violation — internal stack callers must remember to set
`udp__sport` explicitly.

> "A UDP receiver SHOULD NOT bind to port zero."

**Adherence:** PyTCP's `bind()` at
`udp__socket.py:202+` accepts port 0 as the "pick
ephemeral on bind" sentinel (a BSD-API convention; Linux
does the same). It does not bind a socket as "listening
on port 0." The SHOULD NOT is honoured.

> "Applications SHOULD provide a check that protects from
>  off-path data injection ... TCP stacks commonly use a
>  randomized source port to provide this protection
>  [RFC6056]; UDP applications should follow the same
>  technique."

**Adherence:** met (Phase-1 fix). PyTCP's
`pick_local_port()` at `packages/pytcp/pytcp/socket/socket__bind_helpers.py:140-163`
draws from a Linux-parity ephemeral range
(`range(32768, 61000)` — 28,232 ports) via
`secrets.choice`, satisfying both RFC 6056 §3.1 (CSPRNG
entropy) and §3.2 (largest-possible-range SHOULD).

Cross-reference: the dedicated
[RFC 6056 audit](../rfc6056__port_randomization/adherence.md)
catalogues the implementation. Algorithm 3 hash-based
per-destination selection — the TCP-specific §3.5
recommendation — is tracked in the
[TCP-side RFC 6056 audit](../../tcp/rfc6056__port_randomization/adherence.md)
as a separate Phase-2 hardening item.

### §5.1.1 Source Port Entropy and the IPv6 Flow Label

> "UDP applications SHOULD set the flow label field, even
>  when an entropy value is also set in the source port
>  field."

**Adherence:** met. The IPv6 TX path auto-computes the
Flow Label per RFC 6437 §3 from `(src, dst)` via the
`compute_ip6_flow_label` helper, gated by the
`ip6.flow_label_generation` sysctl (default 1). See
[RFC 6437 audit](../../ip6/rfc6437__flow_label/adherence.md).

The current generator is per-`(src, dst)` rather than
per-5-tuple, which is RFC 6437-conformant (the RFC
permits coarser flow definitions) but does **not** vary
the flow label by `(sport, dport, proto)` — so it
doesn't add to ECMP entropy beyond what the source
address already provides. A per-5-tuple refinement is a
follow-up.

### §5.1.2 Applications Using Multiple UDP Ports

**Classification:** application obligation. Multi-port
NAT timeouts, ECMP path divergence, congestion-control
state aggregation — all app concerns.

---

## §5.2 ICMP Guidelines

> "Applications can utilize information about ICMP error
>  messages that the UDP layer passes up ... Applications
>  SHOULD appropriately validate the payload of ICMP
>  messages ..."

**Stack obligation (UDP layer passes ICMP errors up):**
met. The classifier at
`packages/pytcp/pytcp/protocols/icmp/icmp__inbound_classifier.py` plus
the per-socket `notify_*` callbacks
(`packages/pytcp/pytcp/socket/udp__socket.py:519-553`) deliver ICMP
errors to the matching UDP socket via the embedded-
datagram 4-tuple. This is documented in the
[RFC 1122 §4.1 audit](../rfc1122__host_requirements_udp/adherence.md)
§4.1.3.3.

The application-side concerns (validate the embedded
payload corresponds to a real transmission; tolerate
transient ICMP soft errors) are application obligations
— PyTCP exposes the error type/code/embedded-datagram
fields and lets the app decide.

The Linux `IP_RECVERR` / `IPV6_RECVERR` / `MSG_ERRQUEUE`
API parity — the error queue surfaced via
`recvmsg(MSG_ERRQUEUE)` with an `IP_RECVERR` / `IPV6_RECVERR`
cmsg — is shipped:
`packages/pytcp/pytcp/runtime/socket/udp__socket.py::recvmsg`
(`:797`, `MSG_ERRQUEUE` branch at `:828`) dequeues an error-
queue entry and builds the cmsg (`:919-930`).

---

## Test coverage audit

Most of RFC 8085's normative content is **application
obligation**, not stack behaviour. The stack-relevant
clauses are covered by tests in their respective
audits — this section enumerates the cross-references.

| §       | Stack-relevant clause                       | Audit / tests                                                                 |
|---------|---------------------------------------------|-------------------------------------------------------------------------------|
| §3.2    | DF=1 on outbound UDP IPv4                    | [RFC 1191 audit](../../ip4/rfc1191__pmtud_ip4/adherence.md); UDP TX integration test covers the IPv4 path |
| §3.4    | UDP checksum on by default (TX + RX)         | [RFC 768 audit](../rfc768__udp/adherence.md); `test__udp__assembler__operation.py` + `test__udp__parser__integrity_checks.py` |
| §3.4.1  | IPv6 zero-cksum default = checksumming on    | [RFC 768 audit](../rfc768__udp/adherence.md) + [RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md) (task #570) |
| §5.1    | Sender SHOULD NOT use sport=0                | partial — BSD socket layer picks ephemeral; raw `_phtx_udp` permits sport=0. See [RFC 6056 audit](../rfc6056__port_randomization/adherence.md) |
| §5.1    | Randomized source port                       | met — `secrets.choice` + Linux-parity range; see [RFC 6056 audit](../rfc6056__port_randomization/adherence.md) |
| §5.1.1  | IPv6 Flow Label set                          | [RFC 6437 audit](../../ip6/rfc6437__flow_label/adherence.md); `test__ip6__rfc6437_flow_label.py` |
| §5.2    | UDP layer passes ICMP errors up              | [RFC 1122 §4.1 audit](../rfc1122__host_requirements_udp/adherence.md) §4.1.3.3; `packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py` |

This audit's own test surface is **n/a** — RFC 8085 is
guidance, not protocol behaviour. No standalone tests
land in `test__udp__rfc8085_*.py`; the conformance is
expressed through the cross-referenced audits.

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3.1 Congestion control                               | application obligation (stack does not undermine) |
| §3.2 Message size / PMTUD                             | partial — PMTUD wired + per-socket PMTU exposure (`IP_MTU` / `IPV6_MTU`); PLPMTUD (RFC 8899) deferred |
| §3.3 Reliability                                      | application obligation |
| §3.4 Checksum default on (TX + RX)                    | met |
| §3.4 IPv6 cksum required (TX)                         | met |
| §3.4 IPv6 cksum=0 RX must discard by default          | met (see RFC 6935 audit) |
| §3.4.1 Default cksum-on for IPv6                      | met |
| §3.4.1 Per-port enable list for IPv6 zero-cksum       | met (`UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`) |
| §3.4.2 UDP-Lite                                       | N/A (separate protocol, not implemented) |
| §3.5 Middlebox traversal                              | application obligation |
| §3.6 Limited applicability                            | application obligation |
| §4 Multicast UDP usage                                | application obligation (stack ships MLDv2 / RFC 1112) |
| §5.1 Sender SHOULD NOT sport=0                        | partial — BSD socket layer picks ephemeral; raw `_phtx_udp` permits sport=0 |
| §5.1 Receiver SHOULD NOT bind port 0                  | met (bind(0) means "pick ephemeral", not "listen on port 0") |
| §5.1 Random source port (RFC 6056)                    | met (`secrets.choice` + Linux-parity range — see dedicated RFC 6056 audit) |
| §5.1.1 IPv6 flow label set                            | met (RFC 6437 auto-wire shipped) |
| §5.2 UDP passes ICMP errors up                        | met (stack layer + `IP_RECVERR` / `MSG_ERRQUEUE` error-queue API shipped) |

PyTCP **broadly satisfies its stack-side obligations**
under RFC 8085. The two previously-flagged stack-side
gaps are now closed:

1. **Per-port IPv6 zero-cksum opt-in** — shipped via
   `UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`; see
   [RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md).
2. **`IP_MTU` / `IPV6_MTU` getsockopt** to expose the
   discovered PMTU to the application — shipped.

The residual stack-side item is PLPMTUD (RFC 8899) for
UDP, a deferred Phase-1 polish item (classical PMTUD per
RFCs 1191 / 8201 is wired). TCP Algorithm 3
(RFC 6056 §3.3.3) is a TCP-side concern covered by the
[TCP-side RFC 6056 audit](../../tcp/rfc6056__port_randomization/adherence.md);
it does not affect UDP conformance.

The previously-flagged ephemeral port allocator gap
(narrow range, step=2, non-cryptographic entropy) has
been closed — the picker now uses `secrets.choice` over
`range(32768, 61000)`.

The application-obligation clauses (~70% of the
document) do not impose any stack work; they are
documented here as "stack provides primitives, app
implements policy."

---

## Cross-references

- Base UDP: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md)
- UDP host requirements: [`../rfc1122__host_requirements_udp/adherence.md`](../rfc1122__host_requirements_udp/adherence.md)
- IPv6 zero-cksum tunneling: [`../rfc6935__udp_zero_cksum_ipv6/adherence.md`](../rfc6935__udp_zero_cksum_ipv6/adherence.md) (in flight)
- Port randomization: [`../rfc6056__port_randomization/adherence.md`](../rfc6056__port_randomization/adherence.md) (in flight)
- IPv4 PMTUD: [`../../ip4/rfc1191__pmtud_ip4/adherence.md`](../../ip4/rfc1191__pmtud_ip4/adherence.md)
- IPv6 PMTUD: [`../../ip6/rfc8201__pmtud_ip6/adherence.md`](../../ip6/rfc8201__pmtud_ip6/adherence.md)
- IPv6 Flow Label: [`../../ip6/rfc6437__flow_label/adherence.md`](../../ip6/rfc6437__flow_label/adherence.md)
- IPv4 multicast: [`../../ip4/rfc1112__ip4_multicasting/adherence.md`](../../ip4/rfc1112__ip4_multicasting/adherence.md)
- MLDv2: [`../../icmp6/rfc3810__mld2/adherence.md`](../../icmp6/rfc3810__mld2/adherence.md)
- Socket-API parity (IP_RECVERR, IP_MTU, IP_RECVTOS): `docs/refactor/socket_linux_parity_audit.md`
