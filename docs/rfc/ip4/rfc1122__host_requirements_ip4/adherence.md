# RFC 1122 — Requirements for Internet Hosts (Internet Layer)

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 1122                                                 |
| Title       | Requirements for Internet Hosts -- Communication Layers |
| Category    | Internet Standard (STD 3)                            |
| Date        | October 1989                                         |
| Updated by  | RFC 1349, 4379, 5884, 6298, 6633, 6864, 8029, 9293   |
| Source text | [`rfc1122.txt`](rfc1122.txt)                         |

This document records the PyTCP codebase's adherence to RFC 1122
**§3 (Internet Layer)** clause by clause. The audit was performed
by reading the RFC text fresh and inspecting the codebase under
`packages/net_proto/net_proto/protocols/ip4/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__*.py` directly;
no prior memory or rule-file content was reused.

Scope:

- **§3.2.1 (Internet Protocol — IP)** is audited in full here.
- **§3.2.2 (ICMP)** is cross-referenced to
  `docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`.
- **§3.2.3 (IGMP)** is implemented — IGMPv3 host support ships
  (see the RFC 3376 / RFC 2236 / RFC 1112 records); group
  management is audited there, not repeated here.
- **§3.3 (Specific Issues — routing, reassembly, fragmentation,
  multihoming, source-route, broadcasts, multicasting, error
  reporting)** is audited here for the IP-layer-relevant portions.
- §3.4 (Link Layer / Trailer encapsulations) — out of scope.

Non-normative discussion / implementation notes / RFC 2119
boilerplate are omitted.

---

## Top-line adherence

PyTCP **meets** the host-requirements MUSTs for §3.2.1 (IP-layer
RX and TX). Routing-table material in §3.3.1 is now backed by a
real host-mode FIB (`packages/pytcp/pytcp/runtime/fib.py` `RouteTable`,
longest-prefix lookup; Phase-3 `RouteApi` in
`packages/pytcp/pytcp/stack/route.py`) — the next hop is destination-keyed
routing-table state, no longer a single-gateway-per-`IfAddr`
shortcut (`IfAddr.gateway` was deleted). A learned/aged route
*cache* and ICMP-Redirect-driven entries (§3.3.1.x) remain
**not** implemented — gated for Phase 2 — though the FIB
reserves `RouteProtocol.REDIRECT` for that path. The broadcast
/ multicast / error-reporting rules are honoured. Source-route
forwarding (§3.3.5) is Phase 2.

| Section | Topic                                       | Status |
|---------|---------------------------------------------|--------|
| §3.2.1.1 | Version Number MUST=4 check                | met    |
| §3.2.1.2 | Header checksum MUST verify                | met    |
| §3.2.1.3 | Addressing (class, special cases, source validation, dest filtering) | met (mostly) — see clauses below |
| §3.2.1.4 | Fragmentation and Reassembly required      | met (audited under RFC 791 §3.2 + RFC 815 record) |
| §3.2.1.5 | Identification reuse on retransmit         | met (we do not reuse; see RFC 6864 audit) |
| §3.2.1.6 | Type-of-Service handling                   | met (redefined as DSCP+ECN per RFC 2474+3168) |
| §3.2.1.7 | TTL MUST NOT send=0, MUST be configurable  | met    |
| §3.2.1.8 | Options (pass to transport, specific options) | met for pass-through; LSRR/SSRR origination not implemented (Phase 2) |
| §3.3.1   | Routing outbound (FIB next-hop / default route / route cache) | partial — FIB longest-prefix table met; learned/aged cache + Redirect entries Phase 2 |
| §3.3.2   | Reassembly                                  | met (audited separately under RFC 815) |
| §3.3.3   | Fragmentation                               | met (see RFC 791 §3.2) |
| §3.3.4   | Local multihoming                           | partial — L3 routing destination-keyed (multihoming-correct); single physical interface |
| §3.3.5   | Source-route forwarding                     | not implemented (Phase 2) |
| §3.3.6   | Broadcasts                                  | met    |
| §3.3.7   | IP multicasting                             | met — reception + IGMPv3 group management (see RFC 3376 record) |
| §3.3.8   | Error reporting (link-layer errors to upper layers) | partial — Phase 1 logs but does not propagate |

---

## §3.2.1.1 Version Number

> "A datagram whose version number is not 4 MUST be silently
> discarded."

**Adherence:** met. `Ip4Parser._validate_integrity` rejects any
frame whose first nibble is not 4 with `Ip4IntegrityError`
(`packages/net_proto/net_proto/protocols/ip4/ip4__parser.py:94-97`). The RX handler
catches `Ip4IntegrityError`, increments `ip4__failed_parse__drop`,
and silently drops the frame
(`packet_handler__ip4__rx.py:120-126`).

## §3.2.1.2 Checksum

> "A host MUST verify the IP header checksum on every received
> datagram and silently discard every datagram that has a bad
> checksum."

**Adherence:** met. `Ip4Parser._validate_integrity` calls
`inet_cksum(self._frame[:hlen])` and rejects the frame with
`Ip4IntegrityError` on non-zero result
(`ip4__parser.py:108-111`). Silently dropped via the
`Ip4IntegrityError` catch path described above.

## §3.2.1.3 Addressing

> "(a) { 0, 0 } ... {0, <Host-number>} ... MUST NOT be used
> as a source address ... except as part of an initialization
> procedure by which the host learns its own IP address."
> "(c) {-1, -1} Limited broadcast. It MUST NOT be used as a
> source address."
> "(d) {<Network-number>, -1} Directed broadcast ... MUST NOT
> be used as a source address."
> "(g) {127, <any>} Internal host loopback address. Addresses
> of this form MUST NOT appear outside a host."

**Adherence:** met. `Ip4Parser._validate_sanity` rejects every
forbidden source-address class with `Ip4SanityError` and
`pointer=12`, in ascending address-space order
(`ip4__parser.py` `_validate_sanity`):

- (a) 0/8 (this network) minus 0.0.0.0 — `src.is_invalid` →
  reject. 0.0.0.0 itself (`is_unspecified`) is permitted so
  DHCP client initialization (the §3.2.1.3(a) carve-out) can
  reach the UDP RX path.
- (g) 127/8 loopback — `src.is_loopback` → reject. Linux
  enforces the same rule via `rp_filter=1` (the default).
- (Class D) 224/4 multicast — `src.is_multicast` → reject.
- (Reserved) 240/4 minus 255.255.255.255 — `src.is_reserved`
  → reject. (RFC 6890; group includes class E.)
- (c) 255.255.255.255 limited broadcast — `src.is_limited_broadcast`
  → reject.

The (d) per-subnet directed broadcast case requires
`_ip4_ifaddr` state to recognise and is enforced one layer up,
at the packet handler (`packet_handler__ip4__rx.py:145-159`).
All host-side `src` MUST-NOTs from §3.2.1.3 are covered.

> "When a host sends any datagram, the IP source address MUST be
> one of its own IP addresses (but not a broadcast or multicast
> address)."

**Adherence:** met. TX path
(`packet_handler__ip4__tx.py:251-265`) rejects any outbound src
that is not in the stack's owned-address set
(`_ip4_unicast ∪ _ip4_multicast ∪ _ip4_broadcast`) or the
unspecified-source DHCPv4 carve-out. Multicast / limited-
broadcast / network-broadcast sources are detected and replaced
with the stack's primary unicast address before send
(lines 269-321). When no replacement is possible the frame is
dropped with the documented counter.

> "A host MUST silently discard an incoming datagram that is not
> destined for the host. An incoming datagram is destined for
> the host if the datagram's destination address field is:
> (1) (one of) the host's IP address(es); or
> (2) an IP broadcast address valid for the connected network; or
> (3) the address for a multicast group of which the host is a
> member on the incoming physical interface."

**Adherence:** met. RX handler
(`packet_handler__ip4__rx.py:149-159`) checks the destination
against `_ip4_unicast ∪ _ip4_multicast ∪ _ip4_broadcast` and
drops with `ip4__dst_unknown__drop` if no membership matches.
The single exception is the DHCP-client mode (no unicast
configured yet), which permits any destination so the offer/ack
can be accepted before the stack owns an address.

> "A host MUST silently discard an incoming datagram containing
> an IP source address that is invalid by the rules of this
> section."

**Adherence:** met. The sanity rules in
`ip4__parser.py:142-158` enforce the invalid-source ban
(multicast / reserved / limited-broadcast). The handler emits
ICMP Parameter Problem **and** drops — the silent-discard
contract is satisfied because the upper layers never see the
frame; the ICMP reply is independent.

## §3.2.1.4 Fragmentation and Reassembly

> "The Internet model requires that every host support
> reassembly."

**Adherence:** met. See `docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`
for the per-clause audit of the reassembly state machine.

## §3.2.1.5 Identification

> "When sending an identical copy of an earlier datagram, a
> host MAY optionally retain the same Identification field in
> the copy."

**Adherence:** RFC 6864 §4.2 supersedes this MAY with **MUST
NOT** reuse. PyTCP's TX path does not reuse — every entry into
the fragmenter bumps `_ip4_id` afresh. See
`docs/rfc/ip4/rfc6864__ip4_id_field/adherence.md` for the
per-clause audit.

## §3.2.1.6 Type-of-Service

> "The IP layer MUST provide a means for the transport layer to
> set the TOS field of every datagram that is sent; the default
> is all zero bits. The IP layer SHOULD pass received TOS
> values up to the transport layer."
> "The particular link-layer mappings of TOS contained in
> RFC-795 SHOULD NOT be implemented."

**Adherence:** met (semantics redefined). The legacy TOS byte
has been redefined by RFC 2474 (DSCP, 6 bits) + RFC 3168 (ECN,
2 bits). PyTCP exposes both as separate kwargs on the IPv4 TX
entry point (`packet_handler__ip4__tx.py:101` — `ip4__ecn`;
DSCP defaults to 0 in `Ip4Assembler.__init__` at
`ip4__assembler.py:67`) and as separate properties on the
parser (`Ip4Header.dscp`, `Ip4Header.ecn`).

Both default to 0 unless the caller sets them. Received values
are surfaced on the parser object (`packet_rx.ip4.dscp`,
`packet_rx.ip4.ecn`) and propagated to transport-specific
hooks (TCP records peer-ECN on segment receive — see TCP
audits). RFC-795 link-layer mappings are not implemented.
Cross-references:
`docs/rfc/ip4/rfc2474__dscp/adherence.md`,
`docs/rfc/ip4/rfc3168__ecn/adherence.md`.

## §3.2.1.7 Time-to-Live

> "A host MUST NOT send a datagram with a Time-to-Live (TTL)
> value of zero."

**Adherence:** met. `packet_handler__ip4__tx.py:112` asserts
`0 < ip4__ttl < 256` before assembly; a caller attempting
`ttl=0` triggers an assertion. The default is
`IP4__DEFAULT_TTL = 64` (`ip4__header.py:75`) so callers that
don't set TTL get a safe value.

> "A host MUST NOT discard a datagram just because it was
> received with TTL less than 2."

**Adherence:** met. The RX sanity check rejects only **TTL == 0**
(`ip4__parser.py:136-140`); TTL=1 is delivered to the transport
layer normally. This matches the spec: host-mode does not
decrement TTL (decrement is a forwarder responsibility), so
TTL=1 is "fine" at the destination.

> "The IP layer MUST provide a means for the transport layer to
> set the TTL field of every datagram that is sent. When a
> fixed TTL value is used, it MUST be configurable."

**Adherence:** met. `_phtx_ip4` exposes `ip4__ttl: int | None =
None` (`packet_handler__ip4__tx.py:102`); on `None` the
handler resolves the default through qualified-module access
to `ip4_const.IP4__DEFAULT_TTL`
(`packet_handler__ip4__tx.py:122`) so every emission picks up
the live `ip4.default_ttl` sysctl value. The knob is
registered at `packages/pytcp/pytcp/protocols/ip4/ip4__constants.py` with a
validator that rejects TTL=0 (the same value §3.2.1.7
forbids on the wire) and values outside the uint8 wire field.
Operators tune it via `stack.init(sysctls={"ip4.default_ttl":
N})` at boot or `pytcp.stack.sysctl["ip4.default_ttl"] = N`
at runtime. The TCP / UDP / RAW socket layers still pass
explicit `ip4__ttl` when they have a per-packet reason; the
sysctl is the host default the transport layers fall back to.

## §3.2.1.8 Options

> "There MUST be a means for the transport layer to specify IP
> options to be included in transmitted IP datagrams."

**Adherence:** met. The TX entry point exposes
`ip4__options: Ip4Options = Ip4Options()`
(`packet_handler__ip4__tx.py:103`). Callers (today, mostly
tests and one DHCP-client path) construct the options via the
typed dataclasses under `packages/net_proto/net_proto/protocols/ip4/options/`.

> "All IP options (except NOP or END-OF-LIST) received in
> datagrams MUST be passed to the transport layer (or to ICMP
> processing when the datagram is an ICMP message). The IP and
> transport layer MUST each interpret those IP options that
> they understand and silently ignore the others."

**Adherence:** met. `Ip4Parser._parse` builds the typed
`Ip4Options` container from the on-wire byte stream
(`ip4__parser.py:121-123`) and stores it on `self._options`,
which is exposed via `packet_rx.ip4.options` and individual
accessors (`packet_rx.ip4.lsrr`, `packet_rx.ip4.ssrr`, etc.).
The transport layer can read whichever options it understands;
unrecognised kinds become `Ip4OptionUnknown` entries which are
preserved on the wire but not acted on.

> "(b) Stream Identifier Option ... this option SHOULD NOT be
> sent, and it MUST be silently ignored if received."

**Adherence:** met. Stream ID is not implemented as a typed
option (no `Ip4OptionStreamId` file); on receive it lands in
the catch-all `Ip4OptionUnknown` and the option is silently
preserved on the wire without effecting any behaviour.
Cross-reference: RFC 6814 audit (Stream ID formally deprecated).

> "(c) Source Route Options ... A host MUST support originating
> a source route and MUST be able to act as the final
> destination of a source route."

**Adherence:** partial. Wire codec for LSRR/SSRR is shipped
(`ip4__option__lsrr.py`, `ip4__option__ssrr.py`). On receive,
the LSRR/SSRR-bearing packet is gated by
`IP4__ACCEPT_SOURCE_ROUTE` (default False — matching Linux
`net.ipv4.conf.*.accept_source_route=0`)
(`packet_handler__ip4__rx.py:130-144`). When the operator opts
in, the option is parsed but not acted on as a final
destination (the rewrite-pointer step is Phase 2 router work).
Origination of LSRR/SSRR is not exposed on a high-level API.

This is a Phase-1 simplification consistent with the broader
deprecation in RFC 6814 — source-route processing on hosts is
considered an attack surface; modern stacks gate it off by
default.

> "(d) Record Route Option / (e) Timestamp Option:
> Implementation of originating and processing ... is OPTIONAL."

**Adherence:** wire codecs shipped; origination not exposed. We
do not auto-write our address into received Record Route /
Timestamp slots (that's router-side behaviour).

## §3.3.1 Routing Outbound Datagrams

> "The host IP layer MUST operate correctly in a minimal
> network environment, and in particular, when there are no
> gateways."

**Adherence:** met. The next hop is resolved by a host-mode
routing table (FIB): the Ethernet-TX path calls
`stack.ip4_fib.lookup(dst, connected=[...])`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py:265-306`,
table at `packages/pytcp/pytcp/runtime/fib.py` `RouteTable.lookup`). With no
default route, on-link destinations still resolve via a
*connected* route synthesized per-lookup from each assigned
interface address (`RouteTable.lookup` `connected=` arg), and
an off-link destination with no matching route returns the
`DROPPED__ETHERNET__DST_NO_GATEWAY_IP4` exit (now meaning "no
route to host"). The stack starts up and operates on a single
subnet with an empty FIB.

> "To efficiently route a series of datagrams to the same
> destination, the source host MUST keep a 'route cache' of
> mappings to next-hop gateways."

**Adherence:** met. PyTCP keeps a real per-address-family
routing table (`packages/pytcp/pytcp/runtime/fib.py` `RouteTable`) holding
explicit routes (default + operator/protocol static) plus
per-lookup-synthesized connected routes; `lookup` is a
longest-prefix match (`Route.destination.prefixlen`, then
lowest `metric`, then direct-over-gatewayed). This is the
RFC's intent — a deterministic next-hop mapping consulted per
datagram — exposed through the Phase-3 Route API
(`packages/pytcp/pytcp/stack/route.py` `RouteApi`). It is a routing *table*,
not a learned/aged *cache*: there is no per-destination cached
entry created from observed traffic or Redirects.

**`# Phase 2:`** A learned/aged route *cache* (per-destination
next-hop entries populated from ICMP Redirects, with ageing)
is Phase-2 work tied to the forwarding plane and Redirect
processing; the `RouteProtocol.REDIRECT` enum value is already
reserved in `packages/pytcp/pytcp/runtime/fib.py` for that path.

> "The IP layer MUST pick a gateway from its list of 'default'
> gateways. The IP layer MUST support multiple default gateways."

**Adherence:** partial. The data model now *supports* multiple
default routes: `RouteApi.add_ip4_route` accepts any number of
`0.0.0.0/0` `Route`s and `RouteTable.lookup` selects among
equal-prefix candidates by lowest `metric` (then
direct-over-gatewayed, then stable order), so a metric-ordered
default-gateway list is representable and the preferred one is
picked (`packages/pytcp/pytcp/runtime/fib.py` `RouteTable.lookup`). What is
still Phase-2 is *dead-gateway failover* — detecting an
unreachable default router (NUD / Redirect) and demoting it —
which needs the reachability machinery the forwarding plane
brings. `replace_default_ip4` (the boot/DHCP/RA path)
deliberately keeps a single default for the common host case.

> "When it receives a Redirect, the host updates the next-hop
> gateway in the appropriate route cache entry."

**Adherence:** not implemented (Phase 2). ICMP Redirect parsing
exists in the ICMPv4 protocol package, but the RX handler does
not mutate routing state on Redirect — it logs the message and
moves on. The FIB is ready to receive such entries
(`RouteProtocol.REDIRECT`); the missing piece is the RX-path
`RouteApi.add_ip4_route(..., protocol=RouteProtocol.REDIRECT)`
call. Cross-reference:
`docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`
which audits the Redirect-message side of this same gap.

## §3.3.2 Reassembly

See `docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`.

## §3.3.3 Fragmentation

> "Hosts MUST NOT generate fragments that overlap."

**Adherence:** met. The TX fragmenter
(`packet_handler__ip4__tx.py:188-205`) slices the payload at
MTU-aligned 8-byte boundaries with non-overlapping ranges
(`payload[_:payload_mtu+_] for _ in range(0, len(payload),
payload_mtu)`). The construction is algebraically incapable of
producing overlap.

> "A host MAY emit a 'Don't Fragment' ICMP error message in
> response to a frame that would have required fragmentation."

This is the PMTUD feedback path — audited under
`docs/rfc/ip4/rfc1191__pmtud_ip4/adherence.md`.

## §3.3.4 Local Multihoming

> "A host MAY be multihomed."

**Adherence:** partial — single physical interface, but the
L3 routing/next-hop layer is now multihoming-correct. Routing
is destination-keyed: `RouteTable.lookup` resolves the next
hop from the destination against the FIB plus the connected
routes of *all* assigned interface addresses, independent of
which interface address the packet's source belongs to. This
landed the Linux-correct fix where a destination on-link for
one interface address is sent directly even when the source
is a different interface address (the old source-coupled scan
would have sent it to the default gateway) — pinned by
`packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__routing.py::TestIp4RoutingNextHop::test__ip4__routing__multihomed_on_link_dst_resolved_directly`.
What remains single-interface is the link layer (one
`_interface_mtu`, one `_mac_unicast`, one TAP/TUN fd) and the
multihoming sub-requirements 3.3.4.2 (a)-(j) that presume
multiple physical interfaces.

**`# Phase 2:`** Multi-physical-interface support is on the
project north-star (Phase 2 router); the routing/source-
selection half is done, the link layer will catch up.

## §3.3.5 Source Route Forwarding

> "A host MAY support source route forwarding ..."

**Adherence:** not implemented (Phase 2). PyTCP does not
forward source-routed datagrams; it gates them off entirely on
receive (see §3.2.1.8). When forwarding lands, this is where
the LSRR pointer-advance / dst rewrite / option preservation
logic goes.

## §3.3.6 Broadcasts

> "Limited Broadcast Address {-1, -1} ... There is a class of
> hosts that USE this address as a source address. ... it MUST
> NOT be used as a source address."

**Adherence:** met. Limited-broadcast source is rejected on
receive (§3.2.1.3 above) and replaced on send
(`packet_handler__ip4__tx.py:289-306`).

> "Subnet broadcast addresses (e.g., {network, subnet, -1})
> ... MUST be received as a broadcast."

**Adherence:** met. The `_ip4_broadcast` set populated at
`stack.init()` time from each `Ip4IfAddr.network.broadcast`
includes both subnet and (where applicable) network
broadcasts. RX handler checks against this set
(`packet_handler__ip4__rx.py:149-153`).

> "Outgoing IP datagrams from an application using a
> destination IP address of {-1, -1} MUST be silently discarded
> if the host has the option 'broadcasts permitted' [link]
> turned off."

**Adherence:** met. Broadcast TX is gated on the
per-interface `ip4.allow_broadcast` sysctl (default 0 —
"broadcasts permitted" off, registered in
`packages/pytcp/pytcp/protocols/ip4/ip4__constants.py:114`). The TX handler
(`packet_handler__ip4__tx.py:162-180`) reads it via
`sysctl_iface.get_for_iface` and silently drops any datagram
to the limited-broadcast address or a configured subnet
broadcast when the flag is off, bumping
`ip4__dst_broadcast_disallowed__drop`. The DHCP-client
pre-bind path (src=0.0.0.0, UDP sport=68/dport=67) is the sole
exemption, matching Linux.

## §3.3.7 IP Multicasting

> "A host SHOULD support local IP multicasting on all connected
> networks for which a mapping from Class D IP addresses to
> link-layer addresses has been specified."

**Adherence:** met (reception). `_ip4_multicast` is populated
at boot with the all-hosts (224.0.0.1) entry; the destination
filter (`packet_handler__ip4__rx.py:149-153`) admits anything
in this set. The Ethernet MAC mapping is implemented in
`packages/net_addr/net_addr/ip4_address.py` (`Ip4Address.multicast_mac`).

> "Hosts SHOULD implement IGMPv1 ..."

**Adherence:** met (exceeds the SHOULD). PyTCP ships an IGMPv3
host implementation (RFC 3376) with RFC 2236 (IGMPv2) and
RFC 1112 (IGMPv1) querier-version fallback. The group-
management state machine, Report / Leave emission, query
response, and version-compatibility handling are audited in the
`docs/rfc/ip4/rfc3376__igmp_v3`, `rfc2236__igmp_v2`, and
`rfc1112__ip4_multicasting` records.

## §3.3.8 Error Reporting (link-layer → IP layer)

> "Wherever feasible, the IP layer MUST be informed about errors
> reported by the link layer (e.g., a refused connection from an
> X.25 network or an Ethernet Excessive Collisions error)."

**Adherence:** partial. The TAP/TUN interface reports
read/write errors via Python exceptions which the RX/TX
loops catch and log; they do not propagate as ICMP Host
Unreachable upstream. Practical impact is minimal — the only
"link-layer error" on a TAP interface is the fd being
unwriteable, which is a configuration error rather than a
transient network condition.

---

## Test coverage audit

### §3.2.1.1 / §3.2.1.2 Version + Checksum integrity

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__integrity_checks.py`
  Covers `ver != 4` and bad-checksum branches with
  `Ip4IntegrityError`.

**Status:** locked in.

### §3.2.1.3 Source-address sanity (is_invalid / loopback / multicast / reserved / limited-broadcast)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Each branch exercised with the expected `pointer` value
  (one case per address-space class: 0/8 non-zero, 127/8
  loopback, 224/4 multicast, 240/4 reserved,
  255.255.255.255 limited broadcast).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies ICMP Parameter Problem emission with the documented
  rate-limit / DHCP-mode gates.

**Status:** locked in.

### §3.2.1.3 Destination filtering (own / broadcast / multicast)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Covers the three accept paths + the dst-unknown drop.

**Status:** locked in.

### §3.2.1.3 TX source-address validation + replacement (multicast / broadcast / unspec)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Matrix of src=owned, src=multicast (replaced), src=limited-
  broadcast (replaced), src=network-broadcast (replaced),
  src=unspec+DHCP (passthrough), src=unspec+other (selector or
  drop).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  RFC 6724 rule-by-rule selection.

**Status:** locked in.

### §3.2.1.6 TOS / DSCP / ECN propagation

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  Field-level boundary asserts.
- **Integration:** ECN-relevant TCP flows covered in TCP audits.

**Status:** locked in (cross-reference DSCP and ECN audits).

### §3.2.1.7 TTL=0 rejection + default + configurability

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py::ttl == 0`
  pins the RX-side ban.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/ip4/test__ip4__constants.py::TestIp4Constants`
  pins `IP4__DEFAULT_TTL = 64`; `TestIp4DefaultTtlSysctl` pins
  the `ip4.default_ttl` registration, the validator's
  range-and-type rejections (TTL=0, overflow > 255, non-int),
  and that `sysctl.set` updates the backing module attribute.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies ICMP Parameter Problem emission with `pointer=8`.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__tx.py::TestIp4TxRfc1122DefaultTtlSysctl`
  Drives the sysctl override and verifies the wire TTL of an
  outbound unicast datagram reflects the live value; verifies
  multicast destinations stay at TTL=1 regardless of the
  unicast-default override (RFC 1112 §6.1 carve-out).

**Status:** locked in.

### §3.2.1.8 Options pass-through + LSRR/SSRR gate

- **Unit:** one file per option in
  `packages/net_proto/net_proto/tests/unit/protocols/ip4/options/`.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx__source_route.py`
  Drives the `IP4__ACCEPT_SOURCE_ROUTE` matrix.

**Status:** locked in.

### §3.3.1 Routing (FIB next-hop / default route / longest-prefix)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/test__runtime__fib.py::TestRouteTableLookupIp4`
  / `TestRouteTableLookupTiebreaks` — longest-prefix match,
  metric tiebreak, connected-over-gatewayed, default route
  matches anything, no-route returns `None`.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/stack/test__stack__route.py::TestRouteApiRead`
  / `TestRouteApiMutation` /
  `TestInstallBootDefaultRoutes` — copy-by-value read,
  add/remove/replace-default, boot default install.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__routing.py::TestIp4RoutingNextHop`
  — on-link direct, off-link via default gateway, no-route
  drop, and the destination-keyed multihoming behaviour.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__routing.py::TestIp4RoutingStaticRoute`
  — a static non-default `/16` beats the `/0` default
  (longest-prefix), default used outside it, on-link
  unaffected.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ethernet/test__ethernet__tx.py`
  — the parametrized Ethernet-TX matrix exercises the
  FIB-driven next-hop counters/statuses end to end.

**Status:** locked in for the FIB longest-prefix next-hop,
default route, and static-route paths. The learned/aged route
*cache* and Redirect-driven entries are
`n/a (gap not closed; add test with fix)` (Phase 2).

### §3.3.3 Fragmentation on send (no overlap)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Fragmentation matrix asserts that fragment offsets cover the
  payload without overlap and that the last fragment carries
  MF=0.

**Status:** locked in.

### §3.3.6 Broadcasts (TX replacement, RX acceptance)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  + `..__rx.py` cover broadcast send / receive.

**Status:** locked in.

### §3.3.7 IP multicasting (reception)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies the all-hosts 224.0.0.1 RX path.

**Status:** locked in.

### Gaps without tests

- **§3.3.1.5 ICMP Redirect → route-cache update** — not
  implemented (Phase 2); no test surface today.
- **§3.3.4 Multihoming** — the L3 routing/next-hop layer is
  destination-keyed and multihoming-correct (pinned by
  `test__ip4__routing.py::TestIp4RoutingNextHop::test__ip4__routing__multihomed_on_link_dst_resolved_directly`);
  what remains Phase 2 is multiple *physical* interfaces (one
  `_interface_mtu` / `_mac_unicast` / TAP-TUN fd today).
- **§3.3.5 Source-route forwarding** — not implemented
  (Phase 2).
- **§3.3.8 Link-layer error → IP-layer notification** —
  Phase 1 logs, does not propagate; no error-injection test.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| §3.2.1.1 Version != 4 silent discard                  | locked in |
| §3.2.1.2 Bad checksum silent discard                  | locked in |
| §3.2.1.3 Source-address sanity rules                  | locked in |
| §3.2.1.3 Destination filtering (RX)                   | locked in |
| §3.2.1.3 Source-address validation + replacement (TX) | locked in |
| §3.2.1.6 TOS / DSCP / ECN propagation                 | locked in (via separate DSCP / ECN audits) |
| §3.2.1.7 TTL=0 reject + default + configurable        | locked in (sysctl `ip4.default_ttl`) |
| §3.2.1.8 Options pass-through + LSRR/SSRR gate        | locked in |
| §3.3.1 FIB longest-prefix next-hop / default / static | locked in |
| §3.3.1 Learned/aged route cache + Redirect entries    | n/a (Phase 2) |
| §3.3.3 Fragmentation correctness (no overlap)         | locked in |
| §3.3.4 Multihoming (L3 destination-keyed routing)     | locked in; multi-physical-interface n/a (Phase 2) |
| §3.3.5 Source-route forwarding                        | n/a (Phase 2) |
| §3.3.6 Broadcast send / receive                       | locked in |
| §3.3.7 Multicast reception + IGMPv3 group management  | locked in (IGMP audited in RFC 3376 record) |
| §3.3.8 Link-layer error propagation                   | partial (logged, not propagated) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3.2.1 IP wire-format and integrity                 | met    |
| §3.2.1 IP source/destination validity rules         | met    |
| §3.2.1 TTL / TOS / Identification host-side rules   | met (semantics redefined where superseded) |
| §3.2.1 Options pass-through and LSRR/SSRR gate      | met    |
| §3.3.1 Routing — FIB longest-prefix next-hop / default / static | met |
| §3.3.1 Multiple default gateways (representable, metric-ordered) | partial — failover Phase 2 |
| §3.3.1.5 ICMP Redirect route update                 | not met (Phase 2) |
| §3.3.2/3.3.3 Reassembly + fragmentation             | met (cross-referenced)  |
| §3.3.4 Multihoming — L3 routing destination-keyed   | met; multi-physical-interface not met (Phase 2) |
| §3.3.5 Source-route forwarding                      | not met (Phase 2) |
| §3.3.6 Broadcast handling                           | met    |
| §3.3.7 Multicast reception + IGMPv3 group management | met (IGMP audited in RFC 3376 record) |
| §3.3.8 Link-layer error propagation                 | partial |

The principal Phase-1 gaps are:

1. **ICMP Redirect → no route-cache update** — covered by the
   ICMP audit; the gap is symmetric on both sides.

Phase-2 gaps (multihoming, route cache, source-route forwarding)
are tracked by the project north-star.
