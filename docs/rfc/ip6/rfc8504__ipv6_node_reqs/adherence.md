# RFC 8504 — IPv6 Node Requirements

| Field       | Value                                                   |
|-------------|---------------------------------------------------------|
| RFC number  | 8504                                                    |
| Title       | IPv6 Node Requirements                                  |
| Category    | Best Current Practice (BCP 220); obsoletes RFC 6434     |
| Date        | January 2019                                            |
| Source text | [`rfc8504.txt`](rfc8504.txt)                            |

RFC 8504 is a meta-document — an applicability statement that
collects normative IPv6 node requirements from many other
RFCs into one place. Each section references one or more
underlying RFCs; this adherence record maps each section to
the PyTCP status of the referenced specification(s),
classified as one of:

- **shipped** — implemented and regression-pinned by tests.
- **partial** — implemented for the host-relevant subset; the
  remainder is deferred per the North Star (Phase 1 host
  scope today, Phase 2 router-grade later).
- **deferred** — on-list but not yet implemented; tracked in
  `docs/refactor/v6_remaining_items.md` or via a TODO.
- **deliberately skipped** — out of scope per CLAUDE.md
  "Project North Star" non-goals (mobility, IPsec, hardware
  offloads, kernel bypass, userspace routing protocols,
  Netfilter/eBPF hooks, crypto extensions). These exclusions
  apply regardless of phase.
- **N/A** — section is informational, sub-IP layer (link-
  layer specifics belong to the OS / NIC), or addresses
  application-layer behaviour (DNS resolver, mDNS) outside
  the stack proper.

---

## Top-line summary

| Section | Topic                                          | PyTCP status        |
|---------|------------------------------------------------|---------------------|
| §4      | Sub-IP Layer (link-layer RFCs)                 | N/A (TAP/TUN abstracts the link) |
| §5.1    | RFC 8200 IPv6                                  | shipped             |
| §5.2    | Extension Headers                              | shipped             |
| §5.3    | Excessive option protections                   | shipped (`ip6.ext_hdr_max_*` sysctls + RX cap gate) |
| §5.4    | RFC 4861 Neighbor Discovery                    | partial (NUD + RFC 7559 + RFC 4311 + RFC 4429 + RFC 7527 shipped; Redirect TX + RFC 6980 TX-refuse gate are follow-ups) |
| §5.5    | RFC 3971 SEND                                  | deliberately skipped (crypto extension) |
| §5.6    | RFC 5175 RA Flags Option                       | deferred (no consumer in PyTCP) |
| §5.7    | PMTU Discovery (RFC 8201) + min MTU            | shipped             |
| §5.8    | RFC 4443 ICMPv6                                | shipped             |
| §5.9    | RFC 4191 Default Router Preferences            | deferred            |
| §5.10   | RFC 8028 First-Hop Router Selection            | deferred            |
| §5.11   | RFC 3810 MLDv2                                 | partial (TX shipped; RX is querier-role Phase 2) |
| §5.12   | RFC 3168 ECN                                   | shipped (TCP ECN echo + IP-layer ECT/DSCP marking via IPV6_TCLASS + §5.3 reassembly aggregation) |
| §6.1    | RFC 4291 Addressing Architecture               | shipped             |
| §6.2    | Multiple address support                       | shipped             |
| §6.3    | RFC 4862 SLAAC                                 | shipped (basic SLAAC + DAD + RFC 7217 stable IIDs + Optimistic DAD + Enhanced DAD + §5.5.3(e)(6) 2-hour rule) |
| §6.4    | RFC 4941 Privacy Extensions                    | deferred            |
| §6.5    | RFC 3315 DHCPv6                                | deferred            |
| §6.6    | RFC 6724 Default Address Selection             | partial             |
| §7      | DNS                                            | N/A (resolver is application-layer) |
| §8.1    | DHCP for non-address config                    | deferred (paired with §6.5) |
| §8.2    | RA + default gateway                           | shipped             |
| §8.3    | RFC 8106 RA DNS option                         | deferred            |
| §8.4    | DHCP vs RA option discussion                   | informational (no code) |
| §9      | Service Discovery (mDNS / DNS-SD)              | deliberately skipped (application-layer) |
| §10     | IPv4 Support and Transition                    | shipped (full v4 stack runs alongside v6) |
| §11     | Application Support / APIs                     | partial (BSD socket facade) |
| §12     | Mobility (RFC 6275 / 5555)                     | deliberately skipped (North Star non-goal) |
| §13     | Security (IPsec / IKEv2)                       | deliberately skipped (crypto extension) |
| §14     | Router-Specific Functionality                  | Phase 2 (host-only today) |
| §15     | Constrained Devices                            | N/A                 |
| §16     | Node Management (MIB / YANG)                   | deferred (operational telemetry deferred) |

The deliberate-skip categories — mobility, IPsec, SEND, mDNS
— are excluded by PyTCP's North Star (`CLAUDE.md`) regardless
of phase. The deferred categories are on-list for future
Phase 1 host work; the partial categories are "host scope
today, router scope tomorrow" splits.

---

## §4 Sub-IP Layer

> "IPv6 packets can be transmitted via various link layers,
> e.g., Ethernet, Wi-Fi, PPP, ..."

**Adherence: N/A.** PyTCP runs over a TAP/TUN file
descriptor (`packages/pytcp/pytcp/lib/interface_layer.py`); the underlying
link layer is the OS's responsibility. Ethernet framing is
implemented in `packages/net_proto/net_proto/protocols/ethernet/`; 802.3 is
implemented in `packages/net_proto/net_proto/protocols/ethernet_802_3/`.

---

## §5 IP Layer

### §5.1 RFC 8200 IPv6 — shipped

> "IPv6 nodes MUST not create overlapping fragments. ...
> the entire datagram (and any constituent fragments) MUST
> be silently discarded."

**Adherence:** shipped. Overlap detection lands in the
shared `packages/pytcp/pytcp/protocols/ip/ip_frag_table.py::IpFragTable.add_fragment`
with strict-reading policy (RFC 5722 §3); duplicate
fragments are also dropped. See the
[RFC 5722 audit](../rfc5722__overlapping_fragments/adherence.md)
once that record is created — the relevant code is in
`6c1c8634` / `604eebbf`.

> "As recommended in [RFC8021], nodes MUST NOT generate
> atomic fragments ... if a receiving node reassembling a
> datagram encounters an atomic fragment, it should be
> processed as a fully reassembled packet, and any other
> fragments that match this packet should be processed
> independently."

**Adherence:** shipped (receive path). PyTCP's TX path does
not generate atomic fragments. The RX path's atomic-fragment
fast-path in `IpFragTable.add_fragment` handles atomic
fragments in isolation per RFC 6946 §4 (commit `909c3e06`).

> "All nodes SHOULD support the setting and use of the IPv6
> Flow Label field as defined in [RFC6437]."

**Adherence:** shipped. The IPv6 header carries a Flow
Label field (`packages/net_proto/net_proto/protocols/ip6/ip6__header.py`); the
IPv6 TX path auto-computes a stable 20-bit label from the
`(src, dst)` pair via `compute_ip6_flow_label`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py:141-162`),
gated by the `ip6.flow_label_generation` sysctl (default 1;
set 0 to emit `flow=0`). See the
[RFC 6437 audit](../rfc6437__flow_label/adherence.md).

> "All conformant IPv6 implementations MUST be capable of
> sending and receiving IPv6 packets; forwarding
> functionality MAY be supported."

**Adherence:** shipped (host scope). Forwarding is a Phase-2
goal — see CLAUDE.md "Project North Star".

> "Nodes SHOULD avoid using predictable Fragment
> Identification values in Fragment headers, as discussed
> in [RFC7739]."

**Adherence:** partial. The TX path uses a per-stack
`_ip6_id` counter that increments monotonically. RFC 7739
randomized-ID is a Phase-1 polish item; not yet wired.

### §5.2 Support for IPv6 Extension Headers — shipped

**Adherence:** shipped. The full RFC 8200 §4 extension-
header chain is implemented (Hop-by-Hop, Destination
Options, Routing, Fragment, No Next Header). Routing Header
type 0 is hard-dropped per RFC 5095. See the
[RFC 8200 audit](../rfc8200__ipv6/adherence.md) and the
[RFC 5095 audit](../rfc5095__deprecate_rh0/adherence.md).

### §5.3 Protecting a Node from Excessive Extension Header Options — shipped

> "A host MAY limit the number of consecutive PAD1 options
> ... A host MAY limit the number of bytes in a PADN option
> ... A host MAY disallow unknown options ... A host MAY
> impose a limit on the maximum number of non-padding
> options ..."

**Adherence:** shipped. PyTCP enforces three configurable
caps via the sysctl registry, applied by the IPv6 RX path
after a successful HBH / Destination Options parse:

- `ip6.ext_hdr_max_options` (default 16) — total option
  count per Hop-by-Hop / Destination Options header.
- `ip6.ext_hdr_max_pad_bytes` (default 16) — total Pad-
  byte budget per header (Pad1 contributes 1, PadN of
  length N contributes 2 + N).
- `ip6.ext_hdr_max_unknown_options` (default 2) —
  unknown-option count per header.

The defaults are deliberately permissive — Linux's option-
validation defaults pass legitimate traffic with reasonable
padding, and PyTCP matches that behaviour. Setting any cap
to 0 disables that check.

The cap-check helper lives at
`packages/pytcp/pytcp/protocols/ip6/ip6__ext_hdr_limits.py::check_ext_hdr_option_caps`;
the RX wiring is at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py::_phrx_ip6_hbh`
and `::_phrx_ip6_dest_opts`. A cap violation drops the
packet silently (the §5.3 caps are resource-exhaustion
defences; the receiver is not obliged to emit ICMPv6
Parameter Problem) and bumps
`ip6_hbh__option_cap_exceeded__drop` or
`ip6_dest_opts__option_cap_exceeded__drop`.

The pre-existing option-length and -alignment rules from
RFC 8200 §4.2 remain in force (covered by the §4 audit) —
the §5.3 caps layer on top.

### §5.4 Neighbor Discovery for IPv6 — partial

**Adherence:** partial.

| ND mechanism                        | Status                                     |
|-------------------------------------|--------------------------------------------|
| Router Solicitation (TX)            | shipped (`packet_handler__icmp6__tx.py`)   |
| Router Advertisement (RX)           | shipped + RFC 4862 §5.5.3 prefix filtering (commit `d23d17bb`) |
| Neighbor Solicitation (TX)          | shipped                                    |
| Neighbor Solicitation (RX)          | shipped + RFC 4861 §7.2.3 DAD validity (commit `88d09251`) |
| Neighbor Advertisement (TX/RX)      | shipped                                    |
| Duplicate Address Detection         | shipped                                    |
| Solicited-Node multicast address    | shipped (`packages/net_addr/net_addr/ip6_address.py`)        |
| Redirect (RX/TX)                    | deferred (host scope; RX would be Phase-1, TX is Phase-2 router) |
| NUD timers (RFC 4861 §7.3)          | shipped (`packages/pytcp/pytcp/lib/neighbor.py` NUD framework; `neighbor.*` sysctls) |
| RFC 6980 ND fragmentation rejection | partial — RX shipped (`packet_handler__icmp6__rx.py:175-191`); TX-side refuse-to-fragment-ND gate is a Phase-1 follow-up |
| RFC 7559 RS exponential backoff     | shipped (`_send_icmp6_nd_router_solicitations_with_backoff` at `packet_handler/__init__.py:1431`; truncated binary exponential with ±10% jitter) |
| RFC 4311 host-to-router load share  | shipped (`_get_icmp6_default_router_for_destination` at `packet_handler/__init__.py:974`; per-destination modulo over highest-pref equivalence class) |

### §5.5 SEcure Neighbor Discovery (SEND) — deliberately skipped

> "SEND ... and Cryptographically Generated Addresses
> (CGAs) ... At this time, support for SEND is considered
> optional."

**Adherence:** deliberately skipped per North Star. SEND is
a crypto extension (RFC 3971 / 3972 use RSA CGAs); PyTCP's
North Star excludes crypto extensions (AH, ESP, IPsec,
MACsec, SEND).

### §5.6 RFC 5175 RA Flags Option — deferred

**Adherence:** deferred. PyTCP's RA option parser
recognizes the canonical option types (Source Link-layer,
MTU, Prefix Information); the 48-bit flag-extension option
defined in RFC 5175 is not parsed. The RFC notes "no flags
have been defined that make use of the new option" — there
is no consumer to drive implementation today.

### §5.7 Path MTU Discovery and Packet Size — shipped

**Adherence:** shipped. PyTCP implements RFC 8201 PMTUD on
the IPv6 send path; ICMPv6 Packet Too Big drives the per-
destination MTU cache. See the
[RFC 8201 audit](../rfc8201__pmtud_ip6/) for clause-by-
clause coverage.

### §5.8 RFC 4443 ICMPv6 — shipped

**Adherence:** shipped. `packages/net_proto/net_proto/protocols/icmp6/`
implements the full RFC 4443 message set (Destination
Unreachable, Packet Too Big, Time Exceeded, Parameter
Problem, Echo Request/Reply). RX dispatch is in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py`.
RFC 4884 multi-part extension is **deferred** — no
consumer at present.

### §5.9 RFC 4191 Default Router Preferences — deferred

**Adherence:** deferred. PyTCP currently treats every RA as
default-preference router. Multi-router prioritization /
more-specific routes are tracked as a future Phase-1 item.

### §5.10 RFC 8028 First-Hop Router Selection — deferred

**Adherence:** deferred. Multihoming-aware first-hop
selection requires per-prefix gateway state that PyTCP's
single `_ip6_ifaddr` model does not yet expose.

### §5.11 RFC 3810 MLDv2 — partial

**Adherence:** partial.

- **TX (host emits Reports on group-membership change):**
  shipped. `_send_icmp6_multicast_listener_report` in
  `packet_handler__icmp6__tx.py` builds an HBH+RouterAlert-
  wrapped MLDv2 Report (commit `599f67a5`).
- **RX (host receives Queries / processes Reports):** stub.
  Inbound Reports bump `icmp6__mld2_report` and log; no
  state update (host scope — Reports are processed by a
  router-mode querier). MLDv2 Query (type 130) RX is **not
  yet handled** — falls into `__phrx_icmp6__unknown`. A
  full Query → Report responder is a Phase-1 polish item.
  The querier role itself is Phase-2 (router-grade). See
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py::__phrx_icmp6__mld2_report`
  (commit `3459cddf`) for the documented Phase-2 marker.

### §5.12 RFC 3168 ECN — shipped

**Adherence:** shipped. TCP-side ECN echo (CE detection,
ECE/CWR signalling) is wired in `packages/pytcp/pytcp/protocols/tcp/`
(see TCP RFC adherence records). The IP-layer side — host
upper layers asking the IP stack to set the ECT codepoint
on outbound packets — is now exposed via the socket API
(2026-05-29): `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, …)`
threads the ECN bits (and the DSCP bits) onto every
outbound IPv6 packet through `_effective_ip_ecn()` /
`_effective_ip_dscp()`, and fragment reassembly aggregates
the ECN per RFC 3168 §5.3. Full IPv6 ECN audit at
`docs/rfc/ip6/rfc3168__ecn/adherence.md`; DSCP at
`docs/rfc/ip6/rfc2474__dscp/adherence.md`.

---

## §6 Addressing and Address Configuration

### §6.1 RFC 4291 Addressing Architecture — shipped

**Adherence:** shipped. `packages/net_addr/net_addr/ip6_address.py` and
`packages/net_addr/net_addr/ip6_network.py` implement the RFC 4291 address
model with /64 subnet boundary. RFC 7371 multicast flag
updates: covered by the multicast scope/transient flag
handling in `Ip6Address`. RFC 7421 /64 boundary: enforced
by the host-derivation (`Ip6IfAddr.from_eui64`) and SLAAC
paths.

### §6.2 Host Address Availability — shipped

**Adherence:** shipped. PyTCP supports multiple addresses
per host (`_ip6_ifaddr` is a `list[Ip6IfAddr]`). Per-host
prefix delegation (RFC 8273) is **deferred**.

### §6.3 RFC 4862 SLAAC — shipped

**Adherence:** shipped.

| Mechanism                                         | Status                                                                                                       |
|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Link-local address generation                     | shipped (EUI-64 default + RFC 7217 stable opaque IID alternative; per `_derive_ip6_address_from_prefix`)     |
| Duplicate Address Detection                       | shipped (with §7.2.3 strictness — commit `88d09251`)                                                         |
| Prefix Information option processing              | shipped + §5.5.3 (e)(1)-(e)(3) filters (commit `d23d17bb`)                                                    |
| §5.5.3 (e)(6) 2-hour rule on lifetime extension   | shipped (`packet_handler/__init__.py:615-630`; `pi__2hour_rule_ignored__drop` counter on guard)              |
| RFC 7217 stable, opaque IIDs                      | shipped (`_derive_ip6_address_from_prefix` at `packet_handler/__init__.py:1141`; secret-keyed PRF with §6 regenerate-on-collision) |
| Optimistic DAD (RFC 4429)                         | shipped (`_icmp6_dad__states` at `packet_handler/__init__.py:210`; address installed as OPTIMISTIC; NA emit-path clears Override flag per §3.3) |
| Enhanced DAD loopback detection (RFC 7527)        | shipped (Nonce option codec in NS TX/RX paths; `packet_handler__icmp6__tx.py:184`, `packet_handler__icmp6__rx.py:877`) |

### §6.4 RFC 4941 Privacy Extensions — deferred

**Adherence:** deferred. Temporary-address generation is a
Phase-1 polish item; the RFC marks it SHOULD, and PyTCP's
current operating profile (server-style host) gives
privacy addresses limited benefit. Not on the critical
path.

### §6.5 RFC 3315 DHCPv6 — deferred

**Adherence:** deferred. PyTCP implements DHCPv4 client
(`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py`); a DHCPv6 client is a future
Phase-1 item, paired with RFC 7844 anonymity profile
support. The RFC marks DHCPv6 as SHOULD.

### §6.6 RFC 6724 Default Address Selection — partial

**Adherence:** partial. PyTCP runs the RFC 6724 default
source-address selection algorithm in
`_select_ip6_source`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__tx.py:363`):
Rule 1 (prefer same address) short-circuits when the
destination is itself owned, and the remaining candidates
are ranked by a lexicographic key encoding Rule 2 (scope),
Rule 3 (avoid deprecated), Rule 6 (matching label via the
§10.3 default policy table), Rule 7 (temp-address
preference, gated on `icmp6.use_tempaddr`), and Rule 8
(longest matching prefix). Rules 4 (home address) and 5 /
5.5 (outgoing interface / next-hop) are out of scope for a
single-interface host. Full clause-by-clause coverage is in
the [RFC 6724 audit](../rfc6724__default_address_selection/adherence.md).

---

## §7 DNS — N/A

> "All nodes SHOULD implement stub-resolver
> functionality ... with support for AAAA, ip6.arpa
> reverse, EDNS(0)."

**Adherence:** N/A. DNS is application-layer and lives
outside PyTCP's stack scope. Applications running atop
PyTCP can reach DNS via the BSD socket facade as they
would on any host.

---

## §8 Configuring Non-address Information

### §8.1 DHCP for Other Configuration Information — deferred

**Adherence:** deferred (paired with §6.5 DHCPv6 client).

### §8.2 RA + Default Gateway — shipped

**Adherence:** shipped. RA processing extracts the source
address as the gateway for each admitted Prefix
Information option (`packet_handler__icmp6__rx.py::__phrx_icmp6__nd_router_advertisement`).

### §8.3 RFC 8106 RA DNS option — deferred

**Adherence:** deferred (PyTCP does not consume DNS
configuration; resolver is app-layer).

### §8.4 DHCP vs RA option discussion — informational

**Adherence:** N/A (descriptive).

---

## §9 Service Discovery Protocols (mDNS / DNS-SD) — deliberately skipped

**Adherence:** deliberately skipped. mDNS / DNS-SD are
application-layer protocols outside the stack scope.

---

## §10 IPv4 Support and Transition — shipped

**Adherence:** shipped. PyTCP runs a full IPv4 stack
alongside IPv6 (`packages/net_proto/net_proto/protocols/ip4/`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py`,
etc.). Tunnelling (RFC 4213) is **deferred** — PyTCP runs
both stacks natively, not as a transition mechanism.

---

## §11 Application Support

### §11.1 RFC 5952 Textual Representation — partial

**Adherence:** partial. `Ip6Address.__str__` produces a
canonical short-form representation; full RFC 5952
canonicalization (suppress leading zeros, longest run of
zero groups, etc.) is implemented in `packages/net_addr/net_addr/ip6_address.py`.
Operator input parsing accepts the long form too.

### §11.2 APIs — partial

**Adherence:** partial. `packages/pytcp/pytcp/socket/` implements a BSD-
socket facade with `TcpSocket`, `UdpSocket`, `RawSocket`.
Advanced socket APIs (RFC 3542) are not implemented; RFC
5014 Source-Address-Selection control is not exposed; RFC
3678 Multicast Source Filters are not implemented.

---

## §12 Mobility — deliberately skipped

> "Mobile IPv6 [RFC6275] and associated specifications
> ... are considered a MAY at this time."

**Adherence:** deliberately skipped per North Star.
Mobility extensions (RFC 6275 MIPv6, RFC 5555 dual-stack
mobility, NEMO, RH2 mobility processing) are explicitly
excluded by CLAUDE.md "Project North Star".

---

## §13 Security — deliberately skipped

> "RFC 4301 IPsec Architecture SHOULD be supported by all
> IPv6 nodes."

**Adherence:** deliberately skipped per North Star. IPsec
(AH, ESP, IKEv2) is a crypto extension; PyTCP's North Star
explicitly excludes "Crypto extensions (AH, ESP, IPsec,
MACsec)". Application-layer security (TLS, SSH) lives
above the stack and is not in scope.

---

## §14 Router-Specific Functionality — Phase 2

**Adherence:** Phase 2. PyTCP is a host stack today
(`CLAUDE.md` — Phase 1 host parity, Phase 2 router
parity). Router-specific functionality (sending RAs,
processing inbound RS, FIB-driven forwarding, RFC 1812
router requirements, IGMP/MLD querier role) is on-list
for Phase 2. The chain walker, ICMP error rate-limiter,
TTL/Hop-Limit handling, and embedded-data preservation
are already wired with Phase-2 forwarding in mind so the
upgrade path is incremental.

### §14.1 RFC 2711 Router Alert Option — partial

**Adherence:** partial. PyTCP **emits** the RA option in
MLDv2 Reports (commit `599f67a5`). PyTCP does not yet
**consume** the option for a host-side router-alert-aware
upper layer (no MLD querier; no RSVP). Phase-2 router
work would handle inbound transit packets carrying RA.

### §14.2 RFC 4861 ND for routers — Phase 2

**Adherence:** Phase 2 (RA emission, RS processing).

### §14.3 RFC 3315 DHCPv6 server — Phase 2

**Adherence:** Phase 2 (server-side DHCPv6 belongs to a
router-grade stack).

### §14.4 BCP 198 Prefix Length for Forwarding — Phase 2

**Adherence:** Phase 2 (no FIB today).

---

## §15 Constrained Devices — N/A

**Adherence:** N/A. PyTCP is not a constrained-device
profile (no 6LoWPAN, no RPL); applies as-stated.

---

## §16 Node Management — deferred

### §16.1 MIB Modules — deferred

**Adherence:** deferred. PyTCP exposes per-counter
telemetry via `PacketStatsRx` / `PacketStatsTx` for
operational observability (see `packages/pytcp/pytcp/lib/packet_stats.py`).
SNMP MIB integration is not implemented; would be a
deferred operational-tooling item.

### §16.2 YANG Data Models — deferred

**Adherence:** deferred. NETCONF / YANG integration is a
deferred operational-tooling item.

---

## Test coverage audit (§5.3 option-cap gate)

### §5.3 option-count cap

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc8504_ext_hdr_option_caps.py::TestIp6Rfc8504ExtHdrOptionCaps::test__ip6__rfc8504_5_3__option_count_cap_drops_packet`
  — drives an HBH with 22 consecutive Pad1 options and
  asserts the packet is dropped + the
  `ip6_hbh__option_cap_exceeded__drop` counter bumps once.

**Status:** locked in.

### §5.3 pad-byte cap

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc8504_ext_hdr_option_caps.py::TestIp6Rfc8504ExtHdrOptionCaps::test__ip6__rfc8504_5_3__pad_bytes_cap_drops_packet`
  — drives an HBH whose total Pad-byte budget (PadN data +
  trailing Pad1s) exceeds the cap; asserts drop + counter.

**Status:** locked in.

### §5.3 unknown-option cap

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc8504_ext_hdr_option_caps.py::TestIp6Rfc8504ExtHdrOptionCaps::test__ip6__rfc8504_5_3__unknown_count_cap_drops_packet`
  — drives an HBH carrying three unrecognized options
  (action-bit pattern "skip on unrecognized"); asserts
  drop + counter.

**Status:** locked in.

### §5.3 positive control (within caps)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rfc8504_ext_hdr_option_caps.py::TestIp6Rfc8504ExtHdrOptionCaps::test__ip6__rfc8504_5_3__within_caps_passes`
  — drives an HBH well under every cap and asserts the
  `cap_exceeded` counter does NOT bump while the parser
  runs to completion.

**Status:** locked in.

### Test coverage summary

| Aspect                                  | Coverage  |
|-----------------------------------------|-----------|
| §5.3 option-count cap (HBH RX)          | locked in |
| §5.3 pad-byte cap (HBH RX)              | locked in |
| §5.3 unknown-option cap (HBH RX)        | locked in |
| §5.3 positive control (within caps)     | locked in |
| §5.3 DestOpts RX cap-check parity       | covered by shared helper; positive HBH coverage exercises the same code path |

---

## Test coverage audit (deliberate-skip categories)

The deliberate-skip categories carry no implementation, so
they have no positive-path tests. They do appear, however,
as **excluded paths** in the test surface — the absence of
a code path means a regression that *added* one of these
features would be conspicuous in the diff.

| Skipped category   | Greppable absence                                          |
|--------------------|------------------------------------------------------------|
| IPsec AH / ESP     | No `IpProto.AH` / `IpProto.ESP` consumers — `IpProto.from_proto` would `assert False` on construction |
| SEND / CGA         | No `Icmp6NdOptionType.RSA_SIGNATURE` consumers              |
| MIPv6 RH2          | RH parser hard-drops RH0; RH2 falls into the unknown-routing-type ICMP path (per RFC 8200 §4.4) |
| mDNS / DNS-SD      | No application-layer code in `packages/pytcp/pytcp/`                       |
| Mobility (RFC 6275) | No mobility-aware ND options (RA Flags, Mobile IPv6 BU)    |

---

## Cross-references

- `CLAUDE.md` — "Project North Star" (deliberate-skip
  rationale)
- `docs/refactor/v6_remaining_items.md` — punch list for
  deferred items (this record reflects state through
  commit `d23d17bb`)
- `docs/rfc/ip6/rfc8200__ipv6/adherence.md` — RFC 8200 §4
  extension-header coverage (referenced by §5.1, §5.2)
- `docs/rfc/ip6/rfc5095__deprecate_rh0/adherence.md` —
  RH0 hard-drop coverage (referenced by §5.2)
- `docs/rfc/ip6/rfc8201__pmtud_ip6/` — RFC 8201 audit
  (referenced by §5.7.1)
