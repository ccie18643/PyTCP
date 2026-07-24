# RFC 826 — An Ethernet Address Resolution Protocol

| Field       | Value                                                                                |
|-------------|--------------------------------------------------------------------------------------|
| RFC number  | 826                                                                                  |
| Title       | An Ethernet Address Resolution Protocol                                              |
| Category    | Internet Standard (STD 37)                                                           |
| Date        | November 1982                                                                        |
| Updated by  | RFC 5227 (IPv4 ACD), RFC 5494 (IANA registry rules)                                  |
| Source text | [`rfc826.txt`](rfc826.txt)                                                           |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement in RFC 826.
The audit was performed by reading the RFC text fresh and
inspecting the codebase under `packages/net_proto/net_proto/protocols/arp/`,
`packages/pytcp/pytcp/protocols/arp/arp__cache.py`,
`packages/pytcp/pytcp/lib/neighbor.py`, and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__{rx,tx}.py`
directly. Adherence levels use the canonical descriptive
language: **met**, **not met**, **partial**, **not implemented**,
**vacuous**.

RFC 826 contains substantial historical / motivational prose
(Abstract, "The Problem", "Motivation", "Why is it done this
way??", "Network monitoring and debugging", "An Example",
"Related issue") that carries no normative requirements; those
sections are summarised here only insofar as the surrounding
narrative defines a normative statement, and the audit body
focuses on the wire format and the Packet Generation / Packet
Reception algorithms.

The probe / announce / conflict-detection / address-defense
extensions on top of RFC 826 are audited in
[`../rfc5227__ipv4_acd/adherence.md`](../rfc5227__ipv4_acd/adherence.md).
The IANA allocation rules for the wire-format fields are
audited in
[`../rfc5494__arp_iana/adherence.md`](../rfc5494__arp_iana/adherence.md).
Host-side ARP cache requirements (RFC 1122 §2.3.2) are
audited in
[`../rfc1122__host_requirements_arp/adherence.md`](../rfc1122__host_requirements_arp/adherence.md).

---

## Definitions — opcode and hardware-type values

> "Define the following values: `ares_op$REQUEST` (= 1, high
> byte transmitted first) and `ares_op$REPLY` (= 2), and
> `ares_hrd$Ethernet` (= 1)."

**Adherence:** **met**. PyTCP defines `ArpOperation.REQUEST =
0x0001` and `ArpOperation.REPLY = 0x0002`
(`packages/net_proto/net_proto/protocols/arp/arp__enums.py:49-50`); it defines
`ArpHardwareType.ETHERNET = 0x0001`
(`packages/net_proto/net_proto/protocols/arp/arp__enums.py:41`). Both enums
inherit `ProtoEnumWord`, giving big-endian 16-bit wire
encoding ("high byte transmitted first").

---

## Packet format — wire layout

> "Ethernet packet data:
>  16.bit: (ar$hrd) Hardware address space ...
>  16.bit: (ar$pro) Protocol address space ...
>   8.bit: (ar$hln) byte length of each hardware address
>   8.bit: (ar$pln) byte length of each protocol address
>  16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
>  nbytes: (ar$sha) Hardware address of sender ...
>  mbytes: (ar$spa) Protocol address of sender ...
>  nbytes: (ar$tha) Hardware address of target ...
>  mbytes: (ar$tpa) Protocol address of target."

**Adherence:** **met**. The on-the-wire layout is fixed at 28
bytes for Ethernet/IPv4 ARP:
`ARP__HEADER__LEN = 28`
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:67`),
`ARP__HEADER__STRUCT = "! HH BBH 6s L 6s L"`
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:68`). The struct
format pins big-endian (`!`) byte order. Field lengths in
the struct match the RFC: 2-byte hrtype, 2-byte prtype,
1-byte hrlen, 1-byte prlen, 2-byte oper, 6-byte sha (Ethernet
MAC), 4-byte spa (IPv4), 6-byte tha, 4-byte tpa.

> "Numbers here are in the Ethernet standard, which is high
> byte first."

**Adherence:** **met**. The leading `!` in
`ARP__HEADER__STRUCT` enforces network (big-endian) byte
order on every pack/unpack
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:68,135-148,159`).

> "There are no padding bytes between addresses."

**Adherence:** **met**. The struct `! HH BBH 6s L 6s L`
contains no padding bytes; total = 2+2+1+1+2+6+4+6+4 = 28
bytes, matching `ARP__HEADER__LEN`.

---

## Packet Generation — sender constructs an ARP Request

> "If it does not [find the pair in the table], it probably
> informs the caller that it is throwing the packet away (on
> the assumption the packet will be retransmitted by a higher
> network layer), and generates an Ethernet packet with a
> type field of `ether_type$ADDRESS_RESOLUTION`."

**Adherence:** **met**. On a cache miss the Ethernet TX path
enqueues the outbound packet onto the INCOMPLETE neighbour
entry's bounded pending queue (`ArpCache.enqueue_pending`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py:306,337`)
and the NUD state machine fires an ARP Request solicit via
`send_arp_request()`
(`packages/pytcp/pytcp/protocols/arp/arp__cache.py:167-186` →
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:167-193`).
The RFC's "informs the caller that it is throwing the packet
away" clause is satisfied — and PyTCP additionally **saves**
the packet and retransmits it once the MAC resolves, so RFC
1122 §2.3.2.2's SHOULD is also met (see
[`../rfc1122__host_requirements_arp/adherence.md`](../rfc1122__host_requirements_arp/adherence.md)).
The Ethernet type field on outbound ARP frames resolves
via `EtherType.from_proto(ArpAssembler) = EtherType.ARP =
0x0806` (the runtime
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`
selects EtherType from the payload class).

> "The Address Resolution module then sets the ar$hrd field
> to `ares_hrd$Ethernet`, ar$pro to the protocol type that
> is being resolved, ar$hln to 6 ..., ar$pln to the length
> of an address in that protocol, ar$op to `ares_op$REQUEST`,
> ar$sha with the 48.bit ethernet address of itself, ar$spa
> with the protocol address of itself, and ar$tpa with the
> protocol address of the machine that is trying to be
> accessed."

**Adherence:** **met**. The `ArpHeader` dataclass forces
hrtype/prtype/hrlen/prlen via `field(init=False, default=...)`
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:77-96`), so any
caller-constructed Request gets the correct
ETHERNET/IP4/6/4 quadruplet. `send_arp_request()` populates
sha = our MAC, spa = our first IP (or `0.0.0.0` if none
claimed yet), tpa = caller's target, and tha = `MacAddress()`
(unspecified)
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:167-193`).

> "It does not set ar$tha to anything in particular, because
> it is this value that it is trying to determine. It could
> set ar$tha to the broadcast address for the hardware (all
> ones in the case of the 10Mbit Ethernet) if that makes it
> convenient for some aspect of the implementation."

**Adherence:** **met**. PyTCP sets `arp__tha = MacAddress()`
(unspecified, all-zeroes) on outbound Requests
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:179,227`
across `send_arp_request` and `send_arp_unicast_request`).
This is the more-specified of the two RFC-permitted choices
and aligns with Linux's ARP code.

> "It then causes this packet to be broadcast to all stations
> on the Ethernet cable originally determined by the routing
> mechanism."

**Adherence:** **met**. `send_arp_request` sets `ethernet__dst
= MacAddress(0xFFFFFFFFFFFF)` (FF:FF:FF:FF:FF:FF) on the
outbound Ethernet frame
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:175`).
The cache-refresh probe (`send_arp_unicast_request`) is the
one deliberate exception — it addresses the frame to the
cached neighbour MAC (unicast) rather than broadcasting; see
the "Related issue" section below.

---

## Packet Reception — algorithm

> "?Do I have the hardware type in ar$hrd? Yes: (almost
> definitely) [optionally check the hardware length ar$hln]
> ?Do I speak the protocol in ar$pro? Yes: [optionally check
> the protocol length ar$pln] ..."

**Adherence:** **met**. Integrity checks reject any frame
that does not match the Ethernet/IPv4 quadruplet:
- `hrtype != ETHERNET` → `ArpIntegrityError`
  (`packages/net_proto/net_proto/protocols/arp/arp__parser.py:87-88`)
- `prtype != IP4` → `ArpIntegrityError`
  (`packages/net_proto/net_proto/protocols/arp/arp__parser.py:91-92`)
- `hrlen != 6` → `ArpIntegrityError`
  (`packages/net_proto/net_proto/protocols/arp/arp__parser.py:95-96`)
- `prlen != 4` → `ArpIntegrityError`
  (`packages/net_proto/net_proto/protocols/arp/arp__parser.py:99-100`)

The "Negative conditionals indicate an end of processing and
a discarding of the packet" rule is observed: integrity
errors bump `arp__failed_parse__drop` and return without
generating a reply
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:66-74`).

> "Merge_flag := false. If the pair <protocol type, sender
> protocol address> is already in my translation table,
> update the sender hardware address field of the entry with
> the new information in the packet and set Merge_flag to
> true."

**Adherence:** **partial**. The cache merge happens
unconditionally at the end of `__phrx_arp__request` and
`__phrx_arp__reply` via `__update_arp_cache`
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:91-130,243-246,288`),
but the call is **gated** by three conditions:
1. `packet_rx.arp.spa in host.network` (the sender IP must
   belong to one of our local subnets);
2. `packet_rx.ethernet.dst == self._mac_unicast` or
   `packet_rx.ethernet.dst.is_broadcast` (we must be the
   intended L2 destination, not promiscuously sniffing);
3. `packet_rx.arp.spa not in self._ip4_unicast` (anti-spoof:
   never accept a learn for one of our own addresses).

This is **stricter than RFC 826**, which merges before
checking opcode unconditionally if the receiver "speaks the
protocol". The deviation is **deliberate, Linux-aligned**:
default Linux drops cache learns from packets received in
promiscuous mode and from packets whose SPA does not match
a local subnet (the `arp_accept` / `arp_announce` /
`arp_filter` family of sysctls in `net/ipv4/devinet.c` and
`net/ipv4/arp.c`). PyTCP encodes the conservative default.
The `Merge_flag` itself is not represented as an explicit
boolean — the code path simply re-enters `add_entry`, which
routes to `NeighborCache._add_entry` and overwrites the
entry's MAC
(`packages/pytcp/pytcp/lib/neighbor.py:246-293`).

> "?Am I the target protocol address? Yes: If Merge_flag is
> false, add the triplet <protocol type, sender protocol
> address, sender hardware address> to the translation
> table."

**Adherence:** **partial**. PyTCP tests
`packet_rx.arp.tpa in self._ip4_unicast` to gate the
Reply path and distinguishes "TPA matches us" from "TPA is
unknown"
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:169-246`),
but the cache merge in `__update_arp_cache` runs for both
branches (the merge does not require "I am the target"). RFC
826's algorithm only merges on the "Am I the target?" path
when `Merge_flag` is false — so PyTCP's merge happens *more*
often than the RFC strictly mandates (any spa-in-local-subnet
ARP packet directed at our MAC or broadcast). This is again
Linux-aligned (the host learns from any ARP packet on its
local subnet to keep caches warm, not just packets directed
at it). The strict-RFC reading would omit cache learns from
ARP requests targeting other hosts; PyTCP and Linux both
prefer the cache-warming behaviour.

> "?Is the opcode `ares_op$REQUEST`? (NOW look at the
> opcode!!) Yes: Swap hardware and protocol fields, putting
> the local hardware and protocol addresses in the sender
> fields. Set the ar$op field to `ares_op$REPLY`. Send the
> packet to the (new) target hardware address on the same
> hardware on which the request was received."

**Adherence:** **met**. The Reply is composed by
`_send_arp_reply()` with the swap encoded explicitly:
`arp__sha=self._mac_unicast` (our MAC), `arp__spa=<the
incoming tpa>` (our IP that was being asked about),
`arp__tha=<the incoming sha>` (requester's MAC),
`arp__tpa=<the incoming spa>` (requester's IP)
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:237-241`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:131-166`).
The Reply uses `arp__oper=ArpOperation.REPLY` and is unicast
back to the requester (`ethernet__dst=arp__tha`). The
"on the same hardware on which the request was received"
clause is vacuous in PyTCP's single-interface stack.

> "Notice that the <protocol type, sender protocol address,
> sender hardware address> triplet is merged into the table
> before the opcode is looked at."

**Adherence:** **met (semantically)**. PyTCP's RX flow
inspects `oper` first to dispatch
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__rx.py:79-89`)
and the cache merge is performed at the bottom of each
`__phrx_arp__{request,reply}` call before the function
returns, but in both branches the merge runs
unconditionally (subject to the three filters above) and
the same `__update_arp_cache` helper is reused. The
"bidirectional communication" assumption that motivates the
RFC (if A talks to B, B will probably want to talk to A) is
preserved.

---

## Replies and table updates

> "Notice also that if an entry already exists for the
> <protocol type, sender protocol address> pair, then the
> new hardware address supersedes the old one."

**Adherence:** **met**. `ArpCache.add_entry()` routes to
`NeighborCache._add_entry`, which overwrites the entry's
`mac_address` and transitions it to `NUD_REACHABLE`
(`packages/pytcp/pytcp/protocols/arp/arp__cache.py:113-125` →
`packages/pytcp/pytcp/lib/neighbor.py:246-293`) — so a fresher
SHA overrides the stale one immediately.

---

## Generalisation

> "The ar$hrd and ar$hln fields allow this protocol and
> packet format to be used for non-10Mbit Ethernets. For
> the 10Mbit Ethernet <ar$hrd, ar$hln> takes on the value
> <1, 6>."

**Adherence:** **met (single hardware type)**. PyTCP
implements only `<ar$hrd, ar$hln> = <1, 6>` (Ethernet); the
parser rejects every other hardware type as an integrity
error
(`packages/net_proto/net_proto/protocols/arp/arp__parser.py:87-88,95-96`).
RFC 5494 §3 marks `0` and `65535` as reserved; PyTCP rejects
them as part of the "must equal ETHERNET = 1" check.
Non-Ethernet hardware (Packet Radio, FDDI, ATM, etc.) is
out of scope per the project North Star.

> "For other hardware networks, the ar$pro field may no
> longer correspond to the Ethernet type field, but it
> should be associated with the protocol whose address
> resolution is being sought."

**Adherence:** **vacuous**. PyTCP supports only
`<ar$hrd, ar$pro> = <ETHERNET, IP4>`; the protocol field is
hard-locked via `field(init=False, default=EtherType.IP4)`
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:82-86`).

---

## Hardware authority

> "An agreed upon authority is needed to manage hardware
> name space values."

**Adherence:** **met (consumes IANA registry)**. PyTCP's
`ArpHardwareType` enum sources its lone defined value
(`ETHERNET = 0x0001`) from the IANA registry. RFC 5494 now
governs the registry rules; see the RFC 5494 audit.

---

## Length-field consistency

> "In theory, the length fields (ar$hln and ar$pln) are
> redundant, since the length of a protocol address should
> be determined by the hardware type ... and the protocol
> type. It is included for optional consistency checking,
> and for network monitoring and debugging."

**Adherence:** **met**. PyTCP performs the optional
consistency check at `arp__parser.py:95-100`: a frame whose
`hrlen != 6` or `prlen != 4` is rejected as
`ArpIntegrityError`. Wire-emitted frames hard-set both
fields via `field(init=False, default=...)` so they cannot
desync from `hrtype` / `prtype`.

---

## Reply-form fields (informational sanity)

> "The target protocol address is necessary in the request
> form ... It is not necessarily needed in the reply form
> if one assumes a reply is only provoked by a request."

**Adherence:** **met**. PyTCP populates `tpa` on outbound
Replies (`_send_arp_reply` sets `arp__tpa=<the requester's
spa>`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:151`),
matching the RFC's "included for completeness".

> "The target hardware address is included for completeness
> and network monitoring. It has no meaning in the request
> form, since it is this number that the machine is
> requesting. Its meaning in the reply form is the address
> of the machine making the request."

**Adherence:** **met**. PyTCP sets `tha = MacAddress()`
(unspecified) on outbound Requests and `tha =
<requester's sha>` on outbound Replies; the wire form
matches the RFC narrative
(`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:179,227`
for `send_arp_request` / `send_arp_unicast_request`;
`:150` for `_send_arp_reply`).

---

## Sanity checks — RFC backing

PyTCP's `_validate_sanity` enforces invariants that fall under
several RFCs other than 826 plus one PyTCP-only hardening
rule. Each check below cites the canonical source:

- **`oper` must be REQUEST or REPLY.** RFC 826 *Definitions*
  (only `ares_op$REQUEST=1` and `ares_op$REPLY=2` are defined
  for IPv4 ARP); RFC 5494 §3 marks `oper=0` and `oper=65535`
  as reserved. Unknown opcodes raise `ArpSanityError`
  (`packages/net_proto/net_proto/protocols/arp/arp__parser.py`).
- **`sha` must not be unspecified / multicast / broadcast.**
  RFC 826 *Packet Generation* "ar$sha with the 48.bit
  ethernet address of itself"; RFC 5227 §1.1 reinforces "MUST
  contain the hardware address of the interface sending the
  packet"; IEEE 802.3 forbids the all-zeros, group-bit-set,
  or all-ones MAC as a unicast source.
- **REPLY `spa` must not be unspecified.** RFC 5227 §1.1 —
  `spa=0.0.0.0` is reserved for ARP Probes (Request form
  only); a Reply with `spa=0.0.0.0` is malformed.
- **`spa` must not be loopback / multicast / limited
  broadcast.** RFC 1122 §3.2.1.3 — a sender's IPv4 source
  address MUST NOT be 127/8, 224/4, or 255.255.255.255.
- **`tpa` must not be multicast / limited broadcast.**
  RFC 1112 §6.4 — IPv4 multicast resolves algorithmically
  to `01:00:5e:xx:xx:xx`, bypassing ARP entirely. Limited
  broadcast resolves to `ff:ff:ff:ff:ff:ff` directly. Neither
  is ever a legitimate ARP target. **Stricter than Linux**,
  which does not filter these at `arp_rcv`.

The RFC-backed checks above are normative under their cited
RFCs even though RFC 826 itself is silent on the point. The
two PyTCP-only hardenings (`tpa.is_multicast` and
`tpa.is_limited_broadcast`) are explicit local policy and are
documented as such in the parser source.

A previous PyTCP-only check that required ARP `sha` to equal
the parent Ethernet `src` was removed (commit on the
`PyTCP_3_0_6` branch): it was not RFC-normative, Linux's
`net/ipv4/arp.c::arp_rcv` does not enforce it, and the value
of catching cross-layer MAC drift is more naturally a
receiver-policy concern than a parser-level invariant.

---

## "Related issue" — table aging and timeouts

> "It may be desirable to have table aging and/or timeouts.
> The implementation of these is outside the scope of this
> protocol."

**Adherence:** **met (in scope of RFC 1122)**. RFC 826
explicitly defers aging to the implementation. PyTCP
implements timer-driven aging in the generic NUD state
machine `NeighborCache._subsystem_loop`
(`packages/pytcp/pytcp/lib/neighbor.py:406`), which the
IPv4 `ArpCache` adapter extends
(`packages/pytcp/pytcp/protocols/arp/arp__cache.py:49`).
The aging cadence is governed by the runtime-tunable
`neighbor.*` sysctls — `neighbor.reachable_time` (default
30 s), `neighbor.delay_first_probe_time` (default 5 s),
`neighbor.retrans_timer` (default 1 s), and
`neighbor.max_unicast_solicit` / `neighbor.max_multicast_solicit`
(default 3) — registered in
`packages/pytcp/pytcp/lib/neighbor__constants.py`. (The former
static `stack.ARP__CACHE__ENTRY_MAX_AGE` /
`ARP__CACHE__ENTRY_REFRESH_TIME` constants were removed when
ARP moved onto the shared NUD cache.) The full audit of the
host-requirements layer (RFC 1122 §2.3.2) lives at
[`../rfc1122__host_requirements_arp/adherence.md`](../rfc1122__host_requirements_arp/adherence.md).

> "Another alternative is to have a daemon perform the
> timeouts. After a suitable time, the daemon considers
> removing an entry. It first sends ... an address
> resolution packet with opcode REQUEST directly to the
> Ethernet address in the table. If a REPLY is not seen in
> a short amount of time, the entry is deleted."

**Adherence:** **met**. This is exactly PyTCP's NUD
unicast-probe path. When a `REACHABLE` entry's
`reachable_time` elapses it transitions to `STALE`; on next
use it enters `DELAY` and, after `delay_first_probe_time`,
`PROBE`. In the `PROBE` state the state machine fires a
**unicast** ARP Request addressed directly to the cached MAC
— not a broadcast — retransmitting every `retrans_timer`
until `max_unicast_solicit` is exhausted, at which point the
entry is dropped to `FAILED`
(`packages/pytcp/pytcp/lib/neighbor.py:475-482` →
`ArpCache._solicit_arp`,
`packages/pytcp/pytcp/protocols/arp/arp__cache.py:181-186`
`send_arp_unicast_request(ethernet__dst=cached_mac)` →
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__tx.py:195-241`).
This matches Linux's unicast-poll form (RFC 1122 §2.3.2.1
IMPLEMENTATION (2) "Unicast Poll").

---

## Test coverage audit

### Wire format / `ArpHeader` dataclass

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__header__asserts.py::TestArpHeaderAsserts`
  — asserts that every field rejects a wrong type
  (`oper`, `sha`, `spa`, `tha`, `tpa`).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__header__asserts.py::TestArpHeaderDefaults::test__arp__header__hrtype_default`
  / `..._prtype_default` / `..._hrlen_default` /
  `..._prlen_default` — asserts the four `field(init=False,
  default=...)` constants.
- **Unit:**
  `..._hrtype_cannot_be_overridden` — asserts the
  hard-locked field cannot be passed as a kwarg.
- **Unit:**
  `..._buffer_protocol` — asserts `bytes(header)` equals
  the wire layout for both REQUEST and REPLY.
- **Unit:**
  `..._from_buffer_roundtrip` — asserts
  `ArpHeader.from_buffer(bytes(header)) == header` (full
  pack/unpack).
- **Unit:**
  `..._is_frozen` / `..._is_hashable` — asserts the
  dataclass invariants used by the cache.

**Status:** **locked in**.

### Integrity checks (RFC 826 hardware/protocol-type guards)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__parser__integrity_checks.py::TestArpParserIntegrityChecks::test__arp__parser__integrity_error`
  — parametrised matrix of `hrtype != ETHERNET`,
  `prtype != IP4`, `hrlen != 6`, `prlen != 4`, and
  `len(frame) < ARP__HEADER__LEN`. Each case asserts
  `ArpIntegrityError` is raised with the canonical message.
- **Unit:**
  `..._minimum_length_accepted` — asserts the boundary
  case (28-byte frame) parses cleanly.

**Status:** **locked in**.

### Sanity checks — RFC backing

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__parser__sanity_checks.py::TestArpParserSanityChecks::test__arp__parser__sanity_error`
  — parametrised matrix covering every `_validate_sanity`
  branch: unknown opcode (RFC 826 / 5494 §3); sha =
  unspecified / multicast / broadcast (RFC 826 + 5227 §1.1 +
  IEEE 802.3); reply with spa = unspecified (RFC 5227 §1.1);
  spa = loopback / multicast / limited-broadcast (RFC 1122
  §3.2.1.3); tpa = multicast / limited-broadcast (RFC 1112
  §6.4).
- **Unit:**
  `..._sanity__valid_reply_parses_cleanly` /
  `..._sanity__request_with_unspecified_spa_allowed` /
  `..._sanity__sha_mismatch_with_ethernet_src_allowed` —
  happy-path coverage: valid Reply parses; ARP Probe with
  spa=0.0.0.0 parses (RFC 5227 §1.1); ARP frame whose sha
  differs from the parent Ethernet src parses (regression net
  against re-introducing the dropped PyTCP-only hardening).

**Status:** **locked in**.

### Packet Reception — Request handling (algorithm body)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__rx.py::TestArpRx`
  — parametrised matrix covering: unknown TPA on local
  network (drop, no reply); unknown TPA off-network
  (drop); unsupported opcode (drop, parse-time gate);
  request for stack MAC broadcast (reply + cache update);
  request for stack MAC unicast (reply + cache update);
  request with SHA = `00:00:00:00:00:00` (drop); probe
  (SPA = `0.0.0.0`) (reply + no cache learn for our IP);
  request from a foreign SPA for our IP (reply, no cache
  learn); looped frames sourced from our own MAC (drop).
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__regular_request_replies_and_updates_cache`
  — asserts the Reply field swap (`arp__sha = our MAC`,
  `arp__spa = our IP`, `arp__tha = requester's SHA`,
  `arp__tpa = requester's SPA`).

**Status:** **locked in**.

### Packet Reception — Reply handling

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__rx.py::TestArpRx`
  — Reply matrix: looped reply (drop), direct reply (cache
  update), gratuitous reply (cache update with SPA == TPA on
  local subnet), gratuitous reply on a foreign subnet (no
  cache update), broadcast non-gratuitous reply (cache update
  only).
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py::TestPacketHandlerArpRxReply::test__stack__packet_handler__arp__rx__reply_direct_updates_cache`
  — asserts the cache learn for a direct unicast reply.

**Status:** **locked in**.

### Cache merge gates (Linux-aligned deviation)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest::test__stack__packet_handler__arp__rx__regular_request_replies_and_updates_cache`
  — happy path covers the in-subnet learn.
- **Unit:**
  the various probe / gratuitous / looped tests above
  exercise the negative branches (do-not-learn) of the
  three gating conditions.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheAddEntry::test__lib__neighbor__add_entry_transitions_incomplete_to_reachable`
  — pins that `add_entry` installs the SHA (`NUD_REACHABLE`),
  so a fresher mapping supersedes the old one.

**Status:** **locked in**.

### Packet Generation — Request, Reply, and broadcast destination

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__tx.py::TestArpTx`
  — asserts both Request (broadcast resolution lookup) and
  Reply (unicast direct response) produce wire-correct
  frames.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/arp/test__arp__tx.py::TestArpTxHelpers`
  — convenience-helper matrix over `_send_arp_reply` and
  `send_arp_request`, asserting the exact wire bytes for
  each.

**Status:** **locked in**.

### Aging / refresh / expiry

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCachePermanent::test__lib__neighbor__permanent_skips_all_aging`
  — asserts permanent entries are not aged.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheProbeToFailed::test__lib__neighbor__probe_transitions_to_failed_after_max_unicast_solicit`
  — asserts an entry that exhausts `max_unicast_solicit`
  probes is dropped to `FAILED`.
- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__neighbor.py::TestNeighborCacheDelayToProbe::test__lib__neighbor__delay_transitions_to_probe_after_delay_first_probe_time`
  — asserts a `DELAY` entry crosses into `PROBE` after
  `delay_first_probe_time` and fires a unicast refresh
  solicit.

**Status:** **locked in**.

### Test coverage summary

| Aspect                                       | Coverage                                                       |
|----------------------------------------------|----------------------------------------------------------------|
| Wire format (28-byte Ethernet/IPv4 layout)   | locked in                                                      |
| Hardware / protocol type guards (integrity)  | locked in                                                      |
| Sanity guards beyond RFC 826                 | locked in                                                      |
| Request handling — algorithm body            | locked in                                                      |
| Reply handling                               | locked in                                                      |
| Cache merge with Linux-aligned filters       | locked in                                                      |
| Packet Generation — Request / Reply / probe  | locked in                                                      |
| Aging / refresh / expiry                     | locked in                                                      |
| RFC 1122 §2.3.2.2 packet-queue (one packet)  | n/a (gap not closed; covered by RFC 1122 audit)                |

---

## Overall assessment

| Aspect                                 | Status                                              |
|----------------------------------------|-----------------------------------------------------|
| Wire format (header layout, byte order)| met                                                 |
| Hardware-type / protocol-type guards   | met (Ethernet / IPv4 only; non-Ethernet out of scope) |
| Length fields (`hrlen`, `prlen`)       | met (consistency check + hard-set on emit)          |
| Packet Generation — Request            | met                                                 |
| Packet Generation — Reply              | met                                                 |
| Packet Reception — algorithm body      | met (Linux-aligned cache-merge gating)              |
| "Merge before checking opcode"         | met (semantically; merge happens before return)     |
| Aging / table refresh (suggested)      | met (broadcast refresh; unicast variant deferred)   |
| Drop-the-original-packet on miss       | partial — see RFC 1122 §2.3.2.2                     |

The PyTCP ARP implementation is faithful to the RFC 826
algorithm with two deliberate, Linux-aligned deviations:

1. **The cache merge in `__update_arp_cache` is gated by
   three filters** (sender-IP-in-local-subnet, frame
   addressed to us or broadcast, sender-IP not one of
   ours). RFC 826's bare algorithm merges unconditionally
   if the receiver "speaks the protocol." Linux applies an
   even stricter set of filters via `arp_accept` /
   `arp_announce` / `arp_filter` / `arp_ignore`
   (`net/ipv4/arp.c`); PyTCP encodes a conservative
   default. CLAUDE.md "Linux-as-tiebreaker" applies.
2. **Cache refresh near expiry uses broadcast Requests
   instead of unicast probes.** RFC 826's "Related issue"
   suggests unicast probes only as one alternative; the
   broadcast form is correct but louder on the wire.

Neither deviation is silent — both are visible from
`packet_handler__arp__rx.py::__update_arp_cache` and
`arp_cache.py::_subsystem_loop` respectively, and both
have unit-test coverage.

The principal RFC-826-adjacent gap is the discarded-on-miss
packet (the RFC's "throwing the packet away" sentence is
satisfied, but RFC 1122 §2.3.2.2's SHOULD that one such
packet be **saved** and retransmitted post-resolution is
not). That gap is an RFC 1122 issue and is detailed in
that audit, not duplicated here.
