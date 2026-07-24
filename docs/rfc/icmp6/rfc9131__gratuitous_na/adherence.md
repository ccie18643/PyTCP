# RFC 9131 — Gratuitous Neighbor Discovery: Creating Neighbor Cache Entries on First-Hop Routers

| Field       | Value                                                                            |
|-------------|----------------------------------------------------------------------------------|
| RFC number  | 9131                                                                             |
| Title       | Gratuitous Neighbor Discovery: Creating Neighbor Cache Entries on First-Hop Routers |
| Category    | Standards Track (Updates RFC 4861)                                               |
| Date        | October 2021                                                                     |
| Source text | [`rfc9131.txt`](rfc9131.txt)                                                     |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 9131. The audit was performed by reading the RFC
text fresh and inspecting
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py`
plus `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** RFC 9131 §3 host-side gratuitous NA emission.
When a SLAAC (or static) address completes Duplicate Address
Detection successfully, the stack emits
`icmp6.gratuitous_na_count` unsolicited Neighbor
Advertisements (default 1) with the Override flag set to
all-nodes-multicast. Peers pre-populate their neighbour
cache for the new address; the time-to-first-packet after
host attachment drops dramatically.

The router-side surface (a forwarding router using
gratuitous NAs to pre-populate ITS neighbour cache for
known on-link hosts) is **deferred** to the Phase-2 router
track per CLAUDE.md Project North Star.

| Section | Topic                                              | Status |
|---------|----------------------------------------------------|--------|
| §1 / §2 | Background — proactive ND analog of gratuitous ARP | n/a (motivation)               |
| §3      | Host-side gratuitous NA on attachment              | met                            |
| §4      | Router-side gratuitous NA on cache population      | deferred (Phase-2 router track) |
| §5      | Security considerations                            | n/a (no new attack surface)    |

---

## §3 Host-Side Gratuitous Neighbor Advertisement

> "When a host attaches to a link and completes Duplicate
>  Address Detection for an address, the host SHOULD
>  transmit one or more unsolicited Neighbor
>  Advertisement messages to ff02::1 with the Override
>  flag set."

**Adherence:** met.
`send_icmp6_neighbor_advertisement_gratuitous` at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py:810-842`
emits the gratuitous NA:

```python
for _ in range(sysctl_iface.get_for_iface("icmp6.gratuitous_na_count", self._if._interface_name)):
    self.send_icmp6_neighbor_advertisement(
        ip6__src=ip6_unicast,
        ip6__dst=Ip6Address("ff02::1"),
        target_address=ip6_unicast,
        flag_s=False,    # unsolicited
        flag_o=True,     # Override — peers replace cache entry
        include_tlla=True,
    )
```

The DAD-success caller at
`packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3695-3700`
invokes the helper immediately after the DAD slot
declares the address VALID:

```python
# RFC 9131 §3 — gratuitous Neighbor Advertisement(s)
# announce that the candidate is now in use; count
# tunable via 'icmp6.gratuitous_na_count' (default 1;
# 0 disables).
self.send_icmp6_neighbor_advertisement_gratuitous(ip6_unicast=ip6_unicast_candidate)
```

The wire form satisfies §3:

- Target Address = the newly-claimed address.
- Source Address = the same (this is "for myself").
- Destination = `ff02::1` (all-nodes link-local
  multicast — every on-link host hears it).
- Override flag (O) = True — receivers replace any cache
  entry they may have for this address from a previous
  holder.
- Solicited flag (S) = False — unsolicited NA.
- TLLA option = the host's MAC (so peers can pre-populate
  the IP→MAC mapping without first running ND).

> "The host MAY emit more than one gratuitous NA to defend
>  against packet loss."

**Adherence:** met. The `ICMP6__GRATUITOUS_NA_COUNT`
sysctl (default 1) controls the emit count. Operators on
lossy links can bump it to 2 or 3.

---

## §3 Operator Knob

> "Implementations SHOULD provide an operator-tunable
>  knob to enable / disable gratuitous NA on attachment."

**Adherence:** met. The `icmp6.gratuitous_na_count`
sysctl (declared in
`packages/pytcp/pytcp/protocols/icmp6/nd/nd__constants.py`) is the
on/off + emit-count knob. Setting it to 0 disables
gratuitous NA emission entirely; the DAD-success path
falls through the helper's for-loop trivially without
emitting anything.

---

## §4 Router-Side Gratuitous NA (Phase-2 Router)

> "Routers SHOULD process inbound gratuitous NAs to
>  pre-populate their neighbour cache when the host
>  attaches, eliminating the first-packet ND latency."

**Adherence:** deferred (Phase-2 router track). PyTCP is
a host stack today; the forwarder is part of the eventual
router-grade work per CLAUDE.md Project North Star §Phase
2. The RX-side inbound NA path
(`__phrx_icmp6__nd_neighbor_advertisement`) already
processes unsolicited NAs and updates the ND cache when
the Override flag is set; what's missing is the
router-specific behaviour of registering the entry as a
forwarding-table neighbour without waiting for a host-
initiated NS exchange.

---

## §5 Security Considerations

> "Gratuitous NA does not introduce new attack surface
>  beyond standard unsolicited NA (RFC 4861)."

**Adherence:** n/a. The unsolicited NA RX path is the
same one used by RFC 4861 §7.2.5; any anti-spoofing
defence applied there (SEND, IPv6 ND inspection) covers
gratuitous NAs equally.

---

## Test coverage audit

### §3 Host-side gratuitous NA wire shape

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp6__tx.py::TestPacketHandlerIcmp6TxGratuitousNa::test__stack__packet_handler__icmp6__tx__gratuitous_na__default_count_emits_one`
  — invokes the helper and asserts the gratuitous NA
  appears with the correct wire shape (target = address,
  dst = ff02::1, flag_o = True, flag_s = False, TLLA
  option present).

**Status:** locked in (helper).

### §3 Emit-count sysctl (multi-emit + on/off)

- **Unit:** the same
  `TestPacketHandlerIcmp6TxGratuitousNa` class covers the
  count knob:
  `..._gratuitous_na__sysctl_override_emits_three`
  (`icmp6.gratuitous_na_count = 3` emits three) and
  `..._gratuitous_na__sysctl_count_zero_emits_none`
  (`= 0` kill-switch suppresses emission).

**Status:** locked in (helper).

### §3 DAD-success trigger wiring

The DAD-success caller
(`packet_handler/__init__.py:3700`) that invokes the helper
after an address is declared VALID has **no dedicated
integration test** asserting a gratuitous NA appears on the
wire at the end of a full DAD run; the trigger wiring is
covered only indirectly.

**Status:** gap (trigger not directly pinned).

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Gratuitous NA emission (helper)                     | locked in |
| Wire shape (target / dst / flags / TLLA)            | locked in |
| Emit-count sysctl (0 = disable; N = emit N times)   | locked in |
| DAD-success trigger fires the helper                | gap (not directly pinned) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §3 Host-side gratuitous NA on DAD success             | met    |
| §3 Override flag set, all-nodes destination, TLLA     | met    |
| §3 Multi-emit count (operator-tunable)                | met    |
| §3 Sysctl on/off knob                                 | met (`icmp6.gratuitous_na_count`) |
| §4 Router-side cache pre-population                   | deferred (Phase-2 router) |
| §5 Security considerations                            | n/a (no new attack surface) |

PyTCP fully ships the RFC 9131 host-side surface. Phase-2
router work will add the forwarder's RX-side
cache-pre-population logic when the forwarding plane
lands.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` —
  parent classification.
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record; unsolicited NA RX path lives there.
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` — DAD
  path that triggers the gratuitous NA emit.
- IPv4 parallel: `docs/rfc/arp/rfc5227__ipv4_acd/adherence.md`
  §2.3 (gratuitous ARP Announcement after DAD).
- Source: `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py:810-842`
  (`send_icmp6_neighbor_advertisement_gratuitous`),
  `packages/pytcp/pytcp/runtime/packet_handler/__init__.py:3695-3700`
  (DAD-success trigger).
