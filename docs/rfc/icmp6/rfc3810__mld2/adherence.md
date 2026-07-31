# RFC 3810 — Multicast Listener Discovery Version 2 (MLDv2)

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 3810                                               |
| Title       | Multicast Listener Discovery Version 2 (MLDv2)     |
| Category    | Standards Track                                    |
| Date        | June 2004                                          |
| Source text | [`rfc3810.txt`](rfc3810.txt)                       |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 3810 (MLDv2 — IPv6 multicast listener-side and
querier-side protocol). The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__icmp6__{rx,tx}.py`
plus `packages/net_proto/net_proto/protocols/icmp6/` directly.

MLDv2 has two roles: **listener** (every host that joins a
non-trivial IPv6 multicast group) and **querier** (typically
one multicast-aware router per link). PyTCP is a host stack:

- **Listener role**: PyTCP emits Reports when its multicast
  group membership changes; this lets the local querier
  learn what groups are interested on this link.
- **Querier role**: MLDv2 querier met (Phase-2 M5d — emission + election + membership); MLDv1 querier interop is M5e
  Project North Star (router-grade parity). A Phase-1 host
  has no need to send Queries.

Sections without normative content — Abstract, §1
Introduction, §2 Terminology (informational definitions),
§9 References, §10 Authors' Addresses, §11 IANA, §12
Security boilerplate — are omitted.

Adherence levels: **met**, **partial**, **not implemented**,
**deferred (Phase 2 router)**, **n/a**.

---

## Top-line adherence

PyTCP **meets** the MLDv2 listener-role requirements that
matter for a host stack: it emits Reports when group
membership changes, wraps Reports in a Hop-by-Hop header
carrying the RFC 2711 Router Alert option (value = MLD),
sets Hop Limit = 1 per §5.2.13, sources from a link-local
address per §5.2.13, and sends to the all-MLDv2-routers
group `ff02::16`. Full **source-specific multicast (SSM)**
is implemented on the listener side: per-socket INCLUDE /
EXCLUDE source filters (the `MCAST_JOIN_SOURCE_GROUP` family
via `stack.membership6`), the §6.1 merge into per-interface
reception state, source-bearing state-change Reports
(`ALLOW_NEW_SOURCES` / `BLOCK_OLD_SOURCES` / `CHANGE_TO_*`)
with §9.1 robustness retransmission, and the §4.1 data-plane
source-delivery gate for UDP and RAW receive.

The **MLDv2 querier role** is met as of Phase-2 M5d: an
interface with `mld.mc_forwarding` set emits General Queries
(startup burst then steady state), runs the §7.6.2 election
(step down on a lower-source Query, resume on Other Querier
Present expiry), and learns downstream reception state from
inbound Reports into a per-group membership table (§7.4),
pruned by the §9.4 Multicast Address Listening Interval. The
MLDv1 querier interop (older-version-querier compat +
fast-leave Multicast-Address-Specific Queries) is Phase-2
M5e. See the §7 / §8 section below.

| Section | Topic                                          | Status |
|---------|------------------------------------------------|--------|
| §4 wire | Query (type 130) wire format                   | met (codec + parser + assembler; querier state machine is Phase-2 M5d) |
| §4 wire | Report (type 143) wire format                  | met (codec + assembler + parser) |
| §4 wire | Multicast Address Record wire format           | met |
| §5      | Listener-side state machine                    | met (source-bearing state-change Reports — `ALLOW`/`BLOCK`/`CHANGE_TO_*` per the §6.1 difference table — with §9.1 robustness retransmission; §5.2.12 / §6.1, tested by `test__icmp6__mld__source_state_change.py` + `test__icmp6__mld2_leave.py`) |
| §5      | Querier General Query emission                 | met (Phase-2 M5d) |
| §5.1.10 | Listener responds to Query with Report         | met (MRC random-delay window, `stack.timer`-scheduled) |
| §5.2.13 | Hop Limit = 1 on outbound MLDv2 messages       | met |
| §5.2.13 | Source = link-local address                    | met |
| §5.2.14 | Destination = `ff02::16` (all-MLDv2-routers)   | met (for Reports) |
| §5.2.14 | Router Alert option (RFC 2711) in HBH          | met |
| §6      | Multicast Listener Discovery state transitions | met for the host (full INCLUDE / EXCLUDE source filters via `MCAST_*` socket options + data-plane source-delivery gate for UDP / RAW) |
| §7      | Querier election + timers (§7.4 / §7.6.2)      | met (Phase-2 M5d) |
| §8      | Action on reception (membership from Reports)  | met (Phase-2 M5d; group granularity) |

---

## §4 Message Formats

> "There are two MLDv2 message types: Multicast Listener
>  Query (type 130) and Version 2 Multicast Listener
>  Report (type 143)."

**Adherence:** met (RX side). Both message types live in
the ICMPv6 demux:

- Type 130 (`MULTICAST_LISTENER_QUERY`) — declared in
  `Icmp6Type` at `packages/net_proto/net_proto/protocols/icmp6/message/icmp6__message.py`
  with the codec class `Icmp6Mld2MessageQuery` at
  `packages/net_proto/net_proto/protocols/icmp6/message/mld2/icmp6__mld2__message__query.py`
  (28-byte fixed header + N × 16-byte source-address
  list; the parser feeds the host handler, and as of the
  Phase-2 M5a scaffolding `assemble` / `_pack_header` also
  serialise the Query wire form — tested at
  `test__icmp6__mld2__message__query__assembler.py`. The
  querier state machine that drives emission is Phase-2
  M5d–M5e router work). The RX path at
  `packet_handler__icmp6__rx.py:194` dispatches to
  `__phrx_icmp6__mld_query` (definition at `:1174`) per
  §5.1.10.
- Type 143 (`MULTICAST_LISTENER_REPORT_V2`) — full codec
  at
  `packages/net_proto/net_proto/protocols/icmp6/message/mld2/icmp6__mld2__message__report.py`
  (Header / Base / Parser / Assembler + multi-record
  payload). The RX path at
  `packet_handler__icmp6__rx.py:192` dispatches to
  `__phrx_icmp6__mld2_report` which counts the Report but
  takes no state-update action (host-side; querier role
  deferred).

> "A Multicast Address Record is a block of fields that
>  contain information on the sender listening to a single
>  multicast address on the interface from which the
>  Report is sent."

**Adherence:** met. The
`Icmp6Mld2MulticastAddressRecord` dataclass at
`packages/net_proto/net_proto/protocols/icmp6/message/mld2/` carries Record
Type, Aux Data Length, Number of Sources, Multicast
Address, and optional source addresses. The
`Icmp6Mld2MulticastAddressRecordType` enum covers all six
record types (`MODE_IS_INCLUDE = 1` through
`BLOCK_OLD_SOURCES = 6`).

---

## §5 Protocol Description

### §5.1 Action on Change of Per-Interface State

> "Whenever a multicast listener's per-interface state
>  changes, the listener immediately transmits a State
>  Change Report from that interface."

**Adherence:** met. A per-interface reception-state change
emits a source-bearing MLDv2 State Change Report via
`_send_mld_state_change` (`packet_handler__icmp6__tx.py`),
computed from the §6.1 difference table: a filter-mode
change yields one `CHANGE_TO_INCLUDE` / `CHANGE_TO_EXCLUDE`
record carrying the new source list, and a within-mode
source change yields `ALLOW_NEW_SOURCES` and/or
`BLOCK_OLD_SOURCES` records. The Report is retransmitted
`[Robustness Variable] - 1` times (§9.1, `mld.robustness`)
at intervals drawn uniformly at random from (0,
`mld.unsolicited_report_interval`] (§9.11); a compat-mode
change cancels the train (§8.2.1). While in MLDv1 Host
Compatibility Mode the change degrades to the coarse MLDv1
Report / Done. The all-nodes multicast (`ff02::1`) is never
reported (a permanent group per §6). The three reception
edges — join, leave, and a mid-membership filter delta —
all route through this path. Tested by
`test__icmp6__mld__source_state_change.py`.

### §5.1.10 Switching from an Older Version of MLD

> "If a host wishes to acquire MLDv2 protocol semantics
>  ... it MUST transition by sending a Version 2 Report
>  ..."

**Adherence:** met. PyTCP runs MLDv2 by default but now
implements the RFC 3810 §8 MLDv1 Host Compatibility Mode:
on hearing a 24-octet MLDv1 Query the interface enters
MLDv1 mode and emits MLDv1 Reports (type 131) instead of
the MLDv2 Report (type 143) for the Older Version Querier
Present timeout, then reverts. See
`docs/rfc/icmp6/rfc2710__mld_v1/adherence.md` for the full
MLDv1 + §8 audit.

### §5.2 Multicast Listener Query Message Format

> "Hop Limit: 1 (in fact, MLDv2 messages always have their
>  Hop Limit set to 1)."

**Adherence:** met. `_send_icmp6_multicast_listener_report`
forces `ip6__hop = 1` via the IPv6 TX path; see line 290+
of `packet_handler__icmp6__tx.py` where `_phtx_ip6` is
called. Confirmed by the wire-frame assertion in the
existing MLDv2 integration test.

> "Router Alert option [RFC 2711] in a Hop-by-Hop Options
>  header [RFC 2460]."

**Adherence:** met. The HBH carrier is constructed at
`packet_handler__icmp6__tx.py:271-284`:

```python
hbh_packet_tx = Ip6HbhAssembler(
    ip6_hbh__next=IpProto.ICMP6,
    ip6_hbh__options=Ip6HbhOptions(
        Ip6HbhOptionRouterAlert(
            value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
        ),
        Ip6HbhOptionPadN(b""),
    ),
    ...
)
```

The `Ip6HbhOptionRouterAlert` codec lives at
`packages/net_proto/net_proto/protocols/ip6_hbh/options/ip6_hbh__option__router_alert.py`
and supports the canonical RFC 2711 RA values
(`MLD`, `RSVP`, `ACTIVE_NETWORKS`, etc.). The
PadN-to-8-octet alignment is computed inline (2-byte HBH
prefix + 4-byte RA + 2-byte PadN(0) = 8 bytes total).

> "Source Address: link-local address ... unless the
>  link-local address is not yet known (e.g. SLAAC has not
>  yet completed) in which case the unspecified address
>  (::) MAY be used."

**Adherence:** met. The IPv6 TX path checks the candidate
source: when the stack has a usable link-local on the
sending interface it is used; otherwise the unspecified
address `::` is allowed for MLDv2 Reports (the MLDv2-report
branch in `packet_handler__ip6__tx.py:260-269` explicitly
documents this as the "src=:: legitimate for MLDv2"
exception that the generic `src=:: unicast` drop rule
makes for this protocol).

### §5.2.13 / §5.2.14 Destination = `ff02::16`

**Adherence:** met. `ip6__dst = Ip6Address("ff02::16")` at
`packet_handler__icmp6__tx.py:237` — the all-MLDv2-routers
multicast group.

---

## §6 Multicast Listener Discovery State Transitions

> "The listener tracks the multicast address membership of
>  the interface ... The MLDv2 state for each multicast
>  address is one of two filter modes: INCLUDE or EXCLUDE."

**Adherence:** met. PyTCP maintains per-interface multicast
reception state as
`_ip6_multicast_filters: dict[Ip6Address, Ip6MulticastFilter]`
on the packet handler — one merged INCLUDE / EXCLUDE source
filter per group (the §4.2 merge of the per-socket
contributors, guarded by `_lock__multicast`);
`_ip6_multicast` is a derived read-only view over its keys.
Source-specific multicast (SSM) is fully consumed: the
protocol-independent BSD socket options
`MCAST_JOIN_SOURCE_GROUP` / `MCAST_LEAVE_SOURCE_GROUP` /
`MCAST_BLOCK_SOURCE` / `MCAST_UNBLOCK_SOURCE` (dispatched
through the `stack.membership6` API) build per-socket
INCLUDE / EXCLUDE-with-sources filters; the data-plane RX
gate `Socket.ip6_multicast_source_admits` (Linux
`ip_mc_sf_allow`) delivers an inbound multicast datagram to
a socket only if its filter admits the datagram's source
(UDP + RAW); and a filter change emits the §6.1 source-
bearing state-change Report. Any-source joins (SLAAC /
solicited-node / `IPV6_JOIN_GROUP`) remain EXCLUDE{}. Tested
by `test__icmp6__mld__source_filter_model.py`,
`test__socket__ipv6_source_membership.py`,
`test__icmp6__mld__source_state_change.py`, and
`test__icmp6__mld__source_data_filter{,__raw}.py`.

> "When a multicast address listener change happens, the
>  listener responds with a State Change Report."

**Adherence:** met. Every reception-state edge —
`assign_ip6_multicast` (join), `remove_ip6_multicast`
(leave), and a mid-membership filter delta in
`_mc6_recompute` — emits a `_send_mld_state_change` State
Change Report so the local querier sees the updated
membership immediately. The solicited-node multicast for a
new address is joined automatically by `_assign_ip6_host`.

---

## §7 / §8 Querier-side Timers and Action on Reception

> "The MLDv2 querier sends [General / Multicast-Address-
>  Specific / Multicast-Address-and-Source-Specific]
>  Queries periodically ... and processes inbound Reports
>  to update per-group / per-source state."

**Adherence:** met (Phase-2 M5d) for the General-Query
querier; MLDv1 querier interop is M5e. An interface
configured as a multicast router (`mld.mc_forwarding`)
takes the querier role (`Icmp6TxHandler`, the IPv6 mirror
of the IGMPv3 querier):

1. **General Query emission** — `_send_mld_general_query`
   builds an MLDv2 General Query (multicast address ::)
   advertising the §9.3 Query Response Interval (Max Resp
   Code), §9.1 Robustness Variable (QRV), and §9.2 Query
   Interval (QQIC) to ff02::1, Hop Limit 1. Startup burst
   (§9.6 / §9.7) then steady state (§9.2) via a self-
   re-arming ticket.
2. **Election (§7.6.2)** — `observe_query` steps the router
   down to Non-Querier on a lower-source Query and arms the
   §9.5 Other Querier Present timer; expiry resumes the
   Querier role.
3. **Membership table (§7.4)** — `observe_report` replaces
   the former counter-only `__phrx_icmp6__mld2_report`,
   mapping each Multicast Address Record (`MODE_IS_INCLUDE`
   / `MODE_IS_EXCLUDE` / `CHANGE_TO_*` / `ALLOW_NEW_SOURCES`
   / `BLOCK_OLD_SOURCES`) to a per-group filter-mode +
   source-list entry, pruned by its §9.4 Multicast Address
   Listening Interval group timer. The querier receives
   Reports on ff02::16, admitted receive-only (an MLD
   control group never reported). Snapshot via
   `PacketHandler.mld_querier_memberships()`. Tested at
   `tests/integration/router/test__router__mld__querier.py`.

**Fast-leave Multicast-Address-Specific Queries** — as of
Phase-2 M5e, an MLDv2 leave (a `CHANGE_TO_INCLUDE{}` record
or a `BLOCK` that empties an INCLUDE set) triggers the RFC
3810 §7.6.3 fast-leave rather than an immediate prune:
`Icmp6TxHandler._start_group_fast_leave` lowers the group
timer to the Last Listener Query Time (§9.8 × §9.9), sends
the first of the §9.9 Last Listener Query Count Multicast-
Address-Specific Queries to the group, and arms the rest at
the §9.8 Last Listener Query Interval; a refreshing Report
cancels the train. Tested in the same router integration
file.

Group-granularity membership; the §7.2 per-source timers,
the per-source Address-and-Source-Specific Query for a
partial `BLOCK`, and the §8 MLDv1 querier-emit interop are
deferred refinements (niche for a last-hop router).

---

## §5.1.10 Listener-side Query → Report response

> "When a node receives a Multicast Listener Query, the
>  node responds with a Multicast Listener Report
>  containing the multicast listener record for each
>  multicast address listened on."

**Adherence:** met. The RX handler at
`__phrx_icmp6__mld_query` in `packet_handler__icmp6__rx.py`
emits the same `CHANGE_TO_EXCLUDE` Report PyTCP sends on
spontaneous group-membership changes; the wire form is
identical and the querier merges the on-Query Report with
any spontaneous Reports from the listener.

**MRC random-delay window:** PyTCP honours the §5.1.10
random-delay rule. On Query receipt the handler:

1. Decodes the Maximum Response Code field via the §5.1.3
   helper `_mld2_mrc_to_mrd_ms` (linear for MRC < 32768;
   floating-point `(mant | 0x1000) << (exp + 3)` for
   MRC ≥ 32768).
2. Picks a uniformly-random delay in [0, MRD] via the
   `_mld2_query__pick_response_delay_ms` method (extracted
   for deterministic test patching; backed by
   `random.randint`).
3. Schedules the Report via `stack.timer.register_method`
   with `repeat_count=0` (one-shot); the timer-fired
   callback `_mld2_query__deferred_send` clears the
   pending state and emits the Report.

**Coalescing per §5.1.10:** the handler tracks the absolute
`stack.timer.now_ms` at which the next Report will fire
in `_mld2_query__pending_response_at_ms`. A subsequent
Query whose computed response time is **later** than the
existing pending entry is absorbed without rescheduling;
one whose computed time is **earlier** supersedes the
pending entry — the old timer is cancelled via
`unregister_method` and a new one registered.

**Counters:**

- `icmp6__mld2_query` — every inbound Query.
- `icmp6__mld2_query__scheduled` — bumped on each timer
  registration (initial + reschedule).
- `icmp6__mld2_query__superseded` — bumped when an
  earlier Query cancels a pending Report.
- `icmp6__mld2_query__respond` — bumped when the Report is
  actually emitted (immediate-send for delay=0 OR
  timer-fired deferred send).

**Delay = 0 fast path:** the Timer's tick semantics
(`remaining_delay -= 1; if remaining_delay: return`) mean a
task registered with `delay=0` never fires (it ticks to -1
which is truthy). The handler short-circuits delay=0 to a
synchronous `_send_icmp6_multicast_listener_report` call,
preserving the immediate-response behaviour the RFC's
[0, MRD] interval permits at its zero endpoint.

The querier-role items (§7 timers; §8 inbound-Report
processing) remain Phase-2 router work.

---

## Test coverage audit

### §4 Report wire format

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__assembler.py`
  — pins the type-143 wire form, multi-record payload,
  per-record-type encoding (1-6).
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser.py`
  — pins the RX-side parse path.

**Status:** locked in.

### §5 Listener-side Report emission

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__tx.py`
  (plus `..test__icmp6__mld2_query_response.py` for the
  on-Query Report)
  — MLDv2 Report cases verify: Hop Limit = 1, source =
  link-local, destination = `ff02::16`, HBH RA-option
  carrier with value = MLD, `CHANGE_TO_EXCLUDE` record
  set populated from `_ip6_multicast`.

**Status:** locked in.

### §6 Address-change triggers Report

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc8981_temp.py`
  and `test__icmp6__nd__optimistic_dad.py` — every SLAAC
  address-claim sequence ends with an MLDv2 Report,
  verifying the trigger fires from the addressing path.

**Status:** locked in indirectly (no dedicated "address
change → Report" assertion; the integration cases pin the
end-to-end behaviour via wire observation).

### §5.1.10 Query → Report response (wire-format)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_query_response.py::TestIcmp6Mld2QueryResponse`
  — 4 tests with the delay-picker patched to 0 (immediate
  emission): General Query elicits exactly one TX frame;
  `icmp6__mld2_query` counter increments on Query receipt;
  `icmp6__mld2_query__respond` counter increments on
  Report emission; the outbound TX frame is ICMPv6 type
  143 (the MLDv2 Report).

**Status:** locked in.

### §5.1.3 MRC → MRD decoder

- **Integration (unit-style):**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_query_delay_window.py::TestIcmp6Mld2MrcEncodingDecode`
  — 2 tests: linear mapping for MRC < 32768;
  floating-point decoding for MRC ≥ 32768 across exp/mant
  corner cases (0x8000, 0x8FFF, 0xFFFF).

**Status:** locked in.

### §5.1.10 MRC random-delay window

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_query_delay_window.py::TestIcmp6Mld2QueryDelayWindow`
  — 5 tests covering the full deferred-send lifecycle:
  (a) non-zero delay defers the Report (no synchronous
  TX; FakeTimer advance triggers the fire);
  (b) delay=0 fast-path emits synchronously without
  registering a timer;
  (c) later Query coalesces (no reschedule, no
  `superseded` bump);
  (d) earlier Query supersedes (counter bumps; original
  timer cancelled and never fires);
  (e) pending-state attribute clears to None after the
  Report is sent.

**Status:** locked in.

### §5 / §7 / §8 MLDv2 querier role

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/router/test__router__mld__querier.py`
  The `mld.mc_forwarding` activation gate, the startup
  General-Query burst + steady-state periodic Query, the
  §7.6.2 election (lower-source step-down, higher-source
  ignore, Other Querier Present resume), and the §7.4
  membership table (EXCLUDE / INCLUDE learning + §9.4
  Multicast Address Listening Interval expiry).

**Status:** locked in (Phase-2 M5d — group-granularity
membership; MLDv1 querier interop + fast-leave queries are
M5e).

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Report wire format (TX + RX parse)                  | locked in |
| Hop Limit = 1 on outbound                           | locked in |
| RA-option HBH carrier                               | locked in |
| Address-change triggers Report                      | locked in indirectly |
| Query → Report response (wire format)               | locked in |
| §5.1.3 MRC → MRD decoder                            | locked in |
| §5.1.10 MRC random-delay window + coalescing        | locked in |
| MLDv2 querier (emission + election + membership)     | met (Phase-2 M5d) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §4 Query wire format                                  | met (codec + parser + assembler; querier state machine is Phase-2 M5d) |
| §4 Report wire format                                 | met    |
| §4 Multicast Address Record codec                     | met    |
| §5 Listener-side Report emission on join              | met    |
| §5.1.10 Query → Report response                       | met (MRC random-delay window + coalescing; `stack.timer`-scheduled) |
| §5.2.13 Hop Limit = 1                                 | met    |
| §5.2.13 Source = link-local                           | met    |
| §5.2.14 Destination = `ff02::16` + RA-option HBH      | met    |
| §6 Per-interface multicast state                      | met (EXCLUDE-source-list-empty default) |
| §7 / §8 Querier timers + Action on Reception          | met (Phase-2 M5d) |
| §5.1.10 MLDv1 compatibility mode                      | n/a (PyTCP is MLDv2-only) |

PyTCP fully satisfies the listener-side requirements that
matter for a multicast-using host. Remaining items:

1. **§5-§8 querier role** (Phase-2 router). Lands when the
   forwarding plane / multicast routing arrives.

## Cross-references

- IPv4 parallel: [`../../ip4/rfc1112__ip4_multicasting/adherence.md`](../../ip4/rfc1112__ip4_multicasting/adherence.md)
  (RFC 1112 IPv4 multicasting; IGMPv2 / IGMPv3 — RFCs 2236
  / 3376 — are tracked as item E in the IPv4 audit punch
  list and are not yet shipped).
- HBH Router-Alert option carrier: RFC 2711 (referenced
  here; no standalone audit yet).
- IPv6 ND / SLAAC adherence audits in this folder cover
  the upstream sources of multicast group membership (every
  SLAAC address claim adds a solicited-node multicast
  group; every group change triggers a Report).
