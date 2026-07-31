# RFC 3376 — Internet Group Management Protocol, Version 3 (IGMPv3)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 3376                                           |
| Title       | Internet Group Management Protocol, Version 3  |
| Category    | Standards Track                                |
| Date        | October 2002                                   |
| Updates     | RFC 2236                                        |
| Source text | [`rfc3376.txt`](rfc3376.txt)                   |

This document records, clause by clause, how the PyTCP codebase
relates to each normative statement in RFC 3376 relevant to the
**host** role. The audit was performed by reading the RFC text
fresh and inspecting `packages/net_proto/net_proto/protocols/igmp/`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__igmp__{rx,tx}.py`,
`packages/pytcp/pytcp/stack/membership.py`, and
`packages/pytcp/pytcp/protocols/igmp/igmp__constants.py` directly.

**Scope.** PyTCP implements the IGMPv3 **host** (group member)
role, including source filtering: a group is held per-socket as
an INCLUDE / EXCLUDE source filter (RFC 3376 §3.1), the
per-interface reception state is the §3.2 merge of all socket
filters, and the source-filter socket options
(`IP_ADD_SOURCE_MEMBERSHIP` / `IP_DROP_SOURCE_MEMBERSHIP` /
`IP_BLOCK_SOURCE` / `IP_UNBLOCK_SOURCE`) drive it. The
**data-plane** RX source filter (dropping a received multicast
datagram from a non-admitted source before socket delivery,
Linux `ip_mc_sf_allow`) is implemented for both UDP and RAW
sockets, mirroring Linux which gates both delivery paths
(`__udp4_lib_mcast_deliver` and `raw_v4_input`). The IGMPv3
**router / querier** role (sending Queries, maintaining group
membership state for forwarding, the querier election) is
Phase-2 router work and is marked out-of-scope per clause.

---

## Top-line adherence

| Section  | Topic                                                    | Status |
|----------|----------------------------------------------------------|--------|
| §3.1     | Per-socket filter mode + source list                     | met |
| §3.2     | Per-interface state = merge of socket filters            | met |
| §4       | Messages carried in IPv4, protocol 2, TTL 1, Router Alert | met |
| §4.1     | Membership Query parse + wire assembly (v1/v2/v3)        | met |
| §4.1.1 / §4.1.7 | Max Resp Code / QQIC floating-point decode        | met |
| §4       | Inbound IGMP TTL = 1 enforced (drop martian TTL != 1)    | met |
| §4.1.12  | Accept Query to 224.0.0.1 / any interface address        | met |
| §4.2     | Version 3 Membership Report format                       | met |
| §4.2.12  | Current-State / Filter-Mode-Change / Source-List-Change records | met |
| §4.2.14  | Reports sent to 224.0.0.22                               | met |
| §5.1     | State-change Report on join/leave/source-delta + robustness retransmit | met |
| §5.2     | Random-delay response to a Query (general / group / group-and-source) | met |
| §6       | Host state — all-systems group never reported            | met (host); router state out of scope |
| §7       | Older-version (v1/v2) querier interoperation             | met |
| §8       | Timing / robustness constants                            | met (sysctls) |
| §9       | Source-Specific Multicast (INCLUDE / source filters)     | met (control plane + UDP data-plane RX filter) |

---

## §3.1. Socket State

> "For each socket on which IPMulticastListen has been invoked,
> the system records the desired multicast reception state ...
> (interface, multicast-address, filter-mode, source-list). ...
> If the requested filter mode is INCLUDE and the requested
> source list is empty, then the entry ... is deleted ..."

**Adherence:** met. Each socket holds its filter per
(ifindex, group) in `socket._ip4_source_filters`
(`packages/pytcp/pytcp/socket/__init__.py`) as an
`Ip4MulticastFilter` (mode + `frozenset` of sources, in
`packages/pytcp/pytcp/lib/ip4_multicast_filter.py`).
`IP_ADD_MEMBERSHIP` records EXCLUDE{} (any-source);
`_apply_source_op` runs the per-option state machine for
`IP_ADD_SOURCE_MEMBERSHIP` (INCLUDE-add), `IP_DROP_SOURCE_
MEMBERSHIP` (INCLUDE-remove, leaving the group when the
include list empties — the INCLUDE{} delete), `IP_BLOCK_SOURCE`
(EXCLUDE-add), and `IP_UNBLOCK_SOURCE` (EXCLUDE-remove), with
Linux `ip_mc_source` errno parity (EINVAL on a filter-mode
conflict, EADDRNOTAVAIL on a missing source). `close()`
releases every filter (`_release_ip4_memberships`, Linux
`ip_mc_drop_socket`); a socket dropped without `close()` releases
them on GC via the socket `__del__` finalizer, so a leaked joined
socket cannot keep its group joined forever.

## §3.2. Interface State

> "if *any* such record has a filter mode of EXCLUDE, then the
> filter mode of the interface record is EXCLUDE, and the source
> list ... is the intersection of the ... EXCLUDE mode, minus
> those source addresses that appear in any ... INCLUDE mode ...
> if *all* such records have a filter mode of INCLUDE, then ...
> the union of the source lists."

**Adherence:** met. `Ip4MulticastFilter.merge`
(`packages/pytcp/pytcp/lib/ip4_multicast_filter.py`) implements
the merge exactly — any EXCLUDE → EXCLUDE with (intersection of
the EXCLUDE lists) − (union of the INCLUDE lists); else INCLUDE
with the union; no contributors → INCLUDE{} (no reception). The
packet handler keys per-socket filters by an opaque socket token
(`_Ip4GroupMembership.socket_filters`, plus the operator hold)
and re-derives the materialized interface filter
(`_ip4_multicast_filters[group]`) in `_mc_recompute` on every
filter change; the flat `_ip4_multicast` joined-group list is a
derived read-only view over that map. The §3.2 re-evaluation
"does not necessarily result in a change of interface state"
holds — `_mc_recompute` emits a state-change Report only when
the merged filter actually changes.

## §4. Message Formats

> "IGMP messages are encapsulated in IPv4 datagrams, with an IP
> protocol number of 2.  Every IGMP message described in this
> document is sent with an IP Time-to-Live of 1, ... and carries
> an IP Router Alert option [RFC-2113] in its IP header."

**Adherence:** met. `IpProto.IGMP = 2`
(`packages/net_proto/net_proto/lib/enums.py`) and `IpProto.from_proto` maps the
`Igmp` assembler to it, so an IGMP message rides IPv4 with
Protocol = 2. The TX path
(`packet_handler__igmp__tx.py::_emit_v3_report`) sends every
Report to its destination with `ip4__ttl=1` and
`ip4__options=Ip4Options(Ip4OptionRouterAlert())`.

> "Unrecognized message types MUST be silently ignored."

**Adherence:** met. The parser routes an unrecognised type byte
to `IgmpMessageUnknown`, whose `validate_sanity` raises; the RX
handler catches the validation error and drops the frame
(`packet_handler__igmp__rx.py::_phrx_igmp`, counter
`igmp__failed_parse__drop`).

## §4.1. Membership Query Message

> "[Query wire format: Type=0x11, Max Resp Code, Checksum, Group
> Address, Resv|S|QRV, QQIC, Number of Sources, Source
> Address[]]"

**Adherence:** met (RX + wire assembly). `IgmpMessageQuery.from_buffer`
(`igmp__message__query.py`) decodes the 8-octet v1/v2 form and
the ≥12-octet v3 form, exposing `group_address`, `s_flag`,
`qrv`, `qqic`, and the source list. As of the Phase-2 M5a
scaffolding `IgmpMessageQuery.assemble` / `__buffer__` also
serialise the v1/v2 and v3 Query wire forms (checksum injected by
the `Igmp` base), tested at
`test__igmp__message__query__assembler__operation.py`. The
querier state machine that *drives* this emission — election,
General-Query timers, the router-side group-membership table — is
the Phase-2 M5b–M5c router work and remains out of scope here.

### §4.1.1 / §4.1.7 Max Resp Code / QQIC

> "If Max Resp Code >= 128, Max Resp Code represents a
> floating-point value ... Max Resp Time = (mant | 0x10) <<
> (exp + 3)."

**Adherence:** met. `decode_igmp_float_code`
(`igmp__message__query.py`) implements the 8-bit
`(mant | 0x10) << (exp + 3)` decode for both Max Resp Code and
QQIC; `IgmpMessageQuery.max_response_time` /
`.querier_query_interval` expose the decoded values.

### §4.1.12 IP Destination Addresses for Queries

> "a system MUST accept and process any Query whose IP
> Destination Address field contains *any* of the addresses
> (unicast or multicast) assigned to the interface on which the
> Query arrives."

**Adherence:** met. General Queries arrive at 224.0.0.1, which
the host joins permanently (on `_ip4_multicast`), and the IPv4
RX path admits any datagram destined to a joined multicast
group or an interface unicast address before the IGMP demux
runs (`packet_handler__ip4__rx.py`).

## §4.2. Version 3 Membership Report Message

> "[Report wire format: Type=0x22, Reserved, Checksum, Reserved,
> Number of Group Records, Group Record[]]"

**Adherence:** met. `IgmpMessageV3Report` (`igmp__message__
v3_report.py`) and `IgmpV3GroupRecord` (`igmp__v3_group_record.py`)
assemble and parse the Report and its records, including the
Aux Data Len in 32-bit words and the N×4-byte source list.

### §4.2.14 IP Destination Addresses for Reports

> "Version 3 Reports are sent with an IP destination address of
> 224.0.0.22, to which all IGMPv3-capable multicast routers
> listen."

**Adherence:** met. `_emit_v3_report` sends every Report to
`224.0.0.22` (`IGMP__ALL_IGMPV3_ROUTERS`).

## §5.1. Action on Change of Interface State

> "A change of interface state causes the system to immediately
> transmit a State-Change Report from that interface."

**Adherence:** met. A reception-state change computes the §5.1
difference records from the old and new merged interface filters
and emits them: `_assign_ip4_multicast` / `_remove_ip4_multicast`
report the join (non-existent→filter) and leave
(filter→non-existent) transitions, and `_mc_recompute` reports a
source-list change on a still-joined group
(`packet_handler/__init__.py`), all via
`IgmpTxHandler._send_igmp_state_change(group, old=, new=)`.

> "INCLUDE (A) → INCLUDE (B): ALLOW (B-A), BLOCK (A-B); EXCLUDE
> (A) → EXCLUDE (B): ALLOW (A-B), BLOCK (B-A); INCLUDE (A) →
> EXCLUDE (B): TO_EX (B); EXCLUDE (A) → INCLUDE (B): TO_IN (B).
> ... the 'non-existent' state ... INCLUDE ... empty source
> list."

**Adherence:** met. `IgmpTxHandler._state_change_records`
implements the table exactly (the non-existent state is
INCLUDE{}): a filter-mode change → one CHANGE_TO_INCLUDE_MODE /
CHANGE_TO_EXCLUDE_MODE record carrying the new source list; a
within-mode change → ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES
records, with the empty record omitted. An any-source join is
the INCLUDE{}→EXCLUDE{} mode change (TO_EX{}), a leave the
EXCLUDE{}→INCLUDE{} mode change (TO_IN{}); a source add/drop on
an INCLUDE membership is an ALLOW/BLOCK, a block/unblock on an
EXCLUDE membership likewise.

> "To cover the possibility of the State-Change Report being
> missed ... it is retransmitted [Robustness Variable] - 1 more
> times, at intervals chosen at random from the range (0,
> [Unsolicited Report Interval])."

> "If more changes to the same interface state entry occur
> before all the retransmissions of the State-Change Report for
> the first change have been completed, each such additional
> change triggers the immediate transmission of a new
> State-Change Report."

**Adherence:** met. A state change records a per-group
pending-change entry (record type + remaining-repeat count
seeded to `igmp.robustness` − 1) and arms a single retransmit
ticket; each fire recomputes the records from the live
pending-change map, decrements the counts, drops the exhausted
entries, and re-arms while any remain — so the repeats are
chained at successive random intervals drawn from (0,
`igmp.unsolicited_report_interval` ms] via `stack.timer` (the
Linux `igmp_ifc_timer` / `mr_ifc_count` model). A new change to
the same group overwrites that group's pending record and
re-seeds its count, so a join cancelled by a quick leave
retransmits the leave, never the stale join
(`IgmpTxHandler._send_igmp_v3_state_change` /
`_arm_state_change_retransmit` / `_fire_state_change_retransmit`).

## §5.2. Action on Reception of a Query

> "When a system receives a Query, it does not respond
> immediately.  Instead, it delays its response by a random
> amount of time, bounded by the Max Resp Time ..."

**Adherence:** met. `__phrx_igmp__membership_query`
(`packet_handler__igmp__rx.py`) draws a random delay in
[0, Max Resp Time] and schedules the current-state Report via
`stack.timer` (delay 0 = respond now).

> "1. If there is a pending response to a previous General Query
> scheduled sooner than the selected delay, no additional
> response needs to be scheduled.  2. If the received Query is a
> General Query, the interface timer is used to schedule a
> response ... Any previously pending response to a General
> Query is canceled."

**Adherence:** met. A General Query uses the single per-interface
pending-response deadline (`_igmp_query__pending_response_at_ms`
/ `_handle`): a Query whose computed response is later than the
pending one is absorbed (rule 1), an earlier one supersedes it
(rule 2). A **Group-Specific or Group-and-Source-Specific Query**
uses a per-group timer (`_igmp_group_query__pending`, group →
`IgmpGroupQueryPending` = deadline + handle + recorded sources):
a General response scheduled sooner absorbs it (rule 1), else a
per-group timer is armed and the queried source list recorded
(rule 3), a Group-Specific query or an empty recorded list
clears the recorded sources (rule 4), and a further GSSQ augments
them (rule 5), each at the earliest of the pending and selected
delays (`_igmp_query__schedule_group`).

> "INCLUDE (A) ... IS_IN (A*B); EXCLUDE (A) ... IS_IN (B-A). If
> the resulting Current-State Record has an empty set of source
> addresses, then no response is sent."

**Adherence:** met. On group-timer expiry a Current-State Record
is sent iff the interface still has reception state
(`_igmp_group_query__send_now`); with no recorded sources it
carries the group's real filter mode + source list (expiry rules
1-2), and with recorded sources B it applies the rule-3 table —
`_send_igmp_v3_group_current_state` answers IS_IN(A∩B) for an
INCLUDE(A) interface filter and IS_IN(B−A) for an EXCLUDE(A) one,
sending nothing when the result is empty.

## §6. Description of the Router / Host Behaviour

> "the all-systems multicast address, 224.0.0.1, to which all
> IP systems ... are always members.  ... a system can never be
> in any state with respect to this address; ... reception
> state for it is never reported."

**Adherence:** met (host). `_send_igmp_v3_report` and
`_send_igmp_v3_state_change` exclude 224.0.0.1 from the records
(`IGMP__ALL_SYSTEMS` guard), and the membership API refuses to
leave it.

**Querier General Query emission** — as of the Phase-2 M5b
slice, an interface configured as a multicast router
(`igmp.mc_forwarding`) takes the querier role and emits General
Queries: `IgmpTxHandler._send_igmp_general_query` builds an
IGMPv3 General Query (group 0.0.0.0) advertising the Query
Response Interval (Max Resp Code, §8.3), Robustness Variable
(QRV), and Query Interval (QQIC, §8.2) to the all-systems group
224.0.0.1 with TTL 1. `refresh_querier` / `_start_querier`
send the §8.7 Startup Query Count burst spaced at the §8.6
Startup Query Interval, then settle to the §8.2 steady-state
interval via the self-re-arming General-Query ticket. Tested at
`tests/integration/router/test__router__igmp__querier.py`.

**Querier election** — as of the Phase-2 M5b election slice, an
inbound Query from a source address lower than our interface
address makes the router step down to Non-Querier and stop
emitting General Queries (`IgmpTxHandler.observe_query`, called
from the IGMP RX Query handler); the Other Querier Present timer
(§8.5) resumes the Querier role when the elected querier goes
silent (RFC 3376 §6.6.2). Tested in the same router integration
file.

**Router group-membership table** — as of the Phase-2 M5b
membership slice, a querier interface learns downstream reception
state from inbound Membership Reports into a per-group table
(`IgmpTxHandler.observe_report`, called from the IGMP RX Report
handler): the §6.4 action-on-reception maps each group record to a
filter-mode + source-list entry, refreshed on every Report and
pruned when its §8.4 Group Membership Interval group timer expires
(§6.5). The table is populated **only** from inbound Reports,
never from this stack's own host joins (which stay in the separate
`_ip4_multicast_refs` host table). The querier receives Reports on
the all-IGMPv3-routers group 224.0.0.22, admitted receive-only —
it is an IGMP control group the interface never reports membership
in (`IGMP__CONTROL_GROUPS`). A read-only snapshot is exposed via
`PacketHandler.igmp_querier_memberships()` (the router-side
introspection surface). Tested in the same router integration
file.

**Fast-leave Group-Specific Queries** — as of Phase-2 M5c, a leave
(a `CHANGE_TO_INCLUDE{}` record, a `BLOCK` that empties an INCLUDE
set, or an IGMPv2 Leave Group) triggers the RFC 3376 §6.4.2
fast-leave rather than an immediate prune:
`IgmpTxHandler._start_group_fast_leave` lowers the group timer to
the Last Member Query Time (§8.8 × §8.9), sends the first of the
§8.9 Last Member Query Count Group-Specific Queries to the group
address, and arms the rest at the §8.8 Last Member Query Interval; a
refreshing Report cancels the train and restores the full group
timer. The querier receives IGMPv2 Leaves on the all-routers group
224.0.0.2, admitted receive-only alongside 224.0.0.22. Tested in the
same router integration file.

PyTCP tracks membership at group granularity; the RFC 3376 §6.2.1
per-source timers (independent aging of EXCLUDE-group sources), the
per-source Group-and-Source-Specific Query for a partial `BLOCK`, and
the §7.3 IGMPv1/v2 querier-emit interop (a querier emitting
older-version-format Queries) are deferred refinements — niche for a
last-hop router, whose value is the group-level membership the
forwarding plane (M5f) consumes.

## §7. Interoperation With Older Versions of IGMP

> "In order to be compatible with older version routers, IGMPv3
> hosts MUST operate in version 1 and version 2 compatibility
> modes.  ... If a host receives ... an older version Query ...
> it MUST use ... the host compatibility mode ..."

> "Whenever a host changes its compatibility mode, it cancels
> all its pending response and retransmission timers."

**Adherence:** met. A per-interface Host Compatibility Mode
machine (§7.2.1) arms an IGMPv1 / IGMPv2 Older Version Querier
Present deadline on an 8-octet Query (zero Max Resp Code = v1,
non-zero = v2) for the §8.12 timeout (RV × `igmp.query_interval`
+ one Query Response Interval; a v1 Max Resp Code of 0 is read
as 100). `PacketHandler._igmp_host_compatibility_mode()` returns
IGMPv1 while the v1 timer runs, else IGMPv2 while the v2 timer
runs, else IGMPv3; a forced `igmp.version` (1/2/3) overrides. A
mode change cancels the pending query-response timer and the
state-change retransmit train.

The report form follows the mode (§7.2.1 "acts using only the
[mode] protocol"): the query response and join/leave state
changes emit a v3 Report to 224.0.0.22, a per-group IGMPv2
Membership Report to the group (join) + IGMPv2 Leave Group to
224.0.0.2 (leave) per RFC 2236 §3, or a per-group IGMPv1 Report
on join with nothing on leave per RFC 1112 §6. The robustness
retransmit recomputes the mode form at fire time. §7.2.2
report suppression (a MAY) is implemented for v1/v2 mode —
another host's v1/v2 Report for a pending group cancels this
host's pending Report; IGMPv3 keeps count-and-ignore.
(`packet_handler__igmp__rx.py` / `__tx.py`,
`igmp.version` / `igmp.query_interval` sysctls.)

## §8. List of Timers and Default Values

> "The Robustness Variable ... default: 2.  ... The Unsolicited
> Report Interval is the time between repetitions of a host's
> initial report of membership in a group.  Default: 1 second."

**Adherence:** met (operator-tunable). `igmp.robustness`
(default 2) and `igmp.unsolicited_report_interval` (default
1000 ms) are registered sysctls
(`packages/pytcp/pytcp/protocols/igmp/igmp__constants.py`). The
querier-side intervals (Query Interval, Query Response Interval,
Startup / Last-Member values) are router parameters the host
reads from the wire (QQIC / Max Resp Code), not host config.

## §9. Source-Specific Multicast (host control plane)

**Adherence:** met (control plane). The source-filter socket
options (`IP_ADD_SOURCE_MEMBERSHIP` / `IP_DROP_SOURCE_MEMBERSHIP`
/ `IP_BLOCK_SOURCE` / `IP_UNBLOCK_SOURCE`) drive a per-socket
INCLUDE / EXCLUDE source filter (§3.1); the per-interface
reception state is the §3.2 merge; filter changes emit the §5.1
source-bearing state-change records (ALLOW / BLOCK / CHANGE_TO_*);
and Group-and-Source-Specific Queries are answered with the §5.2
rule-3 intersection math. The protocol-independent `MCAST_*`
socket API and the MSFv1 `IP_MSFILTER` get/set surface are not
implemented (PyTCP has no consumer).

> "After a multicast packet has been accepted from an interface
> by the IP layer, its subsequent delivery to the application or
> process listening on a particular socket depends on the
> multicast reception state of that socket ..." (§3.2)

**Adherence:** met (UDP). The **data-plane** RX source filter is
enforced at socket delivery: `UdpRxHandler.__phrx_udp__multicast_
source_allowed` (`packet_handler__udp__rx.py`) gates each
candidate socket for an IPv4 multicast datagram by that socket's
`_ip4_source_filters[(ifindex, group)].allows(source)`
(`Ip4MulticastFilter.allows` — INCLUDE delivers listed sources,
EXCLUDE delivers all but listed); a filtered-out source bumps
`udp__multicast_source_filtered__drop` and falls through to the
next candidate socket. A socket with no per-(interface, group)
filter keeps the existing any-source delivery, so the gate only
tightens delivery for source-specific sockets. The same filter
gates RAW-socket delivery in the IPv4 RX path
(`packet_handler__ip4__rx`) via the shared
`socket._ip4_multicast_source_admits` helper — a matched-but-
filtered RAW socket drops the datagram (bumping
`raw__multicast_source_filtered__drop`) and, mirroring Linux
`raw_v4_input` where a matched socket sets `delivered = 1`,
suppresses the Protocol-Unreachable rather than falling through
to the transport demux. RAW reception of `(group, INADDR_ANY)`
multicast is itself enabled by the wildcard `RawMetadata.socket_ids`
enumeration (the connected / local-bound / fully-wildcard
candidates the UDP demux already produced).

---

## Test coverage audit

### §4 IGMP-in-IPv4 + unknown-type drop

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__ip4_payload.py`
  An IGMP Report carried in IPv4 sets Protocol = 2 and the
  message follows the header intact.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__unknown.py`
  and `test__igmp__parser__integrity_checks.py` — an unknown
  type is rejected at sanity (silent drop).

**Status:** locked in.

### §4.1 / §4.1.1 / §4.1.7 Query parse + wire assembly + float decode

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py`
  v1/v2/v3 version discrimination, field decode, the §4.1.1 /
  §4.1.7 float-code table, the General-Query predicate.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__assembler__operation.py`
  v1/v2/v3 Query serialisation, buffer layout, checksum
  injection, and the assemble→parse round-trip (Phase-2 M5a).

**Status:** locked in.

### §4.2 / §4.2.14 V3 Report format + destination

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__v3_report__assembler.py`
  and `test__igmp__v3_group_record__assembler.py` — Report /
  record wire format + roundtrip.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__report_tx.py`
  Emitted Report goes to 224.0.0.22 (its multicast MAC),
  TTL = 1, Protocol = IGMP, type 0x22.

**Status:** locked in.

### §5.1 State-change Report + robustness retransmit

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py`
  Join → one CHANGE_TO_EXCLUDE_MODE record; leave → one
  CHANGE_TO_INCLUDE_MODE record; all-systems group silent.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__robustness_retransmit.py`
  RV=2 → one retransmit at the URI delay; RV=3 → two chained at
  successive intervals; RV=1 → none; and a leave before the join
  retransmit fires supersedes it (the retransmit carries
  CHANGE_TO_INCLUDE_MODE, never the stale CHANGE_TO_EXCLUDE_MODE).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__shutdown_leave.py`
  On shutdown the host emits a single combined Report transitioning
  every joined group to CHANGE_TO_INCLUDE_MODE (a graceful Leave so
  routers prune immediately — Linux `ip_mc_down`); the all-systems
  group is excluded and an all-systems-only state emits nothing.
- **Unit:**
  `test__stack__init.py::TestStackStopOrdering` — `stack.stop()` sends
  each interface's graceful Leave before stopping the packet handler,
  while the TX path is still live.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__source_state_change.py`
  The §5.1 difference table: ALLOW_NEW_SOURCES on a source add /
  unblock, BLOCK_OLD_SOURCES on a source drop / block,
  CHANGE_TO_EXCLUDE_MODE on an INCLUDE→EXCLUDE interface mode flip,
  and a robustness retransmit carrying the source list.

**Status:** locked in.

### §5.2 Query response random delay + coalescing

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__query_response.py`
  General Query: zero-delay → immediate Report; non-zero delay →
  Report deferred until the FakeTimer crosses the deadline;
  bad-checksum Query dropped.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__group_specific_query.py`
  Group-Specific Query: the response carries a record for only
  the queried group; an unjoined group elicits nothing; a
  deferred per-group response fires for the group; a sooner
  pending General response absorbs the Query (rule 1).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__source_query_response.py`
  General / Group-Specific responses carry the real INCLUDE /
  EXCLUDE mode + source list; a Group-and-Source-Specific Query
  answers IS_IN(A∩B) on an INCLUDE interface and IS_IN(B−A) on an
  EXCLUDE interface (rule-3 table); an empty IS_IN result sends no
  response.

**Status:** locked in.

### §3.1 / §3.2 / §9 Source filters (socket + interface merge)

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__ip4_multicast_filter.py`
  The §3.2 merge table — INCLUDE union, EXCLUDE intersection
  minus the INCLUDE union, the mixed and EXCLUDE{}-collapse rows,
  and the INCLUDE{}-is-no-reception predicate.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__source_filter_model.py`
  A plain join materializes EXCLUDE{}; `_ip4_multicast` is a
  derived view over the filter map; the merge over operator +
  per-socket contributors drives the join/leave edge.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__source_socket_opts.py`
  Each source option's effect on the socket + interface filter,
  the §3.2 merge across two sockets (INCLUDE union; EXCLUDE{} +
  INCLUDE → EXCLUDE{}), the `ip_mc_source` errno table (EINVAL
  mode conflict, EADDRNOTAVAIL missing source), and close-release.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__socket_gc_release.py`
  A socket dropped without `close()` releases all its joined groups
  on GC via the `__del__` finalizer; an explicitly-closed socket's
  finalizer is a no-op (no double-release).

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__ip4_multicast_filter.py`
  The `allows()` per-source delivery predicate (INCLUDE lists,
  EXCLUDE complements, INCLUDE{} delivers nothing).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__source_data_filter.py`
  An inbound IPv4 multicast UDP datagram is delivered to the
  socket only from an admitted source — an INCLUDE socket gets
  its listed source and drops others (bumping
  `udp__multicast_source_filtered__drop`); an EXCLUDE socket
  drops a blocked source and gets an unblocked one.

**Status:** locked in.

### §6 All-systems group never reported

- **Integration:**
  `test__igmp__membership_change.py::...all_systems_group_change_emits_nothing`
  and `test__igmp__report_tx.py::...no_groups_no_emit`.

**Status:** locked in.

### §6 / §8.2 / §8.6 / §8.7 Querier General-Query emission

All in
`packages/pytcp/pytcp/tests/integration/router/test__router__igmp__querier.py`:

- `TestRouterIgmpQuerier::test__router__igmp_querier__disabled_interface_is_silent`
  — an `igmp.mc_forwarding`-off interface emits no Query over
  two Query Intervals (the activation gate).
- `TestRouterIgmpQuerier::test__router__igmp_querier__startup_emits_first_general_query`
  — bring-up immediately emits one General Query to 224.0.0.1
  from the interface address, and a non-refreshed interface
  stays silent.
- `TestRouterIgmpQuerier::test__router__igmp_querier__startup_burst_spacing`
  — exactly Startup Query Count (§8.7) General Queries fire,
  spaced one Startup Query Interval (§8.6).
- `TestRouterIgmpQuerier::test__router__igmp_querier__steady_state_periodic_query`
  — after the burst drains, one General Query recurs every
  Query Interval (§8.2).
- `TestRouterIgmpQuerier::test__router__igmp_querier__general_query_advertises_timers`
  — the Query advertises the Query Response Interval (Max Resp
  Code), Query Interval (QQIC), and Robustness Variable (QRV).
- `TestRouterIgmpQuerier::test__router__igmp_querier__stop_cancels_queries`
  — querier teardown cancels the pending General-Query ticket.

**Status:** locked in.

### §6.6.2 / §8.5 Querier election

`test__router__igmp__querier.py`:

- `TestRouterIgmpQuerierElection::test__router__igmp_querier__lower_ip_query_steps_down`
  — a Query from a lower source address makes the router lose
  the election once and stop emitting General Queries.
- `TestRouterIgmpQuerierElection::test__router__igmp_querier__higher_ip_query_ignored`
  — a higher-address Query does not cost the election; startup
  Queries continue.
- `TestRouterIgmpQuerierElection::test__router__igmp_querier__resumes_after_other_querier_present`
  — the router resumes emitting after the §8.5 Other Querier
  Present Interval of silence.

**Status:** locked in.

### §6.4 / §6.5 / §8.4 Router membership table from Reports

`test__router__igmp__querier.py`:

- `TestRouterIgmpQuerierMembership::test__router__igmp_querier__learns_exclude_membership`
  — a MODE_IS_EXCLUDE Report installs an EXCLUDE entry and bumps
  the querier-learn counter once.
- `TestRouterIgmpQuerierMembership::test__router__igmp_querier__learns_include_membership_with_source`
  — a MODE_IS_INCLUDE Report installs an INCLUDE entry carrying
  the reported source list.
- `TestRouterIgmpQuerierMembership::test__router__igmp_querier__membership_expires_after_gmi`
  — a group with no refreshing Report is pruned after the §8.4
  Group Membership Interval (§6.5).
- `TestRouterIgmpQuerierMembership::test__router__igmp_querier__host_interface_learns_nothing`
  — an interface that is not a multicast router builds no table
  (the §6.4 active-router gate).

**Status:** locked in (group-granularity membership).

### §6.4.2 / §8.8 / §8.9 Fast-leave Group-Specific Queries

`test__router__igmp__querier.py`:

- `TestRouterIgmpQuerierMembership::test__router__igmp_querier__to_include_empty_is_leave`
  — a CHANGE_TO_INCLUDE{} leave retains the group pending
  re-assertion, then prunes it after the Last Member Query Time.
- `TestRouterIgmpQuerierFastLeave::test__router__igmp_querier__to_include_empty_sends_group_query`
  — the leave emits a Group-Specific Query for the group and
  retains the membership.
- `TestRouterIgmpQuerierFastLeave::test__router__igmp_querier__fast_leave_query_burst`
  — Last Member Query Count (§8.9) Group-Specific Queries fire,
  spaced one Last Member Query Interval (§8.8).
- `TestRouterIgmpQuerierFastLeave::test__router__igmp_querier__fast_leave_prunes_after_last_member_time`
  — an un-re-asserted group is pruned after the Last Member
  Query Time (LMQI × LMQC).
- `TestRouterIgmpQuerierFastLeave::test__router__igmp_querier__reassert_cancels_fast_leave`
  — a fresh Report during the window retains the group past the
  Last Member Query Time.
- `TestRouterIgmpQuerierFastLeave::test__router__igmp_querier__v2_leave_triggers_fast_leave`
  — an IGMPv2 Leave Group (received on 224.0.0.2) triggers the
  Group-Specific Query.

**Status:** locked in.

### §4.1.1 / §4.1.7 Max Resp Code / QQIC float-code encoder

- `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py::TestIgmpFloatCodeEncode`
  — linear form, exactly-representable round-trip through
  decode, and the floor / saturate cases of `encode_igmp_float_code`.

**Status:** locked in.

### §5.2.4 Multicast forwarding (last hop)

`packages/pytcp/pytcp/tests/integration/router/test__router__ip4__mforward.py`:

- `TestRouterIp4MulticastForward::test__router__ip4__mforward__replicates_to_listeners`
  — a transit multicast datagram is replicated (TTL decremented)
  out each interface with a listener and not the ingress.
- `TestRouterIp4MulticastForward::test__router__ip4__mforward__no_listeners_dropped`
  — no downstream listener → dropped, not replicated.
- `TestRouterIp4MulticastForward::test__router__ip4__mforward__rpf_failure_dropped`
  — a datagram arriving off the RPF interface is dropped.
- `TestRouterIp4MulticastForward::test__router__ip4__mforward__link_local_group_not_forwarded`
  — a 224.0.0.0/24 link-local group is never forwarded.

**Status:** locked in.

### §8 Timing / robustness sysctls

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__sysctls.py`
  Defaults, override, validator, and `igmp.max_memberships`
  enforcement.

**Status:** locked in.

### §7 Older-version querier interoperation

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__version_fallback.py`
  Host Compatibility Mode: default v3; a v2/v1 Query flips the
  mode; revert to v3 after the §8.12 timeout; a v3 Query does
  not lower the mode; a forced `igmp.version` pins the mode; a
  mode change cancels the pending state-change retransmit. Plus
  report-form selection: v2/v1 join emits a per-group Report to
  the group, a v2 leave emits a Leave Group to 224.0.0.2, a v1
  leave emits nothing, and the v2 query response is per-group.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__v2_report_suppression.py`
  In v2 mode, another host's v2 Report for a pending group
  suppresses this host's Report; absent it, the Report is sent.

**Status:** locked in.

### Test coverage summary

| Aspect                                         | Coverage |
|------------------------------------------------|----------|
| §3.1 / §3.2 per-socket + interface source filter merge | locked in |
| §4 IGMP-in-IPv4 / unknown-type drop            | locked in |
| §4.1 Query parse + float decode                | locked in |
| §4.2 V3 Report format + 224.0.0.22 destination | locked in |
| §5.1 State-change Report (incl. source deltas) + robustness retransmit | locked in |
| §5.2 Query response (general / group / group-and-source) | locked in |
| §6 all-systems never reported                  | locked in |
| §4.1.1 / §4.1.7 Max Resp Code / QQIC encoder   | locked in |
| §6 / §8.2 / §8.6 / §8.7 querier General-Query emission | locked in |
| §6.6.2 / §8.5 querier election                 | locked in |
| §6.4 / §6.5 / §8.4 router membership table      | locked in |
| §6.4.2 / §8.8 / §8.9 fast-leave Group-Specific Queries | locked in |
| §5.2.4 multicast forwarding — last hop (IPv4)  | locked in |
| §8 timing / robustness sysctls                 | locked in |
| §7 older-version querier interop               | locked in |
| §9 source-specific filtering (control plane)   | locked in |
| §3.1 / §9 data-plane RX source-delivery filter (UDP) | locked in |
| §6.2.1 per-source timers + §7.3 querier-emit interop | n/a (deferred) |

---

## Overall assessment

| Aspect                                         | Status |
|------------------------------------------------|--------|
| §3.1 per-socket filter mode + source list       | met   |
| §3.2 per-interface filter merge                 | met   |
| §4 message formats (Query / V3 Report / record) | met   |
| §4 IPv4 carriage (proto 2, TTL 1, Router Alert) | met   |
| §5.1 state-change Report (incl. source deltas) + robustness retransmit | met |
| §5.2 random-delay Query response (general / group / group-and-source) | met |
| §6 all-systems group exemption (host)           | met   |
| §7 older-version (v1/v2) querier interop        | met   |
| §8 timing / robustness constants (sysctls)      | met   |
| §9 source-specific multicast (control plane)    | met   |
| §3.1 / §9 data-plane RX source-delivery filter (UDP + RAW) | met (`ip_mc_sf_allow`) |
| Querier General Query emission (§6/§8.2/§8.6/§8.7) | met (Phase-2 M5b) |
| Querier election (§6.6.2) + Other Querier Present (§8.5) | met (Phase-2 M5b) |
| Router group-membership table from Reports (§6.4 / §6.5 / §8.4) | met (Phase-2 M5b; group granularity) |
| Fast-leave Group-Specific Queries (§6.4.2 / §8.8 / §8.9) | met (Phase-2 M5c) |
| Per-source timers (§6.2.1) + IGMPv1/v2 querier-emit interop (§7.3) | out of scope (deferred refinement) |

PyTCP implements the IGMPv3 **host** role including source
filtering: a group is held per-socket as an INCLUDE / EXCLUDE
source filter (§3.1) driven by the `IP_*_SOURCE_MEMBERSHIP` /
`IP_*_SOURCE` socket options, the per-interface reception state
is the §3.2 merge of all socket filters (reference-counted, so a
group is held until its last contributor leaves — see
`docs/refactor/igmp_r3_socket_refcounting.md`), filter changes
announce the §5.1 source-bearing difference records
(ALLOW / BLOCK / CHANGE_TO_*) with robustness retransmission,
Membership Queries are answered after the §5.2 random delay with
real-mode Current-State Records (and the rule-3 IS_IN(A∩B) /
IS_IN(B−A) math for Group-and-Source-Specific Queries), and the
host falls back to IGMPv1/v2 report forms under an older-version
querier (§7 Host Compatibility Mode). The **data-plane** RX
source-delivery filter (`ip_mc_sf_allow`) is enforced for both
UDP and RAW sockets — a received multicast datagram reaches a
socket only from a source the socket's filter admits — mirroring
Linux, which gates both `__udp4_lib_mcast_deliver` and
`raw_v4_input`. The IGMPv3 router/querier role is out of scope
(Phase 2).
