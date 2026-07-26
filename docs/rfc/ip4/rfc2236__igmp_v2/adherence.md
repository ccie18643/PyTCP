# RFC 2236 — Internet Group Management Protocol, Version 2 (IGMPv2)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 2236                                           |
| Title       | Internet Group Management Protocol, Version 2  |
| Category    | Standards Track                                |
| Date        | November 1997                                  |
| Updates     | RFC 1112                                        |
| Source text | [`rfc2236.txt`](rfc2236.txt)                   |

This document records how the PyTCP codebase relates to RFC 2236.
The audit was performed by reading the RFC text fresh and
inspecting `packages/net_proto/net_proto/protocols/igmp/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__igmp__{rx,tx}.py`
directly.

**Posture.** PyTCP runs **IGMPv3** (RFC 3376) as its primary host
protocol; RFC 3376 §4 requires an IGMPv3 host to also support the
IGMPv2 message types for interoperation with older routers. PyTCP
therefore implements the IGMPv2 **wire forms** (the 8-octet Query
and the Version 2 Membership Report / Leave Group) and the
IGMPv2-specific host **behaviours** (report suppression, sending
Reports in the v2 form to the group, the Leave Group to
224.0.0.2), which run under the RFC 3376 §7 older-version-querier
Host Compatibility Mode (see the RFC 3376 record §7). This record
calls out the v2-specific clauses; the mode machine and report-form
selection live in the RFC 3376 audit.

---

## Top-line adherence

| Section | Topic                                                  | Status |
|---------|--------------------------------------------------------|--------|
| §2      | 8-octet message format (Type / Max Resp Time / Checksum / Group) | met (codec) |
| §2.1    | Types 0x11 / 0x16 / 0x17 / 0x12                         | met (codec) |
| §2.3    | Checksum over the whole IGMP message                   | met |
| §3      | Unsolicited Report on join (v2 form in v2 mode)        | met |
| §3      | Report suppression on hearing another host's Report    | met (v1/v2 compatibility mode) |
| §3      | Leave Group to 224.0.0.2 on leave                      | met (v2 compatibility mode) |
| §3      | Querier General Query emission                         | met (Phase-2 M5b; IGMPv3 form) |
| §3      | Querier election (lowest address wins)                 | met (Phase-2 M5b) |
| §3      | Querier group-membership table from Reports            | met (Phase-2 M5b) |
| §3      | Querier specific (fast-leave) queries                  | out of scope (M5c) |

---

## §2. Message Format

> "All IGMP messages of concern to hosts have the following format:
> [Type | Max Resp Time | Checksum | Group Address] (8 octets)."

**Adherence:** met (codec). The 8-octet form is parsed by one
class per type (matching the ICMPv4 echo-request / echo-reply
convention): the Membership Query (Type 0x11, 8 octets) by
`IgmpMessageQuery` (its v1/v2 branch), and the Version 2
Membership Report (0x16), Leave Group (0x17) and Version 1
Membership Report (0x12) by `IgmpMessageV2Report` /
`IgmpMessageV2Leave` / `IgmpMessageV1Report`
(`igmp__message__v2_report.py` etc.), each fixing its own Type and
validating the group is a multicast address.

### §2.2 Max Response Time

> "The Max Response Time field is meaningful only in Membership
> Query messages ... In all other messages, it is set to zero by
> the sender and ignored by receivers."

**Adherence:** met. The legacy report / leave `__buffer__` methods
write the second octet as zero for the v2 Report / Leave / v1
Report forms; the Query path decodes Max Resp Time only on the
Query message.

### §2.3 Checksum

> "the 16-bit one's complement of the one's complement sum of the
> whole IGMP message ... When receiving packets, the checksum MUST
> be verified before processing a packet."

**Adherence:** met. The IGMP parser verifies the whole-message
checksum before dispatch (`igmp__parser.py::_validate_integrity`,
shared with the RFC 3376 path); the assembler injects it.

## §3. Protocol Description — host behaviour

> "When a host joins a multicast group, it should immediately
> transmit an unsolicited Version 2 Membership Report for that
> group ... it is recommended that it be repeated once or twice
> after short delays [Unsolicited Report Interval]."

**Adherence:** met. On join PyTCP emits an unsolicited
state-change report and retransmits it per the Robustness
Variable (RFC 3376 §5.1). When the interface is in IGMPv2
compatibility mode (RFC 3376 §7), the report is the **Version 2**
Membership Report (`IgmpMessageV2Report`) sent to the group
address; in IGMPv3 mode it is the v3 CHANGE_TO_EXCLUDE_MODE
Report. The form is selected by `_igmp_host_compatibility_mode()`.

> "If a host hears another host's Report (version 1 or 2) while it
> has a timer running, it stops its timer for the specified group
> and does not send a Report, in order to suppress duplicate
> Reports."

**Adherence:** met in v1/v2 compatibility mode. While a Query
response is pending in IGMPv1/v2 mode, hearing another host's
v1/v2 Membership Report for a joined group cancels this host's
pending Report for that group (bumping
`igmp__membership_query__suppressed`); the suppressed group is
skipped when the response timer fires. In IGMPv3 mode PyTCP does
not suppress (RFC 3376 §7.2.2 makes it a MAY) — it counts the
received Report (`igmp__membership_report`) and ignores it.

> "When a host leaves a multicast group, if it was the last host
> to reply to a Query ... it SHOULD send a Leave Group message to
> the all-routers multicast group (224.0.0.2)."

**Adherence:** met. In IGMPv2 compatibility mode a leave emits an
IGMPv2 **Leave Group** (`IgmpMessageV2Leave`) to the all-routers
group 224.0.0.2; in IGMPv3 mode it emits the CHANGE_TO_INCLUDE_MODE
state-change Report to 224.0.0.22 (RFC 3376 §5.1). An IGMPv1-mode
leave emits nothing (IGMPv1 has no Leave message). The form is
selected by `_igmp_host_compatibility_mode()`.

> "[Query / Querier behaviour: sending Queries, querier election,
> Group-Specific Queries on Leave, the Group Membership
> Interval]."

**Adherence:** out of scope. The querier (router) role is Phase-2
router work. PyTCP is a host (group member) only.

---

## Test coverage audit

### §2 v2 message wire forms

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__legacy_reports.py`
  Per-type matrix over `IgmpMessageV2Report` / `IgmpMessageV2Leave`
  / `IgmpMessageV1Report`: fixed Type, 8-octet length,
  Max-Resp-Time-zero framing, multicast-group sanity, from_buffer
  roundtrip.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py`
  The 8-octet v1/v2 Query branch (version classified by length).

**Status:** locked in (wire forms).

### §2.3 Checksum verification

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__parser__integrity_checks.py`
  and the integration `test__igmp__query_response.py` bad-checksum
  case.

**Status:** locked in.

### §3 join / leave reporting (via IGMPv3)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py`
  Join / leave emit IGMPv3 state-change Reports (the v2-form
  equivalent is covered by the version-fallback tests below).

**Status:** locked in for the IGMPv3 form.

### §3 v2-compatibility behaviours

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__version_fallback.py`
  `TestIgmpVersionFallbackReportForm` drives the §7 older-querier
  compatibility mode and asserts the host answers a join with a
  **v2 Report to the group** (`test__igmp__v2_mode__join_emits_v2_report_to_group`),
  sends a **v2 Leave Group to 224.0.0.2** on leave
  (`test__igmp__v2_mode__leave_emits_v2_leave_to_all_routers`),
  and answers a v2 Query with a per-group v2 Report
  (`test__igmp__v2_mode__query_response_is_per_group_v2_report`).
  `TestIgmpVersionFallback` pins the mode machine itself (v2/v1
  Query flips the mode, revert-to-v3 timeout, forced-version pin).
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__v2_report_suppression.py`
  `TestIgmpV2ReportSuppression` proves a v2 Report from another
  host suppresses this host's pending response
  (`test__igmp__v2__report_from_another_host_suppresses_pending_response`)
  and that an unsuppressed response is still sent
  (`test__igmp__v2__unsuppressed_response_is_sent`).

**Status:** locked in.

### Test coverage summary

| Aspect                              | Coverage |
|-------------------------------------|----------|
| §2 v2 message wire forms            | locked in |
| §2.3 checksum                       | locked in |
| §3 join/leave reporting (IGMPv3)    | locked in |
| §3 v2-form report / Leave-to-224.0.0.2 | locked in (`test__igmp__version_fallback.py`) |
| §3 report suppression               | locked in (`test__igmp__v2_report_suppression.py`) |
| §3 querier role                     | n/a (Phase 2 router) |

---

## Overall assessment

| Aspect                                  | Status |
|-----------------------------------------|--------|
| §2 8-octet message wire forms           | met (codec) |
| §2.3 checksum                           | met    |
| §3 join/leave reporting                 | met via IGMPv3 |
| §3 IGMPv2-form reports / Leave (224.0.0.2) | met (RFC 3376 §7 compatibility mode) |
| §3 report suppression                   | met (in v1/v2 compatibility mode) |
| §3 querier / router role                | out of scope (Phase 2) |

PyTCP supersedes IGMPv2 with IGMPv3 (RFC 3376) and implements the
IGMPv2 message wire forms required for interoperation. The
IGMPv2-specific host behaviours — answering in the v2 Report
form, the Leave Group to 224.0.0.2, and report suppression — are
implemented as the RFC 3376 §7 older-version Host Compatibility
Mode: an older-version Query flips the interface into IGMPv2 (or
IGMPv1) mode, `_igmp_host_compatibility_mode()` selects the v2
report / Leave forms, and report suppression fires while a v2
timer runs. The querier role is Phase-2 router work.
