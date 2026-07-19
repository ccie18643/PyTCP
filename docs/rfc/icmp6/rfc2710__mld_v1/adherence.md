# RFC 2710 — Multicast Listener Discovery v1 (MLDv1) + RFC 3810 §8 fallback — adherence

RFC 2710 defines MLDv1, the IPv6 analogue of IGMPv2. PyTCP's host
multicast-listener protocol is MLDv2 (RFC 3810); this record audits
PyTCP's **MLDv1 host behaviour** as exercised through the RFC 3810 §8
MLDv1 compatibility fallback — the requirement that an MLDv2 host
revert to MLDv1 Reports when it shares a link with an MLDv1-only
querier. It is the IPv6 analogue of the IGMP RFC 3376 §7 fallback
(`docs/rfc/ip4/rfc3376__igmp_v3/adherence.md`). The MLDv2 listener
behaviour is audited at `docs/rfc/icmp6/rfc3810__mld2/adherence.md`.

## Top-line adherence

PyTCP **meets** the host-side MLDv1 fallback: it parses MLDv1 Queries
(distinguished from MLDv2 by their 24-octet length), enters MLDv1 Host
Compatibility Mode for the Older Version Querier Present timeout, and
emits MLDv1 Reports (type 131) — one per joined group, sent to the
group address with the Router Alert Hop-by-Hop option and Hop Limit 1
— instead of the aggregated MLDv2 Report (type 143), reverting to
MLDv2 when the timeout elapses. The querier role (emitting Queries) is
Phase-2 router work and out of host scope.

| Section | Topic | Status |
|---------|-------|--------|
| RFC 2710 §3 | MLDv1 message formats (Query 130 / Report 131 / Done 132) | met (wire codec) |
| RFC 2710 §4 | Hop Limit 1; link-local; Router Alert option | met |
| RFC 3810 §8.1 | MLDv1 vs MLDv2 Query length discrimination (24 vs ≥28) | met |
| RFC 3810 §8.2.1 | Host Compatibility Mode + Older Version Querier Present timer | met |
| Linux parity   | Forced MLD version knob (`mld.version` sysctl, IPv6 analogue of `force_igmp_version`) | met |
| RFC 3810 §8.3.1 | Emit MLDv1 Reports while in MLDv1 mode | met |
| RFC 2710 §5 | MLDv1 Done on leaving a group | met (emitted on leave while in MLDv1 compat mode, to ff02::2) |
| RFC 2710 §4 | Report suppression on hearing another host's Report | deferred (optimization) |
| RFC 2710 §3 | Querier role (emit Queries) | n/a (host; Phase 2) |

---

## RFC 2710 §3 — MLDv1 message formats (wire codec)

**Adherence:** met. The three MLDv1 message types share the fixed
24-octet RFC 2710 §3 form (Type / Code / Checksum / Maximum Response
Delay / Reserved / Multicast Address) and live in
`packages/net_proto/net_proto/protocols/icmp6/message/mld1/`:

- `Icmp6Mld1MessageQuery` (type 130) — parsed on RX to drive the
  compatibility timer; RX-only (the querier emission is Phase-2).
- `Icmp6Mld1MessageReport` (type 131) — full parse + assemble (the
  host emits it in MLDv1 mode).
- `Icmp6Mld1MessageDone` (type 132) — full parse + assemble (available
  for the deferred leave path below).

The ICMPv6 type enum gained `MULTICAST_LISTENER_REPORT = 131` and
`MULTICAST_LISTENER_DONE = 132`.

## RFC 3810 §8.1 — Query version discrimination

**Adherence:** met. `Icmp6Parser._message_class` resolves a type-130
Query to `Icmp6Mld1MessageQuery` when the declared ICMPv6 payload
length is exactly 24 octets, and to `Icmp6Mld2MessageQuery` when it is
≥ 28 — the §8.1 length rule. A received MLDv1 Query therefore parses
into the MLDv1 message class and routes to the compatibility path.

## RFC 3810 §8.2.1 — Host Compatibility Mode + Older Version Querier Present timer

**Adherence:** met. A per-interface scalar
`_mld__v1_querier_present_until_ms`
(`runtime/packet_handler/__init__.py`) records the deadline until which
the interface stays in MLDv1 mode. The RX MLD-Query handler
(`packet_handler__icmp6__rx.py::_mld_arm_v1_compatibility`) arms it on
an MLDv1 Query to `now + [Robustness Variable] x [Query Interval] +
[Max Response Delay]` (the §9.12 timeout; defaults RV=2, QI=125 s from
§9.1/§9.2). `_mld_host_compatibility_mode()` returns `MldVersion.V1`
while the timer runs, else `MldVersion.V2` — reading the deadline live
so the mode reverts automatically when it passes (no explicit revert
timer), mirroring `_igmp_host_compatibility_mode`. The scalar is
written under the per-interface `_lock__multicast` (the no-GIL standing
invariant) and read lock-free.

A forced `mld.version` sysctl (`MLD__FORCE_VERSION` in
`packages/pytcp/pytcp/protocols/icmp6/mld__constants.py`, range 0-2)
overrides the automatic tracking: 0 = auto fallback (the timer-driven
behaviour above), 1/2 = pin the interface to MLDv1/MLDv2 regardless of
the queriers heard. `_mld_host_compatibility_mode()` reads it via
qualified module access so an operator override resolves live. This is a
PyTCP Linux-parity extension — the IPv6 analogue of Linux
`net.ipv4.conf.*.force_igmp_version` (which has no shipped IPv6
counterpart) and of PyTCP's own `igmp.version` knob.

## RFC 3810 §8.3.1 — emit MLDv1 Reports while in MLDv1 mode

**Adherence:** met. `_send_icmp6_multicast_listener_report` selects the
report form by `_mld_host_compatibility_mode()`: in `V1` it emits one
MLDv1 Report (type 131) per joined group via `_send_icmp6_mld1_report`
(an MLDv2-only querier cannot parse the aggregated type-143 Report);
in `V2` it emits the single aggregated MLDv2 Report. Both forms share
the `__send_icmp6_mld_via_hbh_ra` carrier — Hop-by-Hop Router Alert
(value=MLD, RFC 2711), Hop Limit 1. Per RFC 2710 §3 each MLDv1 Report
is sent to the multicast address being reported (destination = the
group); the MLDv2 Report goes to `ff02::16`.

## Deferred (with rationale)

- **RFC 2710 §5 MLDv1 Done on leave** — **shipped.** Leaving an IPv6
  multicast group now emits a departure message: an MLDv2
  `CHANGE_TO_INCLUDE` State Change Report in MLDv2 mode, or — while the
  interface is in MLDv1 Host Compatibility Mode — an MLDv1 Done
  (type 132) to all-routers (ff02::2). `remove_ip6_multicast` calls
  `_send_icmp6_mld_leave`, and `send_mld_leave_all` does the graceful
  leave-all on stack shutdown. (This was the previously-deferred SHOULD;
  it landed once the MLDv2 leave path gave it a counterpart.)
- **RFC 2710 §4 Report suppression** — deferred. A host that hears
  another host's Report for a group may cancel its own pending Report.
  This is an optimization, not a correctness MUST, and PyTCP does not
  implement it for MLDv2 either; received type-131 / type-132 messages
  are counted-and-ignored.
- **Querier role** — n/a (host; Phase-2 router work).

---

## Test coverage audit

### RFC 2710 §3 MLDv1 wire codec
- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/icmp6/test__icmp6__mld1__message__{report,done,query}.py`
  — asserts, assemble wire form, from_buffer round-trip, integrity
  rejection per message.

**Status:** locked in.

### RFC 3810 §8 compatibility fallback (state machine + report form)
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld1_compat.py`
  — an MLDv1 Query elicits an MLDv1 Report (type 131); an MLDv2 Query
  stays in MLDv2 mode (type 143); the mode reverts to MLDv2 after the
  Older Version Querier Present timeout.

**Status:** locked in.

### Forced MLD version knob (`mld.version` sysctl)
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld1_compat.py::TestIcmp6MldForcedVersion`
  — a forced `mld.version` of 1/2 pins `_mld_host_compatibility_mode()`
  to MLDv1/MLDv2 (the default 0 leaves the automatic fallback), and a
  forced v1 makes an MLDv2 Query elicit an MLDv1 Report (type 131).

**Status:** locked in.

### RFC 2710 §5 MLDv1 Done on leave
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_leave.py`
  — `test__mld1_compat__leave_emits_mld1_done` drives the interface
  into MLDv1 compat mode and asserts a leave emits an MLDv1 Done
  (type 132) to ff02::2 (the MLDv2-mode leave and shutdown leave-all
  are covered by the sibling tests in the same file).

**Status:** locked in.

### Test coverage summary

| Aspect | Coverage |
|--------|----------|
| §3 MLDv1 message wire codec (130 / 131 / 132) | locked in |
| §8.1 Query length discrimination | locked in (integration) |
| §8.2.1 compatibility-mode entry + revert | locked in |
| §8.3.1 MLDv1 Report emission in v1 mode | locked in |
| Forced `mld.version` knob | locked in (`TestIcmp6MldForcedVersion`) |
| §5 Done on leave | locked in (`test__icmp6__mld2_leave`) |
| §4 Report suppression | n/a (deferred) |

---

## Overall assessment

PyTCP's MLDv1 host fallback is complete for the RFC 3810 §8 MUSTs: an
MLDv2 host correctly degrades to MLDv1 Reports on an MLDv1-querier
link and reverts when the querier upgrades, and announces departures
with an MLDv1 Done while in v1 mode. The Report-suppression behaviour
is a deferred optimization, and the querier role is Phase-2 router
scope.
