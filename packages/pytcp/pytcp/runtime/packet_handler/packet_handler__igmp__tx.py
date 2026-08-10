################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains the outbound IGMP packet handler for one
interface.

pytcp/runtime/packet_handler/packet_handler__igmp__tx.py

ver 3.0.10
"""

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    IgmpAssembler,
    IgmpMessage,
    IgmpMessageQuery,
    IgmpMessageV1Report,
    IgmpMessageV2Leave,
    IgmpMessageV2Report,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpV3RecordType,
    IgmpVersion,
    Ip4OptionRouterAlert,
    Ip4Options,
    encode_igmp_float_code,
)
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants
from pytcp.runtime.timer import TimerHandle
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv4 destinations defined by RFC 3376 §4 / RFC 2236 §3: every
# host belongs to the all-systems group; IGMPv3 Reports go to the
# IGMPv3-routers group; an IGMPv2 Leave Group goes to the all-routers
# group.
IGMP__ALL_SYSTEMS = Ip4Address("224.0.0.1")
IGMP__ALL_ROUTERS = Ip4Address("224.0.0.2")
IGMP__ALL_IGMPV3_ROUTERS = Ip4Address("224.0.0.22")

# The IGMP link-local control groups a system never reports membership
# in (RFC 3376 §6): the all-systems group every host belongs to, and
# the all-routers / all-IGMPv3-routers groups a querier receives on. An
# interface may listen on these (for control traffic) without ever
# emitting a Membership Report for them.
IGMP__CONTROL_GROUPS = frozenset({IGMP__ALL_SYSTEMS, IGMP__ALL_ROUTERS, IGMP__ALL_IGMPV3_ROUTERS})


@dataclass(frozen=True, kw_only=True, slots=True)
class _IgmpPendingChange:
    """
    A pending IGMPv3 state-change for one group awaiting robustness
    retransmission — the source-bearing §5.1 difference records to
    re-send in IGMPv3 mode, the coarse join/leave record type to re-send
    in an IGMPv1/v2 compatibility mode (None for a source-only change
    that an older-version host cannot express), and the number of
    retransmissions still owed.
    """

    records: tuple[IgmpV3GroupRecord, ...]
    coarse_type: IgmpV3RecordType | None
    remaining: int


@dataclass(kw_only=True, slots=True)
class _QuerierGroupState:
    """
    The querier's router-side reception state for one downstream
    multicast group (RFC 3376 §6.2): the filter mode, the associated
    source list, and the Group Membership Interval timer that expires
    the whole group when no Report refreshes it.

    PyTCP tracks membership at group granularity — the per-source
    timers of RFC 3376 §6.2.1 (which let individual sources of an
    EXCLUDE group age out independently) collapse into the single group
    timer. Phase 2: per-source timers.
    """

    filter_mode: Ip4MulticastFilterMode
    sources: frozenset[Ip4Address]
    group_timer_handle: TimerHandle | None = None
    fast_leave_handle: TimerHandle | None = None
    fast_leave_remaining: int = 0


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpQuerierMembership:
    """
    An immutable snapshot of one router-learned multicast group
    membership — the read-only introspection view of the querier's
    downstream reception state (the '/proc/net/igmp' router equivalent).
    """

    group: Ip4Address
    filter_mode: Ip4MulticastFilterMode
    sources: frozenset[Ip4Address]


class IgmpTxHandler:
    """
    The outbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"
    _igmp_state_change__pending: dict[Ip4Address, _IgmpPendingChange]
    _igmp_state_change__handle: TimerHandle | None
    _igmp_querier__active: bool
    _igmp_querier__is_querier: bool
    _igmp_querier__handle: TimerHandle | None
    _igmp_querier__other_present_handle: TimerHandle | None
    _igmp_querier__startup_remaining: int
    _igmp_querier__memberships: dict[Ip4Address, _QuerierGroupState]

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface
        self._igmp_state_change__pending = {}
        self._igmp_state_change__handle = None
        self._igmp_querier__active = False
        self._igmp_querier__is_querier = False
        self._igmp_querier__handle = None
        self._igmp_querier__other_present_handle = None
        self._igmp_querier__startup_remaining = 0
        self._igmp_querier__memberships = {}

    def _current_state_record(self, group: Ip4Address, /) -> IgmpV3GroupRecord | None:
        """
        Build the IGMPv3 Current-State Record for 'group' from its merged
        interface filter (RFC 3376 §4.2.12 / §5.2): MODE_IS_EXCLUDE or
        MODE_IS_INCLUDE carrying the group's source list. Returns None
        when the interface has no reception state for the group.
        """

        with self._if._lock__multicast:
            filter_ = self._if._ip4_multicast_filters.get(group)

        if filter_ is None:
            return None

        record_type = (
            IgmpV3RecordType.MODE_IS_EXCLUDE
            if filter_.mode is Ip4MulticastFilterMode.EXCLUDE
            else IgmpV3RecordType.MODE_IS_INCLUDE
        )
        return IgmpV3GroupRecord(
            type=record_type,
            multicast_address=group,
            source_addresses=sorted(filter_.sources, key=int),
        )

    def _send_igmp_v3_report(self) -> None:
        """
        Send an IGMPv3 Membership Report describing the interface's
        current multicast reception state — one Current-State Record per
        joined group carrying its real filter mode + source list (RFC
        3376 §5.2 expiry rule 1), excluding the all-systems group
        224.0.0.1 which is never reported (RFC 3376 §6).
        """

        # Dedup while preserving join order; the all-systems group is
        # exempt from reporting.
        records = [
            record
            for group in dict.fromkeys(self._if._ip4_multicast)
            if group not in IGMP__CONTROL_GROUPS and (record := self._current_state_record(group)) is not None
        ]

        self._emit_v3_report(records)

    def _send_igmp_leave_all(self) -> None:
        """
        Emit a single combined IGMPv3 state-change Report transitioning
        every joined group (except the permanent all-systems group
        224.0.0.1, never reported per RFC 3376 §6) to INCLUDE{} — the
        graceful Leave a host sends on shutdown so routers prune its
        memberships immediately rather than waiting for a query timeout
        (RFC 3376 §5.1; Linux 'ip_mc_down'). No robustness retransmits
        are scheduled: this runs during teardown with the timer about to
        stop, and a report carrying no records is not emitted.
        """

        records = [
            IgmpV3GroupRecord(type=IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE, multicast_address=group)
            for group in dict.fromkeys(self._if._ip4_multicast)
            if group not in IGMP__CONTROL_GROUPS
        ]

        self._emit_v3_report(records)

    @staticmethod
    def _state_change_records(
        group: Ip4Address,
        old: Ip4MulticastFilter,
        new: Ip4MulticastFilter,
        /,
    ) -> list[IgmpV3GroupRecord]:
        """
        Compute the IGMPv3 difference records for a group's filter change
        per the RFC 3376 §5.1 table (the "non-existent" state is
        INCLUDE{}): a filter-mode change yields one
        CHANGE_TO_INCLUDE_MODE / CHANGE_TO_EXCLUDE_MODE record carrying
        the new source list; a within-mode source change yields
        ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES records (empty ones are
        omitted).
        """

        if old.mode is new.mode:
            if old.mode is Ip4MulticastFilterMode.INCLUDE:
                allow, block = new.sources - old.sources, old.sources - new.sources
            else:
                allow, block = old.sources - new.sources, new.sources - old.sources
            records: list[IgmpV3GroupRecord] = []
            if allow:
                records.append(
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.ALLOW_NEW_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(allow, key=int),
                    )
                )
            if block:
                records.append(
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.BLOCK_OLD_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(block, key=int),
                    )
                )
            return records

        record_type = (
            IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE
            if new.mode is Ip4MulticastFilterMode.EXCLUDE
            else IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE
        )
        return [
            IgmpV3GroupRecord(
                type=record_type,
                multicast_address=group,
                source_addresses=sorted(new.sources, key=int),
            )
        ]

    def _send_igmp_state_change(
        self,
        group: Ip4Address,
        /,
        *,
        old: Ip4MulticastFilter,
        new: Ip4MulticastFilter,
    ) -> None:
        """
        Emit an unsolicited state-change report for 'group' describing
        the transition from filter 'old' to filter 'new' (RFC 3376 §5.1)
        in the form dictated by the interface's Host Compatibility Mode
        (§7), and schedule its robustness retransmissions. In IGMPv3 mode
        the report carries the source-bearing §5.1 difference records; in
        an IGMPv1/v2 mode it degrades to the coarse join Membership Report
        / leave (those versions have no source concept). The all-systems
        group 224.0.0.1 is never reported (RFC 3376 §6).

        A new change supersedes any retransmit train still pending for the
        same group (overwrite + re-seed) — the PyTCP simplification of the
        §5.1 difference-report merge. A change that produces no record
        (an idempotent re-add) schedules no retransmit.
        """

        if group in IGMP__CONTROL_GROUPS:
            return

        records = self._state_change_records(group, old, new)
        # The coarse IGMPv1/v2 form keys only off the reception edge — a
        # source-only change within a still-joined membership (coarse_type
        # None) is invisible to an older-version querier.
        coarse_type = (
            IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE
            if new.has_reception and not old.has_reception
            else IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE if old.has_reception and not new.has_reception else None
        )

        if self._if._igmp_host_compatibility_mode() is IgmpVersion.V3:
            self._emit_v3_report(records)
        elif coarse_type is not None:
            self._emit_state_change(group, coarse_type)

        repeats = igmp__constants.IGMP__ROBUSTNESS_VARIABLE - 1
        if not records or repeats <= 0:
            self._igmp_state_change__pending.pop(group, None)
            return

        self._igmp_state_change__pending[group] = _IgmpPendingChange(
            records=tuple(records),
            coarse_type=coarse_type,
            remaining=repeats,
        )
        self._arm_state_change_retransmit()

    def _arm_state_change_retransmit(self) -> None:
        """
        Ensure a single retransmit ticket is scheduled for the pending
        state-change records. RFC 3376 §5.1 spaces the robustness
        retransmissions at intervals drawn uniformly at random from (0,
        'igmp.unsolicited_report_interval' ms]; the ticket re-arms itself
        from each fire (the Linux 'igmp_ifc_timer' model) rather than
        scheduling the whole train up front, so a change arriving
        mid-train is picked up by the next fire. Reading the interval
        knob via qualified module access so an operator override resolves
        on each re-arm.
        """

        if self._igmp_state_change__handle is not None:
            return

        delay_ms = random.randint(1, igmp__constants.IGMP__UNSOLICITED_REPORT_INTERVAL__MS)
        self._igmp_state_change__handle = stack.timer.call_later(delay_ms, self._fire_state_change_retransmit)

    def _fire_state_change_retransmit(self) -> None:
        """
        Emit one robustness retransmission of the currently-pending
        state-change records in the current Host Compatibility Mode's
        form — IGMPv3 coalesces them into a single Report, IGMPv1/v2 emit
        one per group (recomputed from the live mode + pending-change
        map, so a superseded change carries its latest form) — then
        decrement each entry's remaining-repeat count, drop the exhausted
        ones, and re-arm the ticket while any repeats remain (RFC 3376
        §5.1 / §7).
        """

        # Runs on the Timer thread. The pending per-group change map and
        # the Host Compatibility Mode deadlines are mutated / written by
        # the RX and application threads under the interface multicast
        # lock, so this fire takes the same lock — without it a
        # free-threaded build could tear the map mid-iteration or read a
        # half-updated compat mode (the RLock is reentrant, so the nested
        # '_igmp_host_compatibility_mode' / '_emit_state_change' reads are
        # fine).
        with self._if._lock__multicast:
            self._igmp_state_change__handle = None

            groups = list(self._igmp_state_change__pending)

            if self._if._igmp_host_compatibility_mode() is IgmpVersion.V3:
                records: list[IgmpV3GroupRecord] = []
                for group in groups:
                    records.extend(self._igmp_state_change__pending[group].records)
                self._emit_v3_report(records)
            else:
                for group in groups:
                    coarse_type = self._igmp_state_change__pending[group].coarse_type
                    if coarse_type is not None:
                        self._emit_state_change(group, coarse_type)

            for group in groups:
                pending = self._igmp_state_change__pending[group]
                if pending.remaining <= 1:
                    del self._igmp_state_change__pending[group]
                else:
                    self._igmp_state_change__pending[group] = _IgmpPendingChange(
                        records=pending.records,
                        coarse_type=pending.coarse_type,
                        remaining=pending.remaining - 1,
                    )

            if self._igmp_state_change__pending:
                self._arm_state_change_retransmit()

    def _cancel_state_change_retransmits(self) -> None:
        """
        Cancel the in-flight state-change retransmit ticket and drop
        every pending per-group change record (RFC 3376 §7.2.1 — a
        compatibility-mode change cancels all pending retransmissions).
        """

        if self._igmp_state_change__handle is not None:
            stack.timer.cancel(self._igmp_state_change__handle)
            self._igmp_state_change__handle = None
        self._igmp_state_change__pending.clear()

    def refresh_querier(self) -> None:
        """
        Reconcile the interface's IGMP querier role with its
        'igmp.mc_forwarding' switch: start the querier when the
        interface is (newly) a multicast router, stop it when the
        switch is cleared. Idempotent — a no-op when already in the
        target state. Called at interface bring-up and by the test
        harness (there is no runtime sysctl-change hook — an operator
        sets 'igmp.mc_forwarding' before bring-up; Phase 2: a control
        API drives this at runtime).

        Reference: RFC 3376 §6 (a multicast router acts as querier).
        """

        with self._if._lock__multicast:
            enabled = bool(sysctl_iface.get_for_iface("igmp.mc_forwarding", self._if._interface_name))
            if enabled and not self._igmp_querier__active:
                self._start_querier()
            elif not enabled and self._igmp_querier__active:
                self._stop_querier()

    def _start_querier(self) -> None:
        """
        Become a multicast router and take up the querier role: a router
        begins in the Querier state (RFC 3376 §6.6.2), sending the first
        of the §8.7 Startup Query Count General Queries and arming the
        re-arming General-Query ticket. Runs under the interface
        multicast lock.

        Phase 2: a querier must also receive Membership Reports on the
        all-IGMPv3-routers group 224.0.0.22 (a receive-only admission
        that, unlike a host join, is never itself reported); that RX-group
        admission is done here — see '_admit_querier_receive_group'.
        """

        self._admit_querier_receive_group()
        self._igmp_querier__active = True
        self._igmp_querier__is_querier = True
        self._igmp_querier__startup_remaining = max(1, igmp__constants.IGMP__STARTUP_QUERY_COUNT)
        self._send_general_query_and_rearm()

    def _admit_querier_receive_group(self) -> None:
        """
        Receive-only admission of the router control groups the querier
        receives on (the interface's reception filter + Ethernet
        multicast MAC): the all-IGMPv3-routers group 224.0.0.22 (v3
        Membership Reports) and the all-routers group 224.0.0.2 (v2 Leave
        Group / Report). They are IGMP control groups (IGMP__CONTROL_GROUPS)
        the interface never reports membership in, so — unlike a host join
        — no Report is emitted for them. Runs under the interface
        multicast lock.
        """

        for group in (IGMP__ALL_IGMPV3_ROUTERS, IGMP__ALL_ROUTERS):
            if group not in self._if._ip4_multicast_filters:
                self._if._assign_ip4_multicast(group)

    def _withdraw_querier_receive_group(self) -> None:
        """
        Undo '_admit_querier_receive_group' when the interface stops
        being a multicast router. Runs under the interface multicast
        lock.
        """

        for group in (IGMP__ALL_IGMPV3_ROUTERS, IGMP__ALL_ROUTERS):
            if group in self._if._ip4_multicast_filters:
                self._if._remove_ip4_multicast(group)

    def _stop_querier(self) -> None:
        """
        Stop being a multicast router: cancel the pending General-Query
        and Other-Querier-Present tickets and clear the querier state.
        Runs under the interface multicast lock.
        """

        self._igmp_querier__active = False
        self._igmp_querier__is_querier = False
        self._igmp_querier__startup_remaining = 0
        if self._igmp_querier__handle is not None:
            stack.timer.cancel(self._igmp_querier__handle)
            self._igmp_querier__handle = None
        if self._igmp_querier__other_present_handle is not None:
            stack.timer.cancel(self._igmp_querier__other_present_handle)
            self._igmp_querier__other_present_handle = None
        for state in self._igmp_querier__memberships.values():
            if state.group_timer_handle is not None:
                stack.timer.cancel(state.group_timer_handle)
            if state.fast_leave_handle is not None:
                stack.timer.cancel(state.fast_leave_handle)
        self._igmp_querier__memberships.clear()
        self._withdraw_querier_receive_group()

    def _fire_general_query(self) -> None:
        """
        Timer callback: emit one periodic General Query and re-arm.
        Takes the interface multicast lock so a concurrent
        'refresh_querier' / stop / election step-down on another thread
        cannot tear the querier state, and bails when the role was
        relinquished or lost while the ticket was in flight.

        Reference: RFC 3376 §6 (querier General Query interval).
        """

        with self._if._lock__multicast:
            self._igmp_querier__handle = None
            if not (self._igmp_querier__active and self._igmp_querier__is_querier):
                return
            self._send_general_query_and_rearm()

    def observe_query(self, source: Ip4Address, query: IgmpMessageQuery, /) -> None:
        """
        Apply the RFC 3376 §6.6.2 / RFC 2236 §3 querier-election rule to
        an inbound Query seen on this interface: the router with the
        numerically lowest interface address on the link is the Querier.
        When a Query arrives from a source lower than our own address we
        step down to Non-Querier and (re)arm the Other Querier Present
        timer. A no-op on an interface that is not a multicast router.

        Reference: RFC 3376 §6.6.2 (querier election — lowest address wins).
        Reference: RFC 3376 §8.5 (Other Querier Present Interval).
        """

        with self._if._lock__multicast:
            if not self._igmp_querier__active:
                return

            our_address = self._if._ip4_unicast[0] if self._if._ip4_unicast else Ip4Address()
            if int(source) >= int(our_address):
                return

            self._become_non_querier(query)

    def _become_non_querier(self, query: IgmpMessageQuery, /) -> None:
        """
        Step down to the Non-Querier state: stop emitting General Queries
        and (re)arm the Other Querier Present timer from the electing
        Query's advertised values. Runs under the interface multicast
        lock.
        """

        self._igmp_querier__is_querier = False
        self._igmp_querier__startup_remaining = 0
        if self._igmp_querier__handle is not None:
            stack.timer.cancel(self._igmp_querier__handle)
            self._igmp_querier__handle = None

        if self._igmp_querier__other_present_handle is not None:
            stack.timer.cancel(self._igmp_querier__other_present_handle)

        self._igmp_querier__other_present_handle = stack.timer.call_later(
            self._other_querier_present_interval_ms(query),
            self._fire_other_querier_present,
        )
        self._if._packet_stats_rx.igmp__querier__election_lost += 1

    def _fire_other_querier_present(self) -> None:
        """
        Timer callback: the elected querier has gone silent for the Other
        Querier Present Interval, so resume the Querier role (RFC 3376
        §6.6.2). Takes the interface multicast lock and bails if this
        interface is no longer a multicast router.
        """

        with self._if._lock__multicast:
            self._igmp_querier__other_present_handle = None
            if not self._igmp_querier__active:
                return
            self._igmp_querier__is_querier = True
            self._igmp_querier__startup_remaining = max(1, igmp__constants.IGMP__STARTUP_QUERY_COUNT)
            self._send_general_query_and_rearm()

    @staticmethod
    def _other_querier_present_interval_ms(query: IgmpMessageQuery, /) -> int:
        """
        Compute the RFC 3376 §8.5 Other Querier Present Interval — the
        Robustness Variable × Query Interval + one half of the Query
        Response Interval — from the electing Query's advertised QRV /
        QQIC / Max Resp Code, falling back to the configured defaults for
        an IGMPv1/v2 Query that carries none.
        """

        qrv = query.qrv or igmp__constants.IGMP__ROBUSTNESS_VARIABLE
        query_interval_sec = query.querier_query_interval or (igmp__constants.IGMP__QUERY_INTERVAL__MS // 1000)
        # Max Resp Code decodes to units of 1/10 s; the RX Query Response
        # Interval is that value in ms.
        query_response_ms = query.max_response_time * 100 or igmp__constants.IGMP__QUERY_RESPONSE_INTERVAL__MS

        return qrv * query_interval_sec * 1000 + query_response_ms // 2

    # --- Router-side group-membership table (RFC 3376 §6.4) ----------

    def observe_report(self, message: IgmpMessage, /) -> None:
        """
        Learn downstream multicast reception state from an inbound
        Membership Report (RFC 3376 §6.4). An IGMPv3 Report contributes
        one group record per group; a legacy IGMPv1/v2 Membership Report
        is an EXCLUDE{} join for its group. A no-op on an interface that
        is not a multicast router. Populated only from inbound Reports —
        never from this stack's own host joins (which live in the
        separate '_ip4_multicast_refs' host table).

        Reference: RFC 3376 §6.4 (router action on reception of a Report).
        """

        with self._if._lock__multicast:
            if not self._igmp_querier__active:
                return

            learned = False
            if isinstance(message, IgmpMessageV3Report):
                for record in message.records:
                    learned |= self._process_group_record(
                        record.multicast_address, record.type, frozenset(record.source_addresses)
                    )
            elif isinstance(message, (IgmpMessageV1Report, IgmpMessageV2Report)):
                # A v1/v2 Membership Report is an EXCLUDE{} join (RFC 3376
                # §7.3.2 — an older-version host wants the whole group).
                learned = self._process_group_record(
                    message.group_address, IgmpV3RecordType.MODE_IS_EXCLUDE, frozenset()
                )
            elif isinstance(message, IgmpMessageV2Leave):
                # RFC 2236 §3 — a v2 Leave Group triggers fast-leave
                # Group-Specific Queries for the group being left.
                if self._igmp_querier__memberships.get(message.group_address) is not None:
                    self._start_group_fast_leave(message.group_address)
                    learned = True

            if learned:
                self._if._packet_stats_rx.igmp__querier__member_report += 1

    def _process_group_record(
        self,
        group: Ip4Address,
        record_type: IgmpV3RecordType,
        sources: frozenset[Ip4Address],
        /,
    ) -> bool:
        """
        Apply one IGMPv3 group record to the router membership table and
        report whether it updated reception state. The all-systems group
        224.0.0.1 is never tracked (RFC 3376 §6). Runs under the
        interface multicast lock.
        """

        if group in IGMP__CONTROL_GROUPS:
            return False

        match record_type:
            case IgmpV3RecordType.MODE_IS_EXCLUDE | IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE:
                self._set_membership(group, Ip4MulticastFilterMode.EXCLUDE, sources)
                return True
            case IgmpV3RecordType.MODE_IS_INCLUDE | IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE:
                # INCLUDE{} is a leave — trigger fast-leave Group-Specific
                # Queries rather than pruning immediately, so another
                # listener on the link can re-assert (RFC 3376 §6.4.2).
                if not sources:
                    if self._igmp_querier__memberships.get(group) is None:
                        return False
                    self._start_group_fast_leave(group)
                    return True
                self._set_membership(group, Ip4MulticastFilterMode.INCLUDE, sources)
                return True
            case IgmpV3RecordType.ALLOW_NEW_SOURCES:
                state = self._igmp_querier__memberships.get(group)
                if state is None:
                    self._set_membership(group, Ip4MulticastFilterMode.INCLUDE, sources)
                elif state.filter_mode is Ip4MulticastFilterMode.INCLUDE:
                    self._set_membership(group, Ip4MulticastFilterMode.INCLUDE, state.sources | sources)
                else:
                    self._set_membership(group, Ip4MulticastFilterMode.EXCLUDE, state.sources - sources)
                return True
            case IgmpV3RecordType.BLOCK_OLD_SOURCES:
                # A BLOCK narrows an INCLUDE source list; blocking the last
                # source is a group leave, so it triggers fast-leave
                # (RFC 3376 §6.4.2). Phase 2: per-source Group-and-Source-
                # Specific Queries for a partial block.
                state = self._igmp_querier__memberships.get(group)
                if state is None or state.filter_mode is not Ip4MulticastFilterMode.INCLUDE:
                    return False
                remaining = state.sources - sources
                if remaining:
                    state.sources = remaining
                else:
                    self._start_group_fast_leave(group)
                return True

        return False

    def _set_membership(
        self,
        group: Ip4Address,
        filter_mode: Ip4MulticastFilterMode,
        sources: frozenset[Ip4Address],
        /,
    ) -> None:
        """
        Install or refresh the router membership entry for 'group' and
        (re)arm its Group Membership Interval timer. Runs under the
        interface multicast lock.
        """

        state = self._igmp_querier__memberships.get(group)
        if state is None:
            state = _QuerierGroupState(filter_mode=filter_mode, sources=sources)
            self._igmp_querier__memberships[group] = state
        else:
            state.filter_mode = filter_mode
            state.sources = sources

        if state.group_timer_handle is not None:
            stack.timer.cancel(state.group_timer_handle)
        state.group_timer_handle = stack.timer.call_later(
            self._group_membership_interval_ms(), self._expire_group, group
        )

        # A refreshing Report re-asserts interest — cancel any in-flight
        # fast-leave Group-Specific Query train (RFC 3376 §6.4.2).
        if state.fast_leave_handle is not None:
            stack.timer.cancel(state.fast_leave_handle)
            state.fast_leave_handle = None
        state.fast_leave_remaining = 0

    def _start_group_fast_leave(self, group: Ip4Address, /) -> None:
        """
        Begin the RFC 3376 §6.4.2 fast-leave for 'group': lower its group
        timer to the Last Member Query Time (§8.8 × §8.9) so it is pruned
        quickly if no listener re-asserts, then send the first of the
        §8.9 Last Member Query Count Group-Specific Queries and arm the
        rest at the §8.8 Last Member Query Interval. Runs under the
        interface multicast lock.
        """

        state = self._igmp_querier__memberships.get(group)
        if state is None:
            return

        lmqi = igmp__constants.IGMP__LAST_MEMBER_QUERY_INTERVAL__MS
        lmqc = max(1, igmp__constants.IGMP__LAST_MEMBER_QUERY_COUNT)

        if state.group_timer_handle is not None:
            stack.timer.cancel(state.group_timer_handle)
        state.group_timer_handle = stack.timer.call_later(lmqi * lmqc, self._expire_group, group)

        self._send_igmp_group_specific_query(group)
        state.fast_leave_remaining = lmqc - 1
        if state.fast_leave_handle is not None:
            stack.timer.cancel(state.fast_leave_handle)
            state.fast_leave_handle = None
        if state.fast_leave_remaining > 0:
            state.fast_leave_handle = stack.timer.call_later(lmqi, self._fire_group_fast_leave, group)

    def _fire_group_fast_leave(self, group: Ip4Address, /) -> None:
        """
        Timer callback: emit one more Group-Specific Query of the
        fast-leave train and re-arm while any remain. Takes the interface
        multicast lock and bails if the group was pruned or re-asserted.
        """

        with self._if._lock__multicast:
            state = self._igmp_querier__memberships.get(group)
            if state is None:
                return
            state.fast_leave_handle = None
            if state.fast_leave_remaining <= 0:
                return
            self._send_igmp_group_specific_query(group)
            state.fast_leave_remaining -= 1
            if state.fast_leave_remaining > 0:
                state.fast_leave_handle = stack.timer.call_later(
                    igmp__constants.IGMP__LAST_MEMBER_QUERY_INTERVAL__MS, self._fire_group_fast_leave, group
                )

    def _send_igmp_group_specific_query(self, group: Ip4Address, /) -> None:
        """
        Emit an IGMPv3 Group-Specific Query for 'group' to the group
        address itself, advertising the Last Member Query Interval as its
        Max Resp Code (RFC 3376 §4.1 / §6.4.2).
        """

        message = IgmpMessageQuery(
            version=IgmpVersion.V3,
            max_resp_code=encode_igmp_float_code(igmp__constants.IGMP__LAST_MEMBER_QUERY_INTERVAL__MS // 100),
            group_address=group,
            qrv=igmp__constants.IGMP__ROBUSTNESS_VARIABLE & 0x07,
            qqic=encode_igmp_float_code(igmp__constants.IGMP__QUERY_INTERVAL__MS // 1000),
        )

        self._if._packet_stats_tx.igmp__group_query__send += 1
        self._emit_igmp(message, group)

    def _remove_membership(self, group: Ip4Address, /) -> bool:
        """
        Drop the router membership entry for 'group' and cancel its
        timers, reporting whether an entry existed. Runs under the
        interface multicast lock.
        """

        state = self._igmp_querier__memberships.pop(group, None)
        if state is None:
            return False
        if state.group_timer_handle is not None:
            stack.timer.cancel(state.group_timer_handle)
        if state.fast_leave_handle is not None:
            stack.timer.cancel(state.fast_leave_handle)
        return True

    def _expire_group(self, group: Ip4Address, /) -> None:
        """
        Group Membership Interval timer callback: no Report refreshed the
        group within the interval, so the last listener is assumed gone
        and the group is pruned (RFC 3376 §6.5). Takes the interface
        multicast lock.
        """

        with self._if._lock__multicast:
            state = self._igmp_querier__memberships.get(group)
            if state is None:
                return
            state.group_timer_handle = None
            if state.fast_leave_handle is not None:
                stack.timer.cancel(state.fast_leave_handle)
                state.fast_leave_handle = None
            del self._igmp_querier__memberships[group]

    @staticmethod
    def _group_membership_interval_ms() -> int:
        """
        The RFC 3376 §8.4 Group Membership Interval — Robustness Variable
        × Query Interval + one Query Response Interval — after which a
        group with no refreshing Report is pruned.
        """

        return (
            igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS
            + igmp__constants.IGMP__QUERY_RESPONSE_INTERVAL__MS
        )

    def querier_memberships(self) -> tuple[IgmpQuerierMembership, ...]:
        """
        Return an immutable snapshot of the router's learned downstream
        multicast memberships (the read-only introspection surface).
        """

        with self._if._lock__multicast:
            return tuple(
                IgmpQuerierMembership(group=group, filter_mode=state.filter_mode, sources=state.sources)
                for group, state in self._igmp_querier__memberships.items()
            )

    def _send_general_query_and_rearm(self) -> None:
        """
        Emit one General Query and schedule the next: at the Startup
        Query Interval while the startup burst is draining (RFC 3376
        §8.6 / §8.7), then at the steady-state Query Interval (§8.2).
        Runs under the interface multicast lock.
        """

        self._send_igmp_general_query()

        if self._igmp_querier__startup_remaining > 1:
            self._igmp_querier__startup_remaining -= 1
            delay_ms = igmp__constants.IGMP__STARTUP_QUERY_INTERVAL__MS
        else:
            self._igmp_querier__startup_remaining = 0
            delay_ms = igmp__constants.IGMP__QUERY_INTERVAL__MS

        self._igmp_querier__handle = stack.timer.call_later(delay_ms, self._fire_general_query)

    def _send_igmp_general_query(self) -> None:
        """
        Emit an IGMPv3 General Query (group 0.0.0.0, no sources) to the
        all-systems group 224.0.0.1 with the querier's advertised Max
        Resp Code (Query Response Interval), QRV (Robustness Variable),
        and QQIC (Query Interval). The Max Resp Code / QQIC are encoded
        via the RFC 3376 §4.1.1 / §4.1.7 float form.

        Reference: RFC 3376 §4.1 (General Query fields).
        Reference: RFC 3376 §8.3 (Query Response Interval — Max Resp Code).
        """

        message = IgmpMessageQuery(
            version=IgmpVersion.V3,
            max_resp_code=encode_igmp_float_code(igmp__constants.IGMP__QUERY_RESPONSE_INTERVAL__MS // 100),
            group_address=Ip4Address(),
            qrv=igmp__constants.IGMP__ROBUSTNESS_VARIABLE & 0x07,
            qqic=encode_igmp_float_code(igmp__constants.IGMP__QUERY_INTERVAL__MS // 1000),
        )

        self._if._packet_stats_tx.igmp__general_query__send += 1
        self._emit_igmp(message, IGMP__ALL_SYSTEMS)

    def _emit_igmp(self, message: IgmpMessage, ip4__dst: Ip4Address, /) -> None:
        """
        Assemble 'message' and send it to 'ip4__dst' with the IPv4
        Router Alert option and TTL=1 (RFC 3376 §4 / RFC 2236 §2). Bumps
        the shared 'igmp__pre_assemble' counter; callers bump the
        per-form send counter.
        """

        igmp_packet_tx = IgmpAssembler(igmp__message=message)

        __debug__ and log("igmp", f"{igmp_packet_tx.tracker} - {igmp_packet_tx}")

        self._if._packet_stats_tx.igmp__pre_assemble += 1

        ip4__src = self._if._ip4_unicast[0] if self._if._ip4_unicast else Ip4Address()

        # Fire-and-forget: IGMP control messages are best-effort, and the
        # caller (an application join / leave, or the timer querier fire)
        # may hold the interface multicast lock while emitting. A blocking
        # dispatch would wedge that thread on the TX worker, which itself
        # re-enters the multicast lock to validate the report source —
        # a cross-thread deadlock. Queue-and-return breaks the cycle.
        self._if._marshal_tx_async(
            lambda: self._if._phtx_ip4(
                ip4__src=ip4__src,
                ip4__dst=ip4__dst,
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=igmp_packet_tx,
            )
        )

    def _emit_v3_report(self, records: list[IgmpV3GroupRecord], /) -> None:
        """
        Assemble and send an IGMPv3 Membership Report carrying 'records'
        to the all-IGMPv3-routers group 224.0.0.22 (RFC 3376 §4 / §9). A
        report with no records is not emitted.
        """

        if not records:
            return

        self._if._packet_stats_tx.igmp__v3_report__send += 1
        self._emit_igmp(IgmpMessageV3Report(records=records), IGMP__ALL_IGMPV3_ROUTERS)

    def _send_igmp_v3_group_current_state(self, group: Ip4Address, queried_sources: frozenset[Ip4Address], /) -> None:
        """
        Emit the IGMPv3 Current-State response for a Group-Specific or
        Group-and-Source-Specific Query on 'group' (RFC 3376 §5.2 expiry
        rules 2-3).

        With no 'queried_sources' (a Group-Specific Query) the response is
        the group's real current state (MODE_IS_INCLUDE / MODE_IS_EXCLUDE
        + source list). With 'queried_sources' B (a Group-and-Source-
        Specific Query) the §5.2 rule-3 table applies: an INCLUDE(A)
        interface answers IS_IN(A∩B), an EXCLUDE(A) interface answers
        IS_IN(B−A); an empty result sends no response.
        """

        with self._if._lock__multicast:
            filter_ = self._if._ip4_multicast_filters.get(group)

        if filter_ is None:
            return

        if not queried_sources:
            record = self._current_state_record(group)
            if record is not None:
                self._emit_v3_report([record])
            return

        if filter_.mode is Ip4MulticastFilterMode.INCLUDE:
            answer = filter_.sources & queried_sources
        else:
            answer = queried_sources - filter_.sources
        if not answer:
            return

        self._emit_v3_report(
            [
                IgmpV3GroupRecord(
                    type=IgmpV3RecordType.MODE_IS_INCLUDE,
                    multicast_address=group,
                    source_addresses=sorted(answer, key=int),
                )
            ]
        )

    def _emit_group_membership_report(self, group: Ip4Address, version: IgmpVersion, /) -> None:
        """
        Emit a per-group IGMPv1 / IGMPv2 Membership Report to the group
        address — the older-version compatibility-mode form (RFC 2236
        §3 / RFC 1112 §6). The all-systems group 224.0.0.1 is never
        reported (RFC 3376 §6).
        """

        if group in IGMP__CONTROL_GROUPS:
            return

        if version is IgmpVersion.V2:
            self._if._packet_stats_tx.igmp__v2_report__send += 1
            self._emit_igmp(IgmpMessageV2Report(group_address=group), group)
        else:
            self._if._packet_stats_tx.igmp__v1_report__send += 1
            self._emit_igmp(IgmpMessageV1Report(group_address=group), group)

    def _emit_v2_leave(self, group: Ip4Address, /) -> None:
        """
        Emit an IGMPv2 Leave Group for 'group' to the all-routers group
        224.0.0.2 (RFC 2236 §3).
        """

        self._if._packet_stats_tx.igmp__v2_leave__send += 1
        self._emit_igmp(IgmpMessageV2Leave(group_address=group), IGMP__ALL_ROUTERS)

    def _emit_state_change(self, group: Ip4Address, record_type: IgmpV3RecordType, /) -> bool:
        """
        Emit one state-change report for 'group' in the form dictated by
        the interface's RFC 3376 §7.2.1 Host Compatibility Mode, and
        return whether a packet was actually emitted:

        - IGMPv3: a single-record Membership Report (CHANGE_TO_EXCLUDE on
          join, CHANGE_TO_INCLUDE on leave) to 224.0.0.22.
        - IGMPv2: a per-group Membership Report to the group on join, an
          IGMPv2 Leave Group to 224.0.0.2 on leave (RFC 2236 §3).
        - IGMPv1: a per-group Membership Report on join; nothing on leave
          (IGMPv1 has no Leave message → returns False).
        """

        mode = self._if._igmp_host_compatibility_mode()
        is_leave = record_type is IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE

        if mode is IgmpVersion.V3:
            self._emit_v3_report([IgmpV3GroupRecord(type=record_type, multicast_address=group)])
            return True
        if mode is IgmpVersion.V2:
            if is_leave:
                self._emit_v2_leave(group)
            else:
                self._emit_group_membership_report(group, IgmpVersion.V2)
            return True
        if not is_leave:  # IGMPv1 join only; v1 has no Leave message
            self._emit_group_membership_report(group, IgmpVersion.V1)
            return True
        return False
