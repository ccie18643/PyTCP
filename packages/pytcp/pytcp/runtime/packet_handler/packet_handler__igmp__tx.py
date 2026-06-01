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


"""
This module contains the outbound IGMP packet handler for one
interface.

pytcp/runtime/packet_handler/packet_handler__igmp__tx.py

ver 3.0.8
"""

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    IgmpAssembler,
    IgmpMessage,
    IgmpMessageV1Report,
    IgmpMessageV2Leave,
    IgmpMessageV2Report,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpV3RecordType,
    IgmpVersion,
    Ip4OptionRouterAlert,
    Ip4Options,
)
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants
from pytcp.runtime.timer import TimerHandle

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv4 destinations defined by RFC 3376 §4 / RFC 2236 §3: every
# host belongs to the all-systems group; IGMPv3 Reports go to the
# IGMPv3-routers group; an IGMPv2 Leave Group goes to the all-routers
# group.
IGMP__ALL_SYSTEMS = Ip4Address("224.0.0.1")
IGMP__ALL_ROUTERS = Ip4Address("224.0.0.2")
IGMP__ALL_IGMPV3_ROUTERS = Ip4Address("224.0.0.22")


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


class IgmpTxHandler:
    """
    The outbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"
    _igmp_state_change__pending: dict[Ip4Address, _IgmpPendingChange]
    _igmp_state_change__handle: TimerHandle | None

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface
        self._igmp_state_change__pending = {}
        self._igmp_state_change__handle = None

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
            if group != IGMP__ALL_SYSTEMS and (record := self._current_state_record(group)) is not None
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
            if group != IGMP__ALL_SYSTEMS
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

        if group == IGMP__ALL_SYSTEMS:
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

        self._if._marshal_tx(
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

        if group == IGMP__ALL_SYSTEMS:
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
