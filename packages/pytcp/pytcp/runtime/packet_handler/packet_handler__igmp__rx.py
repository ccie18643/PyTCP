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
This module contains the inbound IGMP packet handler for one interface.

pytcp/runtime/packet_handler/packet_handler__igmp__rx.py

ver 3.0.9
"""

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    IgmpMessageV1Report,
    IgmpMessageV2Report,
    IgmpType,
    IgmpVersion,
    PacketValidationError,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants
from pytcp.runtime.timer import TimerHandle

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# IGMP Max Resp Time is expressed in units of 1/10 second (RFC 3376
# §4.1.1); the host state machine works in milliseconds.
IGMP__MAX_RESP_TIME__UNIT_MS = 100


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpGroupQueryPending:
    """
    A pending per-group response to a Group-Specific or Group-and-Source-
    Specific Query (RFC 3376 §5.2): the absolute 'stack.timer.now_ms'
    deadline, the scheduled timer handle, and the recorded queried-source
    list (empty for a Group-Specific Query) used to build the response.
    """

    respond_at_ms: int
    handle: TimerHandle
    sources: frozenset[Ip4Address]


class IgmpRxHandler:
    """
    The inbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_igmp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IGMP packet — parse it, then dispatch a
        Membership Query to the query-response state machine. Reports
        and Leaves received from other hosts are counted and ignored
        (a host does not act on another host's Report; IGMPv3 has no
        Report suppression, and v2 suppression is deferred).
        """

        self._if._packet_stats_rx.igmp__pre_parse += 1

        # RFC 3376 §4 — IGMP messages are sent with an IP TTL of 1; Linux
        # drops inbound IGMP with TTL != 1 as martian. The Router Alert
        # option is NOT required on receipt (IGMPv2 senders predate it),
        # matching Linux leniency.
        if packet_rx.ip4.ttl != 1:
            __debug__ and log(
                "igmp",
                f"{packet_rx.tracker} - <CRIT>Dropping IGMP with TTL {packet_rx.ip4.ttl} (expected 1)</>",
            )
            self._if._packet_stats_rx.igmp__ttl_invalid__drop += 1
            return

        try:
            IgmpParser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log("igmp", f"{packet_rx.tracker} - <CRIT>{error}</>")
            self._if._packet_stats_rx.igmp__failed_parse__drop += 1
            return

        __debug__ and log("igmp", f"{packet_rx.tracker} - {packet_rx.igmp}")

        match packet_rx.igmp.message.type:
            case IgmpType.MEMBERSHIP_QUERY:
                self.__phrx_igmp__membership_query(packet_rx)
            case _:
                self.__phrx_igmp__report(packet_rx)

    def __phrx_igmp__report(self, packet_rx: PacketRx) -> None:
        """
        Handle an inbound IGMP Report/Leave from another host.

        An IGMPv3 host does not suppress its reports (RFC 3376 §7.2.2 is
        a MAY) — it counts and ignores. In IGMPv1/v2 compatibility mode
        (RFC 2236 §3), hearing another host's v1/v2 Membership Report for
        a group this host has joined, while a Query response is pending,
        suppresses this host's own pending Report for that group.
        """

        self._if._packet_stats_rx.igmp__membership_report += 1

        message = packet_rx.igmp.message

        # RFC 3376 §6.4 — when this interface is a multicast router, learn
        # downstream reception state from the Report into the querier
        # membership table (delegated to the TX querier state machine,
        # which owns that state; a no-op on a plain host interface).
        self._if._igmp_tx.observe_report(message)

        # Hold the interface IGMP/multicast lock across the query-response
        # state access (the pending-response scalar + suppressed-group
        # set) so the RX and timer threads cannot corrupt it on a no-GIL
        # build. Reentrant: '_ip4_multicast' re-acquires the same lock.
        with self._if._lock__multicast:
            if (
                self._if._igmp_host_compatibility_mode() is not IgmpVersion.V3
                and self._if._igmp_query__pending_response_at_ms is not None
                and isinstance(message, (IgmpMessageV1Report, IgmpMessageV2Report))
                and message.group_address in self._if._ip4_multicast
                and message.group_address not in self._if._igmp_query__suppressed_groups
            ):
                self._if._igmp_query__suppressed_groups.add(message.group_address)
                self._if._packet_stats_rx.igmp__membership_query__suppressed += 1
                __debug__ and log(
                    "igmp",
                    f"{packet_rx.tracker} - Suppressing pending Report for {message.group_address}",
                )
                return

        __debug__ and log(
            "igmp",
            f"{packet_rx.tracker} - Received IGMP Report/Leave from {packet_rx.ip4.src} (ignored)",
        )

    def __phrx_igmp__membership_query(self, packet_rx: PacketRx) -> None:
        """
        Handle an inbound IGMP Membership Query.

        Reference: RFC 3376 §5.2 (host Query-response state machine).

        The host schedules a current-state Report at a uniformly-random
        delay in [0, Max Resp Time] so a link with many members spreads
        its Report burst across the response window. A General Query
        uses the interface-wide timer (rules 1-2); a Group-Specific or
        Group-and-Source-Specific Query uses a per-group timer answering
        for only that group (rules 1, 3-5), recording the queried source
        list for the §5.2 rule-3 intersection math. The response form
        follows the Host Compatibility Mode (RFC 3376 §7).
        """

        self._if._packet_stats_rx.igmp__membership_query += 1
        __debug__ and log(
            "igmp",
            f"{packet_rx.tracker} - Received IGMP Membership Query from {packet_rx.ip4.src}",
        )

        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageQuery)

        # RFC 3376 §6.6.2 querier election — when this interface is a
        # multicast router, a Query from a lower source address makes us
        # step down to Non-Querier (delegated to the TX querier state
        # machine, which owns the election / Other-Querier-Present state).
        self._if._igmp_tx.observe_query(packet_rx.ip4.src, message)

        # Hold the interface IGMP/multicast lock across the whole
        # query-response scheduling (compatibility-mode update + pending
        # scalar / per-group map writes + timer arming) so the RX and
        # timer threads cannot corrupt the IGMP query-response state on a
        # no-GIL build. Reentrant — the scheduling reads '_ip4_multicast'
        # and emits reports that re-acquire the same lock.
        with self._if._lock__multicast:
            # RFC 3376 §7.2.1 — arm the Older Version Querier Present
            # timer and, on a mode change, cancel pending IGMP timers,
            # before scheduling this Query's response.
            self._igmp_update_compatibility_mode(message)

            max_resp_ms = message.max_response_time * IGMP__MAX_RESP_TIME__UNIT_MS
            delay_ms = self._igmp_query__pick_response_delay_ms(max_resp_ms)

            if message.is_general_query:
                self._igmp_query__schedule_general(delay_ms)
            else:
                self._igmp_query__schedule_group(message.group_address, frozenset(message.source_addresses), delay_ms)

    def _igmp_query__schedule_general(self, delay_ms: int, /) -> None:
        """
        Schedule (or absorb) the response to a General Query on the
        single interface-wide timer (RFC 3376 §5.2 rules 1-2). A delay of
        0 responds immediately (bypassing the timer, which only fires on
        a non-zero countdown); an already-pending General response sooner
        than the selected delay absorbs this Query, an earlier one
        supersedes it.
        """

        if delay_ms == 0:
            self._igmp_query__send_now()
            return

        response_at = stack.timer.now_ms + delay_ms
        pending = self._if._igmp_query__pending_response_at_ms
        if pending is not None and pending <= response_at:
            return

        if pending is not None:
            if self._if._igmp_query__handle is not None:
                stack.timer.cancel(self._if._igmp_query__handle)
            self._if._igmp_query__suppressed_groups.clear()
            self._if._packet_stats_rx.igmp__membership_query__superseded += 1

        self._if._igmp_query__pending_response_at_ms = response_at
        self._if._igmp_query__handle = stack.timer.call_later(delay_ms, self._igmp_query__deferred_send)
        self._if._packet_stats_rx.igmp__membership_query__scheduled += 1

    def _igmp_query__schedule_group(
        self,
        group: Ip4Address,
        sources: frozenset[Ip4Address],
        delay_ms: int,
        /,
    ) -> None:
        """
        Schedule (or absorb) the response to a Group-Specific or Group-
        and-Source-Specific Query on a per-group timer (RFC 3376 §5.2
        rules 1, 3-5). A General response scheduled sooner absorbs the
        Query (rule 1). Otherwise the per-group timer is armed (rule 3,
        recording the queried 'sources'), or merged with a pending
        per-group response: a Group-Specific Query or an empty recorded
        list clears the recorded sources (rule 4), a Group-and-Source-
        Specific Query augments them (rule 5), with the response set to
        the earliest of the pending and selected delays.
        """

        response_at = stack.timer.now_ms + delay_ms

        # Rule 1: a General response scheduled sooner covers this group.
        general_pending = self._if._igmp_query__pending_response_at_ms
        if general_pending is not None and general_pending <= response_at:
            return

        existing = self._if._igmp_group_query__pending.get(group)

        # Rules 3-5: determine the recorded source list for the response.
        if existing is None:
            recorded = sources
        elif not sources or not existing.sources:
            recorded = frozenset()
        else:
            recorded = existing.sources | sources

        if existing is not None and existing.respond_at_ms <= response_at:
            # The pending per-group response fires sooner (rules 4-5 keep
            # it); only the recorded source list may need merging.
            if recorded != existing.sources:
                self._if._igmp_group_query__pending[group] = IgmpGroupQueryPending(
                    respond_at_ms=existing.respond_at_ms,
                    handle=existing.handle,
                    sources=recorded,
                )
            return

        if delay_ms == 0:
            if existing is not None:
                stack.timer.cancel(existing.handle)
            self._if._igmp_group_query__pending.pop(group, None)
            self._igmp_group_query__send_now(group, recorded)
            return

        if existing is not None:
            # The selected delay is sooner — supersede the pending timer.
            stack.timer.cancel(existing.handle)
            self._if._packet_stats_rx.igmp__membership_query__superseded += 1

        handle = stack.timer.call_later(delay_ms, lambda: self._igmp_group_query__deferred_send(group))
        self._if._igmp_group_query__pending[group] = IgmpGroupQueryPending(
            respond_at_ms=response_at,
            handle=handle,
            sources=recorded,
        )
        self._if._packet_stats_rx.igmp__membership_query__scheduled += 1

    def _igmp_group_query__deferred_send(self, group: Ip4Address, /) -> None:
        """
        Timer-fired callback for a Group-Specific / Group-and-Source-
        Specific Query: drop the pending record and emit the per-group
        response using its recorded source list.
        """

        with self._if._lock__multicast:
            pending = self._if._igmp_group_query__pending.pop(group, None)
            self._igmp_group_query__send_now(group, pending.sources if pending is not None else frozenset())

    def _igmp_group_query__send_now(self, group: Ip4Address, sources: frozenset[Ip4Address], /) -> None:
        """
        Emit a Current-State response for 'group' in the interface's Host
        Compatibility Mode form, but only if the interface still has
        reception state for it (RFC 3376 §5.2 group-timer expiry rules
        2-3). 'sources' are the recorded Group-and-Source-Specific queried
        sources (empty for a Group-Specific Query); the IGMPv3 path
        applies the §5.2 rule-3 intersection math, while an IGMPv1/v2 mode
        degrades to the any-source group Membership Report.
        """

        if group not in self._if._ip4_multicast:
            return

        mode = self._if._igmp_host_compatibility_mode()
        if mode is IgmpVersion.V3:
            self._if._igmp_tx._send_igmp_v3_group_current_state(group, sources)
        else:
            self._if._igmp_tx._emit_group_membership_report(group, mode)
        self._if._packet_stats_rx.igmp__membership_query__respond += 1

    def _igmp_update_compatibility_mode(self, message: IgmpMessageQuery, /) -> None:
        """
        Arm the RFC 3376 §7.2.1 Older Version Querier Present timer for
        an older-version (v1/v2) General Query and, if that changes the
        interface's Host Compatibility Mode, cancel all pending IGMP
        response and retransmission timers (the mode switch is
        immediate). A v3 Query never lowers the mode.

        The §8.12 timeout is [Robustness Variable] × [Query Interval] +
        [Query Response Interval]; a v1/v2 Query carries no QQIC so the
        default 'igmp.query_interval' is used, and a v1 Query's Max Resp
        Code of 0 is interpreted as 100 (10 s) per §7.2.1.
        """

        if message.version is IgmpVersion.V3:
            return

        old_mode = self._if._igmp_host_compatibility_mode()

        query_response_interval_deci = message.max_response_time if message.version is IgmpVersion.V2 else 100
        timeout_ms = (
            igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS
            + query_response_interval_deci * IGMP__MAX_RESP_TIME__UNIT_MS
        )
        deadline_ms = stack.timer.now_ms + timeout_ms

        if message.version is IgmpVersion.V1:
            self._if._igmp__v1_querier_present_until_ms = deadline_ms
        else:
            self._if._igmp__v2_querier_present_until_ms = deadline_ms

        if self._if._igmp_host_compatibility_mode() is not old_mode:
            self._igmp_cancel_pending_timers()

    def _igmp_cancel_pending_timers(self) -> None:
        """
        Cancel the pending query-response timer and the state-change
        retransmit train (RFC 3376 §7.2.1 — a compatibility-mode change
        cancels all pending response and retransmission timers).
        """

        if self._if._igmp_query__handle is not None:
            stack.timer.cancel(self._if._igmp_query__handle)
            self._if._igmp_query__handle = None
        self._if._igmp_query__pending_response_at_ms = None
        # Snapshot the pending map before iterating: a Group-Specific
        # Query deferred-send fires on the timer thread and pops its own
        # entry, so iterating the live dict here would race that pop and
        # raise 'dictionary changed size during iteration' on the RX
        # thread (matches the snapshot idiom used on the TX side).
        for pending in list(self._if._igmp_group_query__pending.values()):
            stack.timer.cancel(pending.handle)
        self._if._igmp_group_query__pending.clear()
        self._if._igmp_tx._cancel_state_change_retransmits()

    def _igmp_query__pick_response_delay_ms(self, max_resp_ms: int, /) -> int:
        """
        RFC 3376 §5.2 random-response delay: a uniformly-random integer
        in [0, max_resp_ms]. Extracted so tests can patch it
        deterministically.
        """

        return random.randint(0, max_resp_ms)

    def _igmp_query__deferred_send(self) -> None:
        """
        Timer-fired callback that emits the pending IGMPv3 Report and
        clears the per-interface pending-response state.
        """

        with self._if._lock__multicast:
            self._if._igmp_query__pending_response_at_ms = None
            self._if._igmp_query__handle = None
            self._igmp_query__send_now()

    def _igmp_query__send_now(self) -> None:
        """
        Emit the Query response in the form dictated by the interface's
        Host Compatibility Mode (RFC 3376 §7) and bump the canonical
        'igmp__membership_query__respond' counter. Shared between the
        immediate-send (delay 0) and deferred-send (timer-fired) paths.

        IGMPv3 emits one current-state Report covering all joined
        groups; IGMPv1/v2 emit a per-group Membership Report to each
        joined group's address (RFC 2236 §3 / RFC 1112 §6).
        """

        mode = self._if._igmp_host_compatibility_mode()
        if mode is IgmpVersion.V3:
            self._if._send_igmp_v3_report()
        else:
            for group in dict.fromkeys(self._if._ip4_multicast):
                if group not in self._if._igmp_query__suppressed_groups:
                    self._if._igmp_tx._emit_group_membership_report(group, mode)

        self._if._igmp_query__suppressed_groups.clear()
        self._if._packet_stats_rx.igmp__membership_query__respond += 1
