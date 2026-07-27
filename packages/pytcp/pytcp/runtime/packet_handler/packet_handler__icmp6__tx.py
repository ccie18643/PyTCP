############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains packet handler for the outbound ICMPv6 packets.

pytcp/runtime/packet_handler/packet_handler__icmp6__tx.py

ver 3.0.9
"""

import random
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Buffer, Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6Message,
    Icmp6Mld2MessageQuery,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOption,
    Icmp6NdOptionNonce,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6Type,
    IpProto,
    Tracker,
    decode_igmp_float_code,
    encode_igmp_float_code,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__done import (
    Icmp6Mld1MessageDone,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    Icmp6Mld1MessageReport,
    MldVersion,
)
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__router_alert import (
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
    Ip6HbhOptionRouterAlert,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from pytcp import stack
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6 import mld__constants
from pytcp.runtime.timer import TimerHandle
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv6 MLD destinations (RFC 3810 §5.2.14 / RFC 2710 §3): an MLDv2
# Report goes to the all-MLDv2-routers group; the all-nodes group is
# never reported (RFC 3810 §6).
MLD__ALL_MLDV2_ROUTERS = Ip6Address("ff02::16")
MLD__ALL_NODES = Ip6Address("ff02::1")
MLD__ALL_ROUTERS = Ip6Address("ff02::2")

# The MLD link-local control groups a system never reports listener
# state for (RFC 3810 §6): the all-nodes group every host belongs to,
# and the all-routers / all-MLDv2-routers groups a querier receives on.
# An interface may listen on these without ever emitting a Report for
# them.
MLD__CONTROL_GROUPS = frozenset({MLD__ALL_NODES, MLD__ALL_ROUTERS, MLD__ALL_MLDV2_ROUTERS})


@dataclass(frozen=True, kw_only=True, slots=True)
class _MldPendingChange:
    """
    A pending MLDv2 state-change for one group awaiting robustness
    retransmission — the source-bearing §6.1 difference records to
    re-send in MLDv2 mode, the reception-edge direction to re-send in
    MLDv1 compatibility mode ('True' for a join → MLDv1 Report, 'False'
    for a leave → MLDv1 Done, 'None' for a source-only change an
    older-version host cannot express), and the number of
    retransmissions still owed. The IPv6 analogue of '_IgmpPendingChange'.
    """

    records: tuple[Icmp6Mld2MulticastAddressRecord, ...]
    coarse_join: bool | None
    remaining: int


@dataclass(kw_only=True, slots=True)
class _MldQuerierGroupState:
    """
    The MLDv2 querier's router-side reception state for one downstream
    multicast group (RFC 3810 §7.2) — the IPv6 analogue of
    '_QuerierGroupState'. Membership is tracked at group granularity;
    the §7.2 per-source timers collapse into the single group timer.
    Phase 2: per-source timers.
    """

    filter_mode: Ip6MulticastFilterMode
    sources: frozenset[Ip6Address]
    group_timer_handle: TimerHandle | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class MldQuerierMembership:
    """
    An immutable snapshot of one router-learned MLD group membership —
    the read-only introspection view of the querier's downstream
    reception state (the IPv6 '/proc/net/igmp6' router equivalent).
    """

    group: Ip6Address
    filter_mode: Ip6MulticastFilterMode
    sources: frozenset[Ip6Address]


class Icmp6TxHandler:
    """
    The outbound ICMPv6 packet handler for one interface.
    """

    _if: PacketHandler
    _mld_state_change__pending: dict[Ip6Address, _MldPendingChange]
    _mld_state_change__handle: TimerHandle | None
    _mld_querier__active: bool
    _mld_querier__is_querier: bool
    _mld_querier__handle: TimerHandle | None
    _mld_querier__other_present_handle: TimerHandle | None
    _mld_querier__startup_remaining: int
    _mld_querier__memberships: dict[Ip6Address, _MldQuerierGroupState]

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface
        self._mld_state_change__pending = {}
        self._mld_state_change__handle = None
        self._mld_querier__active = False
        self._mld_querier__is_querier = False
        self._mld_querier__handle = None
        self._mld_querier__other_present_handle = None
        self._mld_querier__startup_remaining = 0
        self._mld_querier__memberships = {}

    # --- MLDv2 querier role (RFC 3810 §7) ----------------------------

    def refresh_querier(self) -> None:
        """
        Reconcile the interface's MLD querier role with its
        'mld.mc_forwarding' switch: start the querier when the interface
        is (newly) a multicast router, stop it when the switch is
        cleared. The IPv6 analogue of 'IgmpTxHandler.refresh_querier'.

        Reference: RFC 3810 §7 (a multicast router acts as querier).
        """

        with self._if._lock__multicast:
            enabled = bool(sysctl_iface.get_for_iface("mld.mc_forwarding", self._if._interface_name))
            if enabled and not self._mld_querier__active:
                self._start_querier()
            elif not enabled and self._mld_querier__active:
                self._stop_querier()

    def _start_querier(self) -> None:
        """
        Become a multicast router and take up the MLD querier role: a
        router begins in the Querier state (RFC 3810 §7.6.2), sending the
        first of the §9.7 Startup Query Count General Queries. Admits the
        all-MLDv2-routers group receive-only so inbound Reports arrive.
        Runs under the interface multicast lock.
        """

        self._admit_querier_receive_group()
        self._mld_querier__active = True
        self._mld_querier__is_querier = True
        self._mld_querier__startup_remaining = max(1, mld__constants.MLD__STARTUP_QUERY_COUNT)
        self._send_general_query_and_rearm()

    def _stop_querier(self) -> None:
        """
        Stop being a multicast router: cancel the General-Query and
        Other-Querier-Present tickets, prune the membership table, and
        withdraw the receive-group admission. Runs under the interface
        multicast lock.
        """

        self._mld_querier__active = False
        self._mld_querier__is_querier = False
        self._mld_querier__startup_remaining = 0
        if self._mld_querier__handle is not None:
            stack.timer.cancel(self._mld_querier__handle)
            self._mld_querier__handle = None
        if self._mld_querier__other_present_handle is not None:
            stack.timer.cancel(self._mld_querier__other_present_handle)
            self._mld_querier__other_present_handle = None
        for state in self._mld_querier__memberships.values():
            if state.group_timer_handle is not None:
                stack.timer.cancel(state.group_timer_handle)
        self._mld_querier__memberships.clear()
        self._withdraw_querier_receive_group()

    def _fire_general_query(self) -> None:
        """
        Timer callback: emit one periodic General Query and re-arm. Bails
        under the interface multicast lock if the role was relinquished
        or lost while the ticket was in flight.

        Reference: RFC 3810 §7 (querier General Query interval).
        """

        with self._if._lock__multicast:
            self._mld_querier__handle = None
            if not (self._mld_querier__active and self._mld_querier__is_querier):
                return
            self._send_general_query_and_rearm()

    def _send_general_query_and_rearm(self) -> None:
        """
        Emit one General Query and schedule the next: at the Startup
        Query Interval while the startup burst drains (RFC 3810 §9.6 /
        §9.7), then at the steady-state Query Interval (§9.2). Runs under
        the interface multicast lock.
        """

        self._send_mld_general_query()

        if self._mld_querier__startup_remaining > 1:
            self._mld_querier__startup_remaining -= 1
            delay_ms = mld__constants.MLD__STARTUP_QUERY_INTERVAL__MS
        else:
            self._mld_querier__startup_remaining = 0
            delay_ms = mld__constants.MLD__QUERY_INTERVAL__MS

        self._mld_querier__handle = stack.timer.call_later(delay_ms, self._fire_general_query)

    def _send_mld_general_query(self) -> None:
        """
        Emit an MLDv2 General Query (multicast address ::, no sources) to
        the all-nodes group ff02::1, Hop Limit 1, carrying the querier's
        advertised Maximum Response Code (Query Response Interval), QRV
        (Robustness Variable), and QQIC (Query Interval).

        Reference: RFC 3810 §5.1 (General Query fields).
        Reference: RFC 3810 §9.3 (Query Response Interval — Max Resp Code).
        """

        message = Icmp6Mld2MessageQuery(
            maximum_response_code=self._mld_mrd_to_mrc(mld__constants.MLD__QUERY_RESPONSE_INTERVAL__MS),
            multicast_address=Ip6Address(),
            qrv=mld__constants.MLD__ROBUSTNESS_VARIABLE & 0x07,
            qqic=encode_igmp_float_code(mld__constants.MLD__QUERY_INTERVAL__MS // 1000),
        )

        self._if._packet_stats_tx.icmp6__mld_general_query__send += 1
        self.__send_icmp6_mld_via_hbh_ra(
            Icmp6Assembler(icmp6__message=message),
            ip6__dst=MLD__ALL_NODES,
        )

    def observe_query(self, source: Ip6Address, query: Icmp6Mld2MessageQuery, /) -> None:
        """
        Apply the RFC 3810 §7.6.2 querier-election rule to an inbound
        Query: the router with the numerically lowest interface address
        on the link is the Querier. A Query from a source lower than our
        own address steps us down to Non-Querier and (re)arms the Other
        Querier Present timer. A no-op on a non-router interface.

        Reference: RFC 3810 §7.6.2 (querier election — lowest address wins).
        Reference: RFC 3810 §9.5 (Other Querier Present Timeout).
        """

        with self._if._lock__multicast:
            if not self._mld_querier__active:
                return

            our_address = self._if.ip6_unicast[0] if self._if.ip6_unicast else Ip6Address()
            if int(source) >= int(our_address):
                return

            self._become_non_querier(query)

    def _become_non_querier(self, query: Icmp6Mld2MessageQuery, /) -> None:
        """
        Step down to the Non-Querier state: stop emitting General Queries
        and (re)arm the Other Querier Present timer from the electing
        Query's advertised values. Runs under the interface multicast
        lock.
        """

        self._mld_querier__is_querier = False
        self._mld_querier__startup_remaining = 0
        if self._mld_querier__handle is not None:
            stack.timer.cancel(self._mld_querier__handle)
            self._mld_querier__handle = None

        if self._mld_querier__other_present_handle is not None:
            stack.timer.cancel(self._mld_querier__other_present_handle)

        self._mld_querier__other_present_handle = stack.timer.call_later(
            self._other_querier_present_interval_ms(query),
            self._fire_other_querier_present,
        )
        self._if._packet_stats_rx.icmp6__mld_query__election_lost += 1

    def _fire_other_querier_present(self) -> None:
        """
        Timer callback: the elected querier has gone silent for the Other
        Querier Present Interval, so resume the Querier role (RFC 3810
        §7.6.2). Runs under the interface multicast lock.
        """

        with self._if._lock__multicast:
            self._mld_querier__other_present_handle = None
            if not self._mld_querier__active:
                return
            self._mld_querier__is_querier = True
            self._mld_querier__startup_remaining = max(1, mld__constants.MLD__STARTUP_QUERY_COUNT)
            self._send_general_query_and_rearm()

    @staticmethod
    def _other_querier_present_interval_ms(query: Icmp6Mld2MessageQuery, /) -> int:
        """
        The RFC 3810 §9.5 Other Querier Present Timeout — Robustness
        Variable × Query Interval + one half of the Query Response
        Interval — computed from the electing Query's advertised QRV /
        QQIC / Max Resp Code, falling back to the configured defaults
        where the Query carries none.
        """

        qrv = query.qrv or mld__constants.MLD__ROBUSTNESS_VARIABLE
        query_interval_sec = decode_igmp_float_code(query.qqic) or (mld__constants.MLD__QUERY_INTERVAL__MS // 1000)
        query_response_ms = (
            Icmp6TxHandler._mld_mrc_to_mrd_ms(query.maximum_response_code)
            or mld__constants.MLD__QUERY_RESPONSE_INTERVAL__MS
        )

        return qrv * query_interval_sec * 1000 + query_response_ms // 2

    @staticmethod
    def _mld_mrc_to_mrd_ms(mrc: int, /) -> int:
        """
        Decode a 16-bit MLDv2 Maximum Response Code to its Maximum
        Response Delay in milliseconds (RFC 3810 §5.1.3) — the inverse of
        '_mld_mrd_to_mrc'.
        """

        if mrc < 32768:
            return mrc
        exp = (mrc >> 12) & 0x7
        mant = mrc & 0xFFF
        return (mant | 0x1000) << (exp + 3)

    def observe_report(self, message: Icmp6Message, /) -> None:
        """
        Learn downstream multicast reception state from an inbound MLDv2
        Report (RFC 3810 §7.4) into the router membership table. A no-op
        on a non-router interface. Populated only from inbound Reports —
        never from this stack's own host joins (which live in the
        separate '_ip6_multicast_refs' host table).

        Reference: RFC 3810 §7.4 (router action on reception of a Report).
        """

        with self._if._lock__multicast:
            if not self._mld_querier__active:
                return

            if not isinstance(message, Icmp6Mld2MessageReport):
                return

            learned = False
            for record in message.records:
                learned |= self._process_multicast_address_record(
                    record.multicast_address, record.type, frozenset(record.source_addresses)
                )
            if learned:
                self._if._packet_stats_rx.icmp6__mld2_report__querier_learn += 1

    def _process_multicast_address_record(
        self,
        group: Ip6Address,
        record_type: Icmp6Mld2MulticastAddressRecordType,
        sources: frozenset[Ip6Address],
        /,
    ) -> bool:
        """
        Apply one MLDv2 Multicast Address Record to the router membership
        table and report whether it updated reception state. The MLD
        control groups are never tracked. Runs under the interface
        multicast lock.
        """

        if group in MLD__CONTROL_GROUPS:
            return False

        match record_type:
            case (
                Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE
                | Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE
            ):
                self._set_membership(group, Ip6MulticastFilterMode.EXCLUDE, sources)
                return True
            case (
                Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE
                | Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE
            ):
                if not sources:
                    return self._remove_membership(group)
                self._set_membership(group, Ip6MulticastFilterMode.INCLUDE, sources)
                return True
            case Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES:
                state = self._mld_querier__memberships.get(group)
                if state is None:
                    self._set_membership(group, Ip6MulticastFilterMode.INCLUDE, sources)
                elif state.filter_mode is Ip6MulticastFilterMode.INCLUDE:
                    self._set_membership(group, Ip6MulticastFilterMode.INCLUDE, state.sources | sources)
                else:
                    self._set_membership(group, Ip6MulticastFilterMode.EXCLUDE, state.sources - sources)
                return True
            case Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES:
                # Phase 2 (M5e): a BLOCK schedules a fast-leave query;
                # here it only narrows an INCLUDE source list.
                state = self._mld_querier__memberships.get(group)
                if state is None or state.filter_mode is not Ip6MulticastFilterMode.INCLUDE:
                    return False
                state.sources = state.sources - sources
                return True

        return False

    def _set_membership(
        self,
        group: Ip6Address,
        filter_mode: Ip6MulticastFilterMode,
        sources: frozenset[Ip6Address],
        /,
    ) -> None:
        """
        Install or refresh the router membership entry for 'group' and
        (re)arm its Multicast Address Listening Interval timer. Runs
        under the interface multicast lock.
        """

        state = self._mld_querier__memberships.get(group)
        if state is None:
            state = _MldQuerierGroupState(filter_mode=filter_mode, sources=sources)
            self._mld_querier__memberships[group] = state
        else:
            state.filter_mode = filter_mode
            state.sources = sources

        if state.group_timer_handle is not None:
            stack.timer.cancel(state.group_timer_handle)
        state.group_timer_handle = stack.timer.call_later(
            self._multicast_address_listening_interval_ms(), self._expire_group, group
        )

    def _remove_membership(self, group: Ip6Address, /) -> bool:
        """
        Drop the router membership entry for 'group' and cancel its timer,
        reporting whether an entry existed. Runs under the interface
        multicast lock.
        """

        state = self._mld_querier__memberships.pop(group, None)
        if state is None:
            return False
        if state.group_timer_handle is not None:
            stack.timer.cancel(state.group_timer_handle)
        return True

    def _expire_group(self, group: Ip6Address, /) -> None:
        """
        Multicast Address Listening Interval timer callback: no Report
        refreshed the group, so the last listener is assumed gone and the
        group is pruned (RFC 3810 §7.2.4). Runs under the interface
        multicast lock.
        """

        with self._if._lock__multicast:
            state = self._mld_querier__memberships.get(group)
            if state is None:
                return
            state.group_timer_handle = None
            del self._mld_querier__memberships[group]

    @staticmethod
    def _multicast_address_listening_interval_ms() -> int:
        """
        The RFC 3810 §9.4 Multicast Address Listening Interval —
        Robustness Variable × Query Interval + one Query Response
        Interval — after which a group with no refreshing Report is
        pruned.
        """

        return (
            mld__constants.MLD__ROBUSTNESS_VARIABLE * mld__constants.MLD__QUERY_INTERVAL__MS
            + mld__constants.MLD__QUERY_RESPONSE_INTERVAL__MS
        )

    def querier_memberships(self) -> tuple[MldQuerierMembership, ...]:
        """
        Return an immutable snapshot of the router's learned downstream
        MLD memberships (the read-only introspection surface).
        """

        with self._if._lock__multicast:
            return tuple(
                MldQuerierMembership(group=group, filter_mode=state.filter_mode, sources=state.sources)
                for group, state in self._mld_querier__memberships.items()
            )

    def _admit_querier_receive_group(self) -> None:
        """
        Receive-only admission of the all-MLDv2-routers group ff02::16 so
        the querier receives inbound Reports. It is an MLD control group
        (MLD__CONTROL_GROUPS) the interface never reports listener state
        for, so — unlike a host join — no Report is emitted for it. Runs
        under the interface multicast lock.
        """

        if MLD__ALL_MLDV2_ROUTERS not in self._if._ip6_multicast_filters:
            self._if.assign_ip6_multicast(MLD__ALL_MLDV2_ROUTERS)

    def _withdraw_querier_receive_group(self) -> None:
        """
        Undo '_admit_querier_receive_group' when the interface stops being
        a multicast router. Runs under the interface multicast lock.
        """

        if MLD__ALL_MLDV2_ROUTERS in self._if._ip6_multicast_filters:
            self._if.remove_ip6_multicast(MLD__ALL_MLDV2_ROUTERS)

    @staticmethod
    def _mld_mrd_to_mrc(mrd_ms: int, /) -> int:
        """
        Encode a Maximum Response Delay (ms) to a 16-bit MLDv2 Maximum
        Response Code (RFC 3810 §5.1.3) — the inverse of the RX decode:
        a value below 32768 encodes to itself, a larger value to the
        floating-point form 1|exp|mant, saturating at 0xffff.
        """

        if mrd_ms < 32768:
            return mrd_ms

        mant = mrd_ms >> 3
        exp = 0
        while mant > 0x1FFF:
            mant >>= 1
            exp += 1

        if exp > 0x07:
            return 0xFFFF

        return 0x8000 | (exp << 12) | (mant & 0xFFF)

    def _phtx_icmp6(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv6 packets.
        """

        self._if._packet_stats_tx.icmp6__pre_assemble += 1

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=icmp6__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}")

        match icmp6__message.type, icmp6__message.code:
            case Icmp6Type.ECHO_REPLY, _:
                self._if._packet_stats_tx.icmp6__echo_reply__send += 1
            case Icmp6Type.ECHO_REQUEST, _:
                self._if._packet_stats_tx.icmp6__echo_request__send += 1
            case (
                Icmp6Type.DESTINATION_UNREACHABLE,
                Icmp6DestinationUnreachableCode.PORT,
            ):
                self._if._packet_stats_tx.icmp6__destination_unreachable__port__send += 1
            case (
                Icmp6Type.DESTINATION_UNREACHABLE,
                Icmp6DestinationUnreachableCode.NO_ROUTE,
            ):
                # RFC 4443 §3.1 / RFC 1812 §5.2 — no-route response
                # emitted by the transit forward path.
                self._if._packet_stats_tx.icmp6__destination_unreachable__no_route__send += 1
            case Icmp6Type.PACKET_TOO_BIG, _:
                # RFC 8201 §3 / RFC 4443 §3.2 — transit PMTU response
                # emitted by the forward path when a datagram exceeds
                # the egress MTU (routers never fragment IPv6).
                self._if._packet_stats_tx.icmp6__packet_too_big__send += 1
            case Icmp6Type.PARAMETER_PROBLEM, _:
                self._if._packet_stats_tx.icmp6__parameter_problem__send += 1
            case Icmp6Type.TIME_EXCEEDED, _:
                # RFC 4443 §3.3 / RFC 1812 §5.3.1 — Hop-Limit-expiry
                # response emitted by the transit forward path.
                self._if._packet_stats_tx.icmp6__time_exceeded__send += 1
            case Icmp6Type.ND__ROUTER_SOLICITATION, _:
                self._if._packet_stats_tx.icmp6__nd__router_solicitation__send += 1
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT, _:
                self._if._packet_stats_tx.icmp6__nd__router_advertisement__send += 1
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION, _:
                self._if._packet_stats_tx.icmp6__nd__neighbor_solicitation__send += 1
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT, _:
                self._if._packet_stats_tx.icmp6__nd__neighbor_advertisement__send += 1
            case Icmp6Type.MLD2__REPORT, _:
                self._if._packet_stats_tx.icmp6__mld2__report__send += 1
            case _:
                # Defensive drop: unsupported ICMPv6 type/code shouldn't
                # reach the TX path (the call sites enumerate their
                # message types), but if one does, count + drop is
                # robust where 'raise' would crash the calling thread.
                self._if._packet_stats_tx.icmp6__unknown__drop += 1
                __debug__ and log(
                    "icmp6",
                    f"{icmp6_packet_tx.tracker} - <CRIT>Dropping unsupported ICMPv6 "
                    f"type {icmp6__message.type}, code {icmp6__message.code}</>",
                )
                return TxStatus.DROPPED__ICMP6__UNKNOWN

        return self._if._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=icmp6_packet_tx,
        )

    def _send_icmp6_nd_dad_message(
        self,
        *,
        ip6_unicast_candidate: Ip6Address,
        nonce: bytes | None = None,
    ) -> None:
        """
        Send out ICMPv6 ND Duplicate Address Detection message.
        When 'nonce' is supplied, the probe carries a Nonce option
        per RFC 7527 §4.1 (Enhanced DAD); the caller tracks the
        emitted nonce so the NS-RX path can drop loop-hairpin
        echoes of our own probe.
        """

        options: list[Icmp6NdOption] = []
        if nonce is not None:
            options.append(Icmp6NdOptionNonce(nonce=nonce))

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=Ip6Address(),
                ip6__dst=ip6_unicast_candidate.solicited_node_multicast,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=ip6_unicast_candidate,
                    options=Icmp6NdOptions(*options),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 ND DAD message for " f"{ip6_unicast_candidate}, tx_status: {tx_status}",
            )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send out ICMPv6 Multicast Listener Report for given list of
        addresses, wrapped in a Hop-by-Hop Options header carrying
        the Router Alert option (value=MLD) so MLD-aware routers
        intercept the report per RFC 3810 §5 + RFC 2711.

        Hop Limit is fixed at 1 per RFC 3810 §5.2.13 (MLDv2 messages
        are link-local).
        """

        # All-Multicast-Nodes (ff02::1) is never advertised (RFC 3810
        # §6); a 'set' deduplicates the membership list.
        groups = {group for group in self._if._ip6_multicast if group not in MLD__CONTROL_GROUPS}
        if not groups:
            return

        # RFC 3810 §8.3.1 report-form selection: while the interface
        # is in MLDv1 Host Compatibility Mode (an MLDv1 Query was heard
        # within the §8.2.1 Older Version Querier Present timeout),
        # emit one MLDv1 Report (type 131) per group instead of the
        # single aggregated MLDv2 Report (type 143). The querier that
        # speaks only MLDv1 cannot parse a type-143 Report.
        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            for group in groups:
                self._send_icmp6_mld1_report(group)
            return

        # MLDv2: one aggregated Report (CHANGE_TO_EXCLUDE per group) to
        # the all-MLDv2-routers address.
        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                        multicast_address=group,
                    )
                    for group in groups
                ],
            ),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::16"))

    def _send_icmp6_mld1_report(self, group: Ip6Address, /) -> None:
        """
        Send an MLDv1 Multicast Listener Report (type 131) for 'group'.

        Reference: RFC 2710 §3 / RFC 3810 §8.3.1.

        Per RFC 2710 §3 an MLDv1 Report is sent to the multicast
        address being reported (so the destination is 'group' itself),
        wrapped in the same Hop-by-Hop Router Alert carrier as the
        MLDv2 Report, with Hop Limit 1.
        """

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld1MessageReport(multicast_address=group),
        )
        self._if._packet_stats_tx.icmp6__mld1__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=group)

    def _send_icmp6_mld1_done(self, group: Ip6Address, /) -> None:
        """
        Send an MLDv1 Multicast Listener Done (type 132) for 'group'.

        Reference: RFC 2710 §3 (MLDv1 Done sent to all-routers ff02::2).
        Reference: RFC 3810 §8.3.2 (emit MLDv1 Done while in v1 mode).
        """

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld1MessageDone(multicast_address=group),
        )
        self._if._packet_stats_tx.icmp6__mld1__done__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::2"))

    def _send_icmp6_mld_leave_all(self) -> None:
        """
        Announce departure from every joined IPv6 multicast group, for
        the stack-shutdown graceful-leave path.

        Reference: RFC 3810 §6.1 (graceful leave on shutdown).

        All-nodes (ff02::1) is never reported (RFC 3810 §6). While in
        MLDv1 Host Compatibility Mode one MLDv1 Done is emitted per group;
        otherwise a single aggregated MLDv2 State Change Report carries a
        CHANGE_TO_INCLUDE record per group.
        """

        groups = {group for group in self._if._ip6_multicast if group not in MLD__CONTROL_GROUPS}
        if not groups:
            return

        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            for group in groups:
                self._send_icmp6_mld1_done(group)
            return

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                        multicast_address=group,
                    )
                    for group in groups
                ],
            ),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=Ip6Address("ff02::16"))

    def _emit_mld2_report(self, records: list[Icmp6Mld2MulticastAddressRecord], /) -> None:
        """
        Assemble and emit a single aggregated MLDv2 State Change Report
        (type 143) carrying 'records' to the all-MLDv2-routers group
        ff02::16, wrapped in the Hop-by-Hop Router Alert carrier
        (RFC 3810 §5.2.14). A report with no records is not emitted.
        """

        if not records:
            return

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=Icmp6Mld2MessageReport(records=records),
        )
        self._if._packet_stats_tx.icmp6__mld2__report__send += 1
        self.__send_icmp6_mld_via_hbh_ra(icmp6_packet_tx, ip6__dst=MLD__ALL_MLDV2_ROUTERS)

    @staticmethod
    def _mld_state_change_records(
        group: Ip6Address,
        old: Ip6MulticastFilter,
        new: Ip6MulticastFilter,
        /,
    ) -> list[Icmp6Mld2MulticastAddressRecord]:
        """
        Compute the MLDv2 difference records for a group's filter change
        per the RFC 3810 §6.1 table (the "non-listener" state is
        INCLUDE{}): a filter-mode change yields one CHANGE_TO_INCLUDE /
        CHANGE_TO_EXCLUDE record carrying the new source list; a
        within-mode source change yields ALLOW_NEW_SOURCES and/or
        BLOCK_OLD_SOURCES records (empty ones are omitted). The IPv6
        analogue of the IGMPv3 '_state_change_records'.
        """

        if old.mode is new.mode:
            if old.mode is Ip6MulticastFilterMode.INCLUDE:
                allow, block = new.sources - old.sources, old.sources - new.sources
            else:
                allow, block = old.sources - new.sources, new.sources - old.sources
            records: list[Icmp6Mld2MulticastAddressRecord] = []
            if allow:
                records.append(
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(allow, key=int),
                    )
                )
            if block:
                records.append(
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                        multicast_address=group,
                        source_addresses=sorted(block, key=int),
                    )
                )
            return records

        record_type = (
            Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE
            if new.mode is Ip6MulticastFilterMode.EXCLUDE
            else Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE
        )
        return [
            Icmp6Mld2MulticastAddressRecord(
                type=record_type,
                multicast_address=group,
                source_addresses=sorted(new.sources, key=int),
            )
        ]

    def _emit_mld1_coarse(self, group: Ip6Address, coarse_join: bool | None, /) -> None:
        """
        Emit the coarse MLDv1 form of a state-change for 'group' while in
        MLDv1 Host Compatibility Mode: a Report on a join edge, a Done on a
        leave edge, nothing for a source-only change (MLDv1 has no source
        concept). 'coarse_join' is True (join), False (leave) or None.
        """

        if coarse_join is True:
            self._send_icmp6_mld1_report(group)
        elif coarse_join is False:
            self._send_icmp6_mld1_done(group)

    def _send_mld_state_change(
        self,
        group: Ip6Address,
        /,
        *,
        old: Ip6MulticastFilter,
        new: Ip6MulticastFilter,
    ) -> None:
        """
        Emit an unsolicited state-change Report for 'group' describing the
        transition from filter 'old' to filter 'new' (RFC 3810 §6.1) in
        the form dictated by the interface's Host Compatibility Mode
        (§8.3), and schedule its robustness retransmissions. In MLDv2 mode
        the Report carries the source-bearing §6.1 difference records; in
        MLDv1 mode it degrades to the coarse Report / Done keyed only off
        the reception edge (MLDv1 has no source concept). The all-nodes
        group ff02::1 is never reported (RFC 3810 §6).

        A new change supersedes any retransmit train still pending for the
        same group (overwrite + re-seed). A change that produces no record
        (an idempotent re-add) schedules no retransmit. The IPv6 analogue
        of '_send_igmp_state_change'.
        """

        if group in MLD__CONTROL_GROUPS:
            return

        records = self._mld_state_change_records(group, old, new)
        # The coarse MLDv1 form keys only off the reception edge — a
        # source-only change within a still-joined membership (coarse_join
        # None) is invisible to an older-version querier.
        coarse_join = (
            True
            if new.has_reception and not old.has_reception
            else False if old.has_reception and not new.has_reception else None
        )

        if self._if._mld_host_compatibility_mode() is MldVersion.V1:
            self._emit_mld1_coarse(group, coarse_join)
        else:
            self._emit_mld2_report(records)

        # RFC 3810 §9.1 — read the Robustness Variable live so an operator
        # override resolves per change.
        repeats = mld__constants.MLD__ROBUSTNESS_VARIABLE - 1
        if not records or repeats <= 0:
            self._mld_state_change__pending.pop(group, None)
            return

        self._mld_state_change__pending[group] = _MldPendingChange(
            records=tuple(records),
            coarse_join=coarse_join,
            remaining=repeats,
        )
        self._arm_mld_state_change_retransmit()

    def _arm_mld_state_change_retransmit(self) -> None:
        """
        Ensure a single retransmit ticket is scheduled for the pending
        state-change records. RFC 3810 §6.1 spaces the robustness
        retransmissions at intervals drawn uniformly at random from (0,
        'mld.unsolicited_report_interval' ms]; the ticket re-arms itself
        from each fire rather than scheduling the whole train up front, so
        a change arriving mid-train is picked up by the next fire. Reading
        the interval knob via qualified module access so an operator
        override resolves on each re-arm. The IPv6 analogue of
        '_arm_state_change_retransmit'.
        """

        if self._mld_state_change__handle is not None:
            return

        delay_ms = random.randint(1, mld__constants.MLD__UNSOLICITED_REPORT_INTERVAL__MS)
        self._mld_state_change__handle = stack.timer.call_later(delay_ms, self._fire_mld_state_change_retransmit)

    def _fire_mld_state_change_retransmit(self) -> None:
        """
        Emit one robustness retransmission of the currently-pending
        state-change records in the current Host Compatibility Mode's form
        — MLDv2 coalesces them into a single Report, MLDv1 emits one
        coarse Report / Done per group — then decrement each entry's
        remaining-repeat count, drop the exhausted ones, and re-arm the
        ticket while any repeats remain (RFC 3810 §6.1 / §8.3). The IPv6
        analogue of '_fire_state_change_retransmit'.
        """

        # Runs on the Timer thread. The pending per-group change map and
        # the Host Compatibility Mode deadlines are mutated / written by
        # the RX and application threads under the interface multicast
        # lock, so this fire takes the same lock (the RLock is reentrant,
        # so the nested compat-mode / emit reads are fine).
        with self._if._lock__multicast:
            self._mld_state_change__handle = None

            groups = list(self._mld_state_change__pending)

            if self._if._mld_host_compatibility_mode() is MldVersion.V1:
                for group in groups:
                    self._emit_mld1_coarse(group, self._mld_state_change__pending[group].coarse_join)
            else:
                records: list[Icmp6Mld2MulticastAddressRecord] = []
                for group in groups:
                    records.extend(self._mld_state_change__pending[group].records)
                self._emit_mld2_report(records)

            for group in groups:
                pending = self._mld_state_change__pending[group]
                if pending.remaining <= 1:
                    del self._mld_state_change__pending[group]
                else:
                    self._mld_state_change__pending[group] = _MldPendingChange(
                        records=pending.records,
                        coarse_join=pending.coarse_join,
                        remaining=pending.remaining - 1,
                    )

            if self._mld_state_change__pending:
                self._arm_mld_state_change_retransmit()

    def _cancel_mld_state_change_retransmits(self) -> None:
        """
        Cancel the in-flight state-change retransmit ticket and drop every
        pending per-group change record (RFC 3810 §8.2.1 — a
        compatibility-mode change cancels all pending retransmissions). The
        IPv6 analogue of '_cancel_state_change_retransmits'.
        """

        if self._mld_state_change__handle is not None:
            stack.timer.cancel(self._mld_state_change__handle)
            self._mld_state_change__handle = None
        self._mld_state_change__pending.clear()

    def __send_icmp6_mld_via_hbh_ra(self, icmp6_packet_tx: Icmp6Assembler, /, *, ip6__dst: Ip6Address) -> None:
        """
        Emit an MLD ICMPv6 message ('icmp6_packet_tx') wrapped in a
        Hop-by-Hop Options header carrying the Router Alert option
        (value=MLD, RFC 2711) so MLD-aware routers intercept it
        (RFC 3810 §5 / RFC 2710 §3), with Hop Limit 1 (link-local).

        Shared by the MLDv2 aggregate Report and the per-group MLDv1
        Reports — the only differences are the ICMPv6 message and the
        destination.
        """

        ip6__src = self._if.ip6_unicast[0] if self._if.ip6_unicast else Ip6Address()

        # Pre-compute the ICMPv6 pseudo-header sum used to finalise the
        # ICMPv6 checksum. RFC 4443 §2.3: the pseudo-header carries
        # 'src + dst + Upper-Layer Packet Length + Next Header = 58'
        # regardless of the extension headers between IPv6 and ICMPv6,
        # so it is computed here — 'Ip6Assembler' only auto-injects
        # pshdr_sum when the immediate IPv6 payload is the transport
        # message, not when it is a Hop-by-Hop extension header.
        pseudo_header = struct.pack(
            "! 16s 16s L BBBB",
            bytes(ip6__src),
            bytes(ip6__dst),
            len(icmp6_packet_tx),
            0,
            0,
            0,
            int(IpProto.ICMP6),
        )
        icmp6_packet_tx.pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))

        icmp6_buffers: list[Buffer] = []
        icmp6_packet_tx.assemble(icmp6_buffers)
        icmp6_bytes = b"".join(bytes(buf) for buf in icmp6_buffers)

        # HBH = 2-byte prefix + 4-byte Router Alert + 2-byte PadN(0) = 8 octets.
        hbh_packet_tx = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.ICMP6,
            ip6_hbh__options=Ip6HbhOptions(
                Ip6HbhOptionRouterAlert(value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD),
                Ip6HbhOptionPadN(b""),
            ),
            ip6_hbh__payload=icmp6_bytes,
            echo_tracker=icmp6_packet_tx.tracker,
        )

        self._if._packet_stats_tx.icmp6__pre_assemble += 1

        tx_status = self._if._marshal_tx(
            lambda: self._if._phtx_ip6(
                ip6__src=ip6__src,
                ip6__dst=ip6__dst,
                ip6__hop=1,
                ip6__payload=hbh_packet_tx,
            )
        )

        if tx_status in {TxStatus.PASSED__ETHERNET__TO_TX_RING, TxStatus.PASSED__IP6__TO_TX_RING}:
            __debug__ and log("stack", f"Sent out ICMPv6 Multicast Listener Report (HBH+RA) to {ip6__dst}")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 Multicast Listener Report (HBH+RA) to {ip6__dst}, tx_status: {tx_status}",
            )

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send out ICMPv6 ND Router Solicitation.
        """

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=self._if.ip6_unicast[0],
                ip6__dst=Ip6Address("ff02::2"),
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageRouterSolicitation(
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=self._if._mac_unicast),
                    ),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Router Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Router Solicitation, {tx_status}",
            )

    def send_icmp6_neighbor_solicitation(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a multicast ICMPv6 Neighbor Solicitation — the
        INCOMPLETE-state form (RFC 4861 §7.2.2). The IPv6
        destination is the target's solicited-node multicast
        address.
        """

        # Pick appropriate source address
        ip6__src = Ip6Address()
        for ip6_host in self._if._ip6_ifaddr:
            if icmp6_ns_target_address in ip6_host.network:
                ip6__src = ip6_host.address

        # Send out ND Neighbor Solicitation message
        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=icmp6_ns_target_address.solicited_node_multicast,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=icmp6_ns_target_address,
                    options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self._if._mac_unicast)),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log("stack", "Sent out ICMPv6 ND Neighbor Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Neighbor Solicitation, {tx_status}",
            )

    def send_icmp6_neighbor_solicitation_unicast(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a unicast ICMPv6 Neighbor Solicitation — the
        NUD_PROBE-state form (RFC 4861 §7.3.3). The IPv6
        destination is the target address itself, NOT the
        solicited-node multicast group; the cached neighbour's
        MAC resolves at the Ethernet TX layer via the ND
        cache's PROBE-state entry. RFC 4861 §4.3 SHOULDs
        including the SLLA option in unicast solicitations,
        which we do (matches Linux).

        Used by 'NdCache._solicit_ns' when the FSM enters
        NUD_PROBE — the cached_mac is non-None, so the cache
        already has a working entry and only needs to confirm
        liveness. This saves segment-wide multicast bandwidth
        relative to a full re-resolution.
        """

        # Pick appropriate source address — same logic as the
        # multicast variant since the target is on a known
        # local subnet (we already have a cache entry for it).
        ip6__src = Ip6Address()
        for ip6_host in self._if._ip6_ifaddr:
            if icmp6_ns_target_address in ip6_host.network:
                ip6__src = ip6_host.address

        tx_status = self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=icmp6_ns_target_address,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    target_address=icmp6_ns_target_address,
                    options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self._if._mac_unicast)),
                ),
            )
        )

        if tx_status in {
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP6__TO_TX_RING,
        }:
            __debug__ and log(
                "stack",
                f"Sent out unicast ICMPv6 ND Neighbor Solicitation for {icmp6_ns_target_address}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out unicast ICMPv6 ND Neighbor Solicitation for "
                f"{icmp6_ns_target_address}, {tx_status}",
            )

    def send_icmp6_neighbor_advertisement(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        target_address: Ip6Address,
        flag_r: bool = False,
        flag_s: bool = False,
        flag_o: bool = False,
        include_tlla: bool = True,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Enqueue an ICMPv6 ND Neighbor Advertisement (RFC 4861
        §4.4 wire format). Hop limit hard-set to 255 per
        §7.1.2.

        The 'flag_r' / 'flag_s' / 'flag_o' kwargs map to the
        wire R(outer) / S(olicited) / O(verride) flags. The
        canonical solicited-NA reply path uses flag_s=True; the
        gratuitous form (RFC 9131 §3) uses flag_o=True with
        flag_s=False. 'include_tlla' attaches the host's MAC
        as a TLLA option — required for solicited replies and
        for gratuitous announcements.

        RFC 4429 §3.3: when 'ip6__src' is currently OPTIMISTIC
        the Override flag is forcibly cleared regardless of the
        caller-requested value, so peers do not overwrite an
        existing cache entry on the basis of an unverified
        address.
        """

        from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState

        if self._if._icmp6_dad__states.get(ip6__src) is Icmp6DadState.OPTIMISTIC:
            flag_o = False

        options = Icmp6NdOptions(Icmp6NdOptionTlla(tlla=self._if._mac_unicast)) if include_tlla else Icmp6NdOptions()

        self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__src,
                ip6__dst=ip6__dst,
                ip6__hop=255,
                icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                    flag_r=flag_r,
                    flag_s=flag_s,
                    flag_o=flag_o,
                    target_address=target_address,
                    options=options,
                ),
                echo_tracker=echo_tracker,
            )
        )

    def send_icmp6_neighbor_advertisement_gratuitous(
        self,
        *,
        ip6_unicast: Ip6Address,
    ) -> None:
        """
        Enqueue 'icmp6.gratuitous_na_count' gratuitous Neighbor
        Advertisement messages for 'ip6_unicast' — the IPv6
        analogue of RFC 5227 §2.3 ARP Announcement, formalised
        by RFC 9131 §3 (host attachment). The wire shape:

          - Target Address = 'ip6_unicast'
          - flag_o (Override) = True (overrides any cache
            entry for this address — the whole point)
          - flag_s (Solicited) = False (unsolicited)
          - Destination = ff02::1 (all-nodes link-local
            multicast — every on-link host receives it)
          - TLLA option carries the host's MAC

        Operators tune the emit count via the
        'icmp6.gratuitous_na_count' sysctl (default 1; 0 is the
        kill switch).
        """

        for _ in range(sysctl_iface.get_for_iface("icmp6.gratuitous_na_count", self._if._interface_name)):
            self.send_icmp6_neighbor_advertisement(
                ip6__src=ip6_unicast,
                ip6__dst=Ip6Address("ff02::1"),
                target_address=ip6_unicast,
                flag_s=False,
                flag_o=True,
                include_tlla=True,
            )

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int | None = None,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv6 Socket -> FPA communication.
        Marshaled onto the interface's TX worker via '_marshal_tx'.
        """

        return self._if._marshal_tx(
            lambda: self._phtx_icmp6(
                ip6__src=ip6__local_address,
                ip6__dst=ip6__remote_address,
                ip6__hop=ip6__hop,
                icmp6__message=icmp6__message,
            )
        )
