#!/usr/bin/env python3

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

# pylint: disable=expression-not-assigned
# pylint: disable=too-many-locals
# pylint: disable=too-many-return-statements
# pylint: disable=unused-argument
# pylint: disable=missing-function-docstring

"""
Module contains packet handler for the outbound ICMPv6 packets.

pytcp/protocols/icmp6/icmp6__packet_handler_tx.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Message, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_reply import (
    Icmp6EchoReplyCode,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_request import (
    Icmp6EchoRequestCode,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    Icmp6Mld2ReportCode,
    Icmp6Mld2ReportMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_advertisement import (
    Icmp6NdNeighborAdvertisementCode,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_solicitation import (
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdNeighborSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementCode,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationCode,
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)


class Icmp6PacketHandlerTx(ABC):
    """
    Class defines methods for handling outbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from pytcp.config import IP6__DEFAULT_HOP_LIMIT
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ip6.ip6__base import Ip6Payload
        from pytcp.protocols.raw.raw__assembler import RawAssembler

        packet_stats_tx: PacketStatsTx
        mac_unicast: MacAddress
        ip6_multicast: list[Ip6Address]

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = IP6__DEFAULT_HOP_LIMIT,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus: ...

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

    def _phtx_icmp6(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__hop: int = 64,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ICMPv6 packets.
        """

        self.packet_stats_tx.icmp6__pre_assemble += 1

        icmp6_packet_tx = Icmp6Assembler(
            icmp6__message=icmp6__message,
            echo_tracker=echo_tracker,
        )

        __debug__ and log(
            "icmp6", f"{icmp6_packet_tx.tracker} - {icmp6_packet_tx}"
        )

        match (icmp6__message.type, icmp6__message.code):
            case (Icmp6Type.ECHO_REPLY, Icmp6EchoReplyCode.DEFAULT):
                self.packet_stats_tx.icmp6__echo_reply__send += 1

            case (Icmp6Type.ECHO_REQUEST, Icmp6EchoRequestCode.DEFAULT):
                self.packet_stats_tx.icmp6__echo_request__send += 1

            case (
                Icmp6Type.DESTINATION_UNREACHABLE,
                Icmp6DestinationUnreachableCode.PORT,
            ):
                self.packet_stats_tx.icmp6__unreachable_port__send += 1

            case (
                Icmp6Type.ND__ROUTER_SOLICITATION,
                Icmp6NdRouterSolicitationCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_router_solicitation__send += 1

            case (
                Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                Icmp6NdRouterAdvertisementCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_router_advertisement__send += 1

            case (
                Icmp6Type.ND__NEIGHBOR_SOLICITATION,
                Icmp6NdNeighborSolicitationCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_neighbor_solicitation__send += 1

            case (
                Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
                Icmp6NdNeighborAdvertisementCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_neighbor_advertisement__send += 1

            case (Icmp6Type.MLD2__REPORT, Icmp6Mld2ReportCode.DEFAULT):
                self.packet_stats_tx.icmp6__mld2_report__send += 1

        return self._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=icmp6_packet_tx,
        )

    def _send_icmp6_nd_dad_message(
        self, *, ip6_unicast_candidate: Ip6Address
    ) -> None:
        """
        Send out ICMPv6 ND Duplicate Address Detection message.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=Ip6Address(0),
            ip6__dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdNeighborSolicitationMessage(
                target_address=ip6_unicast_candidate,
                options=Icmp6NdOptions(),  # ND DAD message has no options.
            ),
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 ND DAD message for "
                f"{ip6_unicast_candidate}, tx_status: {tx_status}",
            )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send out ICMPv6 Multicast Listener Report for given list of addresses.
        """

        # Need to use set here to avoid re-using duplicate multicast entries
        # from stack_ip6_multicast list, also All Multicast Nodes address is
        # not being advertised as this is not necessary.
        if icmp6_mlr2_multicast_address_record := {
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                multicast_address=multicast_address,
            )
            for multicast_address in self.ip6_multicast
            if multicast_address not in {Ip6Address("ff02::1")}
        }:
            tx_status = self._phtx_icmp6(
                ip6__src=(
                    self.ip6_unicast[0] if self.ip6_unicast else Ip6Address(0)
                ),
                ip6__dst=Ip6Address("ff02::16"),
                ip6__hop=1,
                icmp6__message=Icmp6Mld2ReportMessage(
                    records=list(icmp6_mlr2_multicast_address_record)
                ),
            )

            if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
                __debug__ and log(
                    "stack",
                    "Sent out ICMPv6 Multicast Listener Report message for "
                    f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}",
                )
            else:
                __debug__ and log(
                    "stack",
                    "Failed to send out ICMPv6 Multicast Listener Report message for "
                    f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}, "
                    f"tx_status: {tx_status}",
                )

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send out ICMPv6 ND Router Solicitation.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=self.ip6_unicast[0],
            ip6__dst=Ip6Address("ff02::2"),
            ip6__hop=255,
            icmp6__message=Icmp6NdRouterSolicitationMessage(
                options=Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=self.mac_unicast),
                ),
            ),
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log("stack", "Sent out ICMPv6 ND Router Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Router Solicitation, {tx_status}",
            )

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int = 64,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv4 Socket -> FPA communication.
        """

        return self._phtx_icmp6(
            ip6__src=ip6__local_address,
            ip6__dst=ip6__remote_address,
            ip6__hop=ip6__hop,
            icmp6__message=icmp6__message,
        )
