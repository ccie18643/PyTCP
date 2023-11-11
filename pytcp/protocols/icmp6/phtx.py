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

# pylint: disable = expression-not-assigned
# pylint: disable = too-many-locals
# pylint: disable = too-many-return-statements
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound ICMPv6 packets.

pytcp/protocols/icmp6/phtx.py

2.7
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.fpa import Icmp6Assembler
from pytcp.protocols.icmp6.ps import (
    Icmp6EchoReplyCode,
    Icmp6EchoRequestCode,
    Icmp6Message,
    Icmp6Mld2ReportCode,
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdRouterAdvertisementCode,
    Icmp6NdRouterSolicitationCode,
    Icmp6Type,
    Icmp6UnreachableCode,
)


class PacketHandlerTxIcmp6(ABC):
    """
    Class defines methods for handling outbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from pytcp.config import IP6_DEFAULT_HOP
        from pytcp.lib.ip6_address import Ip6Address
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.lib.tx_status import TxStatus
        from pytcp.protocols.ip6.ps import Ip6Payload
        from pytcp.protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
        from pytcp.protocols.raw.fpa import RawAssembler
        from pytcp.protocols.tcp.fpa import TcpAssembler
        from pytcp.protocols.udp.fpa import UdpAssembler

        packet_stats_tx: PacketStatsTx

        def _phtx_ip6(
            self,
            *,
            ip6__dst: Ip6Address,
            ip6__src: Ip6Address,
            ip6__hop: int = IP6_DEFAULT_HOP,
            ip6__payload: Ip6Payload = RawAssembler(),
        ) -> TxStatus:
            ...

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
            message=icmp6__message,
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

            case (Icmp6Type.UNREACHABLE, Icmp6UnreachableCode.PORT):
                self.packet_stats_tx.icmp6__unreachable_port__send += 1

            case (
                Icmp6Type.ND_ROUTER_SOLICITATION,
                Icmp6NdRouterSolicitationCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_router_solicitation__send += 1

            case (
                Icmp6Type.ND_ROUTER_ADVERTISEMENT,
                Icmp6NdRouterAdvertisementCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_router_advertisement__send += 1

            case (
                Icmp6Type.ND_NEIGHBOR_SOLICITATION,
                Icmp6NdNeighborSolicitationCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_neighbor_solicitation__send += 1

            case (
                Icmp6Type.ND_NEIGHBOR_ADVERTISEMENT,
                Icmp6NdNeighborAdvertisementCode.DEFAULT,
            ):
                self.packet_stats_tx.icmp6__nd_neighbor_advertisement__send += 1

            case (Icmp6Type.MLD2_REPORT, Icmp6Mld2ReportCode.DEFAULT):
                self.packet_stats_tx.icmp6__mld2_report__send += 1

        return self._phtx_ip6(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__payload=icmp6_packet_tx,
        )
