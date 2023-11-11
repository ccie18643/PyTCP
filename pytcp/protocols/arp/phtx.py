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
# pylint: disable = protected-access

"""
Module contains packet handler for the outbound ARP packets.

pytcp/protocols/arp/phtx.py

ver 2.7
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.arp.fpa import ArpAssembler
from pytcp.protocols.arp.ps import ArpOperation


class PacketHandlerTxArp(ABC):
    """
    Packet handler for the outbound ARP packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip4_address import Ip4Address
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ethernet.ps import EthernetPayload
        from pytcp.protocols.ip4.fpa import Ip4Assembler, Ip4FragAssembler
        from pytcp.protocols.ip6.fpa import Ip6Assembler
        from pytcp.protocols.raw.fpa import RawAssembler

        packet_stats_tx: PacketStatsTx

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(0),
            ethernet__dst: MacAddress = MacAddress(0),
            ethernet__payload: EthernetPayload | None = None,
        ) -> TxStatus:
            ...

    def _phtx_arp(
        self,
        *,
        ethernet__src: MacAddress,
        ethernet__dst: MacAddress,
        arp__oper: ArpOperation,
        arp__sha: MacAddress,
        arp__spa: Ip4Address,
        arp__tha: MacAddress,
        arp__tpa: Ip4Address,
        echo_tracker: Tracker | None = None,
    ) -> TxStatus:
        """
        Handle outbound ARP packets.
        """

        self.packet_stats_tx.arp__pre_assemble += 1

        # Check if IPv4 protocol support is enabled, if not then silently
        # drop the packet
        if not config.IP4_SUPPORT:
            self.packet_stats_tx.arp__no_proto_support__drop += 1
            return TxStatus.DROPED__ARP__NO_PROTOCOL_SUPPORT

        match arp__oper:
            case ArpOperation.REQUEST:
                self.packet_stats_tx.arp__op_request__send += 1
            case ArpOperation.REPLY:
                self.packet_stats_tx.arp__op_reply__send += 1

        arp_packet_tx = ArpAssembler(
            arp__oper=arp__oper,
            arp__sha=arp__sha,
            arp__spa=arp__spa,
            arp__tha=arp__tha,
            arp__tpa=arp__tpa,
            echo_tracker=echo_tracker,
        )

        __debug__ and log("arp", f"{arp_packet_tx.tracker} - {arp_packet_tx}")

        return self._phtx_ethernet(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=arp_packet_tx,
        )
