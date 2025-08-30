#!/usr/bin/env python3

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
This module contains packet handler for the outbound Ethernet 802.3 packets.

pytcp/subsystems/packet_handler/packet_handler__ethernet_802_3__tx.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from net_addr import MacAddress
from net_proto import Ethernet8023Assembler, RawAssembler

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerEthernet8023Tx(ABC):
    """
    Class implements packet handler for the outbound Ethernet 802.3 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Host, Ip6Host
        from net_proto import Ethernet8023Payload

        from pytcp.lib.packet_stats import PacketStatsTx

        _packet_stats_tx: PacketStatsTx
        _mac_unicast: MacAddress

    def _phtx_ethernet_802_3(
        self,
        *,
        ethernet_802_3__src: MacAddress = MacAddress(),
        ethernet_802_3__dst: MacAddress = MacAddress(),
        ethernet_802_3__payload: Ethernet8023Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound Ethernet 802.3 packets.
        """

        self._packet_stats_tx.inc("ethernet_802_3__pre_assemble")

        ethernet_802_3_packet_tx = Ethernet8023Assembler(
            ethernet_802_3__src=ethernet_802_3__src,
            ethernet_802_3__dst=ethernet_802_3__dst,
            ethernet_802_3__payload=ethernet_802_3__payload,
        )

        # Check if packet contains valid source address, fill it out if needed.
        if ethernet_802_3_packet_tx.src.is_unspecified:
            self._packet_stats_tx.inc("ethernet__src_unspec__fill")
            ethernet_802_3_packet_tx.src = self._mac_unicast
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Set source to stack MAC "
                f"{ethernet_802_3_packet_tx.src}",
            )
        else:
            self._packet_stats_tx.inc("ethernet_802_3__src_spec")
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Source MAC specified to "
                f"{ethernet_802_3_packet_tx.src}",
            )

        # Send out packet if it contains valid destination MAC address.
        if not ethernet_802_3_packet_tx.dst.is_unspecified:
            self._packet_stats_tx.inc("ethernet__dst_spec__send")
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Contains valid destination "
                "MAC address",
            )
            self.__send_out_packet(ethernet_802_3_packet_tx)
            return TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING

        # Drop packet in case we are not able to obtain valid destination MAC address.
        self._packet_stats_tx.inc("ethernet__dst_unspec__drop")
        __debug__ and log(
            "ether",
            f"{ethernet_802_3_packet_tx.tracker} - <WARN>No valid destination MAC could "
            "be obtained, dropping</>",
        )
        return TxStatus.DROPED__ETHERNET_802_3__DST_RESOLUTION_FAIL

    @staticmethod
    def __send_out_packet(
        ethernet_802_3_packet_tx: Ethernet8023Assembler,
    ) -> None:
        __debug__ and log(
            "ether",
            f"{ethernet_802_3_packet_tx.tracker} - {ethernet_802_3_packet_tx}",
        )
        stack.tx_ring.enqueue(ethernet_802_3_packet_tx)
