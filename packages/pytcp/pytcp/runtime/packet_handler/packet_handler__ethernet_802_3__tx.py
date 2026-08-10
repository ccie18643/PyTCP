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
This module contains packet handler for the outbound Ethernet 802.3 packets.

pytcp/runtime/packet_handler/packet_handler__ethernet_802_3__tx.py

ver 3.0.10
"""

from typing import TYPE_CHECKING

from net_addr import MacAddress
from net_proto import Ethernet8023Assembler, Ethernet8023Payload, RawAssembler
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class Ethernet8023TxHandler:
    """
    The outbound Ethernet 802.3 packet handler for one interface.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

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

        self._if._packet_stats_tx.ethernet_802_3__pre_assemble += 1

        ethernet_802_3_packet_tx = Ethernet8023Assembler(
            ethernet_802_3__src=ethernet_802_3__src,
            ethernet_802_3__dst=ethernet_802_3__dst,
            ethernet_802_3__payload=ethernet_802_3__payload,
        )

        # Check if packet contains valid source address, fill it out if needed.
        if ethernet_802_3_packet_tx.src.is_unspecified:
            self._if._packet_stats_tx.ethernet_802_3__src_unspec__fill += 1
            ethernet_802_3_packet_tx.src = self._if._mac_unicast
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Set source to stack MAC " f"{ethernet_802_3_packet_tx.src}",
            )
        else:
            self._if._packet_stats_tx.ethernet_802_3__src_spec += 1
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Source MAC specified to " f"{ethernet_802_3_packet_tx.src}",
            )

        # Send out packet if it contains valid destination MAC address.
        if not ethernet_802_3_packet_tx.dst.is_unspecified:
            self._if._packet_stats_tx.ethernet_802_3__dst_spec__send += 1
            __debug__ and log(
                "ether",
                f"{ethernet_802_3_packet_tx.tracker} - Contains valid destination " "MAC address",
            )
            self.__send_out_packet(ethernet_802_3_packet_tx)
            return TxStatus.PASSED__ETHERNET_802_3__TO_TX_RING

        # Drop packet in case we are not able to obtain valid destination MAC address.
        self._if._packet_stats_tx.ethernet_802_3__dst_unspec__drop += 1
        __debug__ and log(
            "ether",
            f"{ethernet_802_3_packet_tx.tracker} - <WARN>No valid destination MAC could " "be obtained, dropping</>",
        )
        return TxStatus.DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL

    def __send_out_packet(
        self,
        ethernet_802_3_packet_tx: Ethernet8023Assembler,
    ) -> None:
        __debug__ and log(
            "ether",
            f"{ethernet_802_3_packet_tx.tracker} - {ethernet_802_3_packet_tx}",
        )
        assert self._if._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._if._tx_ring.enqueue(ethernet_802_3_packet_tx)
