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

# pylint: disable = protected-access
# pylint: disable = expression-not-assigned

"""
Module contains packet handler for the inbound Ethernet packets.

pytcp/protocols/ethernet/phrx.py

ver 2.7
"""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.logger import log
from pytcp.protocols.ethernet.fpp import EthernetParser
from pytcp.protocols.ethernet.ps import EthernetType


class PacketHandlerRxEthernet(ABC):
    """
    Class implements packet handler for the inbound Ethernet packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.mac_address import MacAddress
        from pytcp.lib.packet import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx
        mac_unicast: MacAddress
        mac_multicast: list[MacAddress]
        mac_broadcast: MacAddress

        def _phrx_arp(self, *, packet_rx: PacketRx) -> None:
            ...

        def _phrx_ip6(self, *, packet_rx: PacketRx) -> None:
            ...

        def _phrx_ip4(self, *, packet_rx: PacketRx) -> None:
            ...

    def _phrx_ethernet(self, *, packet_rx: PacketRx) -> None:
        """
        Handle inbound Ethernet packets.
        """

        self.packet_stats_rx.ethernet__pre_parse += 1

        try:
            EthernetParser(packet_rx)
        except PacketValidationError as error:
            self.packet_stats_rx.ethernet__failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log(
            "ether", f"{packet_rx.tracker} - {packet_rx.ethernet}"
        )

        # Check if received packet matches any of stack MAC addresses
        if packet_rx.ethernet.dst not in {
            self.mac_unicast,
            *self.mac_multicast,
            self.mac_broadcast,
        }:
            self.packet_stats_rx.ethernet__dst_unknown__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Ethernet packet not destined for this "
                "stack, dropping",
            )
            return

        if packet_rx.ethernet.dst == self.mac_unicast:
            self.packet_stats_rx.ethernet__dst_unicast += 1

        if packet_rx.ethernet.dst in self.mac_multicast:
            self.packet_stats_rx.ethernet__dst_multicast += 1

        if packet_rx.ethernet.dst == self.mac_broadcast:
            self.packet_stats_rx.ethernet__dst_broadcast += 1

        if packet_rx.ethernet.type == EthernetType.ARP and config.IP4_SUPPORT:
            self._phrx_arp(packet_rx=packet_rx)
            return

        if packet_rx.ethernet.type == EthernetType.IP4 and config.IP4_SUPPORT:
            self._phrx_ip4(packet_rx=packet_rx)
            return

        if packet_rx.ethernet.type == EthernetType.IP6 and config.IP6_SUPPORT:
            self._phrx_ip6(packet_rx=packet_rx)
            return