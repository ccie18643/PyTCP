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
Module contains packet handler for the inbound Ethernet packets.

pytcp/subsystems/packet_handler/packet_handler__ethernet_802_3__rx.py

ver 3.0.2
"""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.errors import PacketValidationError
from pytcp.protocols.ethernet_802_3.ethernet_802_3__parser import (
    Ethernet8023Parser,
)


class PacketHandlerEthernet8023Rx(ABC):
    """
    Class implements packet handler for the inbound Ethernet 802.3 packets.
    """

    if TYPE_CHECKING:
        from net_addr import MacAddress
        from pytcp.lib.packet import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx
        mac_unicast: MacAddress
        mac_multicast: list[MacAddress]
        mac_broadcast: MacAddress

        # pylint: disable=unused-argument

        def _phrx_arp(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_ip6(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_ip4(self, packet_rx: PacketRx, /) -> None: ...

    def _phrx_ethernet_802_3(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound Ethernet 802.3 packets.
        """

        self.packet_stats_rx.ethernet_802_3__pre_parse += 1

        try:
            Ethernet8023Parser(packet_rx)

        except PacketValidationError as error:
            self.packet_stats_rx.ethernet_802_3__failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log(
            "ether", f"{packet_rx.tracker} - {packet_rx.ethernet_802_3}"
        )

        # Check if received packet matches any of stack MAC addresses.
        if packet_rx.ethernet_802_3.dst not in {
            self.mac_unicast,
            *self.mac_multicast,
            self.mac_broadcast,
        }:
            self.packet_stats_rx.ethernet_802_3__dst_unknown__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Ethernet 802.3 packet not destined for this "
                "stack, dropping",
            )
            return

        if packet_rx.ethernet_802_3.dst == self.mac_unicast:
            self.packet_stats_rx.ethernet__dst_unicast += 1

        if packet_rx.ethernet_802_3.dst in self.mac_multicast:
            self.packet_stats_rx.ethernet__dst_multicast += 1

        if packet_rx.ethernet_802_3.dst == self.mac_broadcast:
            self.packet_stats_rx.ethernet__dst_broadcast += 1
