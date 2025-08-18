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
This module contains packet handler for the inbound Ethernet II packets.

pytcp/subsystems/packet_handler/packet_handler__ethernet__rx.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.errors import PacketValidationError
from pytcp.protocols.ethernet.ethernet__header import EtherType
from pytcp.protocols.ethernet.ethernet__parser import EthernetParser


class PacketHandlerEthernetRx(ABC):
    """
    Class implements packet handler for the inbound Ethernet packets.
    """

    if TYPE_CHECKING:
        from net_addr import MacAddress
        from pytcp.lib.packet_rx import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx

        _packet_stats_rx: PacketStatsRx
        _mac_unicast: MacAddress
        _mac_multicast: list[MacAddress]
        _mac_broadcast: MacAddress

        _ip4_support: bool
        _ip6_support: bool

        # pylint: disable=unused-argument

        def _phrx_arp(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_ip6(self, packet_rx: PacketRx, /) -> None: ...
        def _phrx_ip4(self, packet_rx: PacketRx, /) -> None: ...

    def _phrx_ethernet(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound Ethernet packets.
        """

        self._packet_stats_rx.inc("ethernet__pre_parse")

        try:
            EthernetParser(packet_rx)

        except PacketValidationError as error:
            self._packet_stats_rx.inc("ethernet__failed_parse__drop")
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log(
            "ether", f"{packet_rx.tracker} - {packet_rx.ethernet}"
        )

        # Check if received packet matches any of stack MAC addresses.
        if packet_rx.ethernet.dst not in {
            self._mac_unicast,
            *self._mac_multicast,
            self._mac_broadcast,
        }:
            self._packet_stats_rx.inc("ethernet__dst_unknown__drop")
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Ethernet packet not destined for this "
                "stack, dropping",
            )
            return

        if packet_rx.ethernet.dst == self._mac_unicast:
            self._packet_stats_rx.inc("ethernet__dst_unicast")

        if packet_rx.ethernet.dst in self._mac_multicast:
            self._packet_stats_rx.inc("ethernet__dst_multicast")

        if packet_rx.ethernet.dst == self._mac_broadcast:
            self._packet_stats_rx.inc("ethernet__dst_broadcast")

        match packet_rx.ethernet.type:
            case EtherType.ARP if self._ip4_support:
                self._phrx_arp(packet_rx)
            case EtherType.IP4 if self._ip4_support:
                self._phrx_ip4(packet_rx)
            case EtherType.IP6 if self._ip6_support:
                self._phrx_ip6(packet_rx)
            case _:
                self._packet_stats_rx.inc("ethernet__no_proto_support__drop")
                __debug__ and log(
                    "ether",
                    f"{packet_rx.tracker} - Unsupported protocol "
                    f"{packet_rx.ethernet.type}, dropping.",
                )
