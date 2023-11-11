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
Module contains packet handler for the inbound IPv6 packets.

pytcp/protocols/ip6/phrx.py

ver 2.7
"""


from __future__ import annotations

from abc import ABC, abstractproperty
from typing import TYPE_CHECKING

from pytcp.lib.errors import PacketValidationError
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6.fpp import Ip6Parser
from pytcp.protocols.ip6.ps import (
    IP6_NEXT_EXT_FRAG,
    IP6_NEXT_ICMP6,
    IP6_NEXT_TCP,
    IP6_NEXT_UDP,
)


class PacketHandlerRxIp6(ABC):
    """
    Class implements packet handler for the inbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip6_address import Ip6Address
        from pytcp.lib.packet_stats import PacketStatsRx

        packet_stats_rx: PacketStatsRx

        def _phrx_ip6_ext_frag(self, *, packet_rx: PacketRx) -> None:
            ...

        def _phrx_icmp6(self, *, packet_rx: PacketRx) -> None:
            ...

        def _phrx_udp(self, *, packet_rx: PacketRx) -> None:
            ...

        def _phrx_tcp(self, *, packet_rx: PacketRx) -> None:
            ...

        @abstractproperty
        def ip6_unicast(self) -> list[Ip6Address]:
            ...

        @abstractproperty
        def ip6_multicast(self) -> list[Ip6Address]:
            ...

    def _phrx_ip6(self, *, packet_rx: PacketRx) -> None:
        """
        Handle inbound IPv6 packets.
        """

        self.packet_stats_rx.ip6__pre_parse += 1

        try:
            Ip6Parser(packet_rx)
        except PacketValidationError as error:
            self.packet_stats_rx.ip6__failed_parse__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <rb>{error}</>")
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6}")

        # Check if received packet has been sent to us directly or by unicast
        # or multicast
        if packet_rx.ip6.dst not in {*self.ip6_unicast, *self.ip6_multicast}:
            self.packet_stats_rx.ip6__dst_unknown__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - IP packet not destined for this stack, "
                "dropping",
            )
            return

        if packet_rx.ip6.dst in self.ip6_unicast:
            self.packet_stats_rx.ip6__dst_unicast += 1

        if packet_rx.ip6.dst in self.ip6_multicast:
            self.packet_stats_rx.ip6__dst_multicast += 1

        if packet_rx.ip6.next == IP6_NEXT_EXT_FRAG:
            self._phrx_ip6_ext_frag(
                packet_rx=packet_rx,
            )
            return

        if packet_rx.ip6.next == IP6_NEXT_ICMP6:
            self._phrx_icmp6(
                packet_rx=packet_rx,
            )
            return

        if packet_rx.ip6.next == IP6_NEXT_UDP:
            self._phrx_udp(
                packet_rx=packet_rx,
            )
            return

        if packet_rx.ip6.next == IP6_NEXT_TCP:
            self._phrx_tcp(
                packet_rx=packet_rx,
            )
            return
