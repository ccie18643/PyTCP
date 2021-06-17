#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# protocols/ip6/phrx.py - packet handler for inbound IPv6 packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from lib.logger import log
from misc.packet import PacketRx
from protocols.ip6.fpp import Ip6Parser
from protocols.ip6.ps import (
    IP6_NEXT_HEADER_EXT_FRAG,
    IP6_NEXT_HEADER_ICMP6,
    IP6_NEXT_HEADER_TCP,
    IP6_NEXT_HEADER_UDP,
)


def _phrx_ip6(self, packet_rx: PacketRx) -> None:
    """Handle inbound IPv6 packets"""

    Ip6Parser(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            log("ip6", f"{packet_rx.tracker} - <rb>{packet_rx.parse_failed}</>")
        return

    if __debug__:
        log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6}")

    # Check if received packet has been sent to us directly or by unicast or multicast
    if packet_rx.ip6.dst not in {*self.ip6_unicast, *self.ip6_multicast}:
        if __debug__:
            log("ip6", f"{packet_rx.tracker} - IP packet not destined for this stack, dropping")
        return

    if packet_rx.ip6.next == IP6_NEXT_HEADER_EXT_FRAG:
        self._phrx_ip6_ext_frag(packet_rx)
        return

    if packet_rx.ip6.next == IP6_NEXT_HEADER_ICMP6:
        self._phrx_icmp6(packet_rx)
        return

    if packet_rx.ip6.next == IP6_NEXT_HEADER_UDP:
        self._phrx_udp(packet_rx)
        return

    if packet_rx.ip6.next == IP6_NEXT_HEADER_TCP:
        self._phrx_tcp(packet_rx)
        return
