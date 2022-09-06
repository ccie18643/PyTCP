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


#
# protocols/ether/phrx.py - packet handler for inbound Ethernet packets
#
# ver 2.7
#


from __future__ import annotations

from typing import TYPE_CHECKING

import config
from protocols.ether.fpp import EtherParser
from protocols.ether.ps import ETHER_TYPE_ARP, ETHER_TYPE_IP4, ETHER_TYPE_IP6

if TYPE_CHECKING:
    from misc.packet import PacketRx

from lib.logger import log


def _phrx_ether(self, packet_rx: PacketRx) -> None:
    """
    Handle inbound Ethernet packets.
    """

    self.packet_stats_rx.ether__pre_parse += 1

    EtherParser(packet_rx)

    if packet_rx.parse_failed:
        self.packet_stats_rx.ether__failed_parse__drop += 1
        if __debug__:
            log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
            )
        return

    if __debug__:
        log("ether", f"{packet_rx.tracker} - {packet_rx.ether}")

    # Check if received packet matches any of stack MAC addresses
    if packet_rx.ether.dst not in {
        self.mac_unicast,
        *self.mac_multicast,
        self.mac_broadcast,
    }:
        self.packet_stats_rx.ether__dst_unknown__drop += 1
        if __debug__:
            log(
                "ether",
                f"{packet_rx.tracker} - Ethernet packet not destined for this "
                "stack, dropping",
            )
        return

    if packet_rx.ether.dst == self.mac_unicast:
        self.packet_stats_rx.ether__dst_unicast += 1

    if packet_rx.ether.dst in self.mac_multicast:
        self.packet_stats_rx.ether__dst_multicast += 1

    if packet_rx.ether.dst == self.mac_broadcast:
        self.packet_stats_rx.ether__dst_broadcast += 1

    if packet_rx.ether.type == ETHER_TYPE_ARP and config.IP4_SUPPORT:
        self._phrx_arp(packet_rx)
        return

    if packet_rx.ether.type == ETHER_TYPE_IP4 and config.IP4_SUPPORT:
        self._phrx_ip4(packet_rx)
        return

    if packet_rx.ether.type == ETHER_TYPE_IP6 and config.IP6_SUPPORT:
        self._phrx_ip6(packet_rx)
        return
