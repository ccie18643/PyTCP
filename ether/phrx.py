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
# ether/phrx.py - packet handler for inbound Ethernet packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING

import config
import ether.ps
from ether.fpp import EtherParser

if TYPE_CHECKING:
    from misc.packet import PacketRx


def _phrx_ether(self, packet_rx: PacketRx) -> None:
    """Handle inbound Ethernet packets"""

    EtherParser(packet_rx)
    assert packet_rx.ether is not None

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.debug(f"{packet_rx.tracker} - {packet_rx.ether}")

    # Check if received packet matches any of stack MAC addresses
    if packet_rx.ether.dst not in {self.mac_unicast, *self.mac_multicast, self.mac_broadcast}:
        if __debug__:
            self._logger.opt(ansi=True).debug(f"{packet_rx.tracker} - Ethernet packet not destined for this stack, dropping...")
        return

    if packet_rx.ether.type == ether.ps.ETHER_TYPE_ARP and config.ip4_support:
        self._phrx_arp(packet_rx)
        return

    if packet_rx.ether.type == ether.ps.ETHER_TYPE_IP4 and config.ip4_support:
        self._phrx_ip4(packet_rx)
        return

    if packet_rx.ether.type == ether.ps.ETHER_TYPE_IP6 and config.ip6_support:
        self._phrx_ip6(packet_rx)
        return
