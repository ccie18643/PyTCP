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
# arp/phtx.py - packet handler for outbound ARP packets
#


from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING

import config
from arp.fpa import ArpAssembler
from lib.mac_address import MacAddress
from misc.tracker import Tracker

if TYPE_CHECKING:
    from lib.ip4_address import Ip4Address


def _phtx_arp(
    self,
    ether_src: MacAddress,
    ether_dst: MacAddress,
    arp_oper: int,
    arp_sha: MacAddress,
    arp_spa: Ip4Address,
    arp_tha: MacAddress,
    arp_tpa: Ip4Address,
    echo_tracker: Tracker = None,
) -> None:
    """Handle outbound ARP packets"""

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not config.ip4_support:
        return

    arp_packet_tx = ArpAssembler(
        oper=arp_oper,
        sha=arp_sha,
        spa=arp_spa,
        tha=arp_tha,
        tpa=arp_tpa,
        echo_tracker=echo_tracker,
    )

    if __debug__:
        self._logger.opt(ansi=True).info(f"<magenta>{arp_packet_tx.tracker}</magenta> - {arp_packet_tx}")

    self._phtx_ether(ether_src=ether_src, ether_dst=ether_dst, carried_packet=arp_packet_tx)
