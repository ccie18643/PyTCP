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
# icmp4/phrx.py - packet handler for inbound ICMPv4 packets
#


from typing import cast

import icmp4.fpp
import icmp4.ps
from icmp4.fpp import Parser as Icmp4Parser
from ip4.fpp import Parser as Ip4Parser
from misc.packet import PacketRx


def _phrx_icmp4(self, packet_rx: PacketRx) -> None:
    """Handle inbound ICMPv4 packets"""

    icmp4.fpp.Parser(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.icmp4}")

    packet_rx.icmp4 = cast(Icmp4Parser, packet_rx.icmp4)

    # Respond to ICMPv4 Echo Request packet
    packet_rx.ip4 = cast(Ip4Parser, packet_rx.ip4)
    if packet_rx.icmp4.type == icmp4.ps.ECHO_REQUEST:
        if __debug__:
            self._logger.debug(f"Received ICMPv4 Echo Request packet from {packet_rx.ip4.src}, sending reply...")

        self._phtx_icmp4(
            ip4_src=packet_rx.ip4.dst,
            ip4_dst=packet_rx.ip4.src,
            icmp4_type=icmp4.ps.ECHO_REPLY,
            icmp4_ec_id=packet_rx.icmp4.ec_id,
            icmp4_ec_seq=packet_rx.icmp4.ec_seq,
            icmp4_ec_data=packet_rx.icmp4.ec_data,
            echo_tracker=packet_rx.tracker,
        )
        return
