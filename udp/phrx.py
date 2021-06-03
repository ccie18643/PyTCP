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
# udp/phrx.py - packet handler for inbound UDP packets
#


from __future__ import annotations  # Required by Python ver < 3.10

import loguru

import icmp4.ps
import icmp6.ps
import misc.stack as stack
from lib.ip4_address import Ip4Address
from lib.ip6_address import Ip6Address
from misc.packet import PacketRx
from udp.fpp import UdpParser
from udp.metadata import UdpMetadata


def _phrx_udp(self, packet_rx: PacketRx) -> None:
    """Handle inbound UDP packets"""

    UdpParser(packet_rx)
    assert packet_rx.udp is not None
    assert packet_rx.ip is not None

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{self.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.udp}")

    # Create UdpMetadata object and try to find matching UDP socket
    packet = UdpMetadata(
        local_ip_address=packet_rx.ip.dst,
        local_port=packet_rx.udp.dport,
        remote_ip_address=packet_rx.ip.src,
        remote_port=packet_rx.udp.sport,
        data=packet_rx.udp.data,
        tracker=packet_rx.tracker,
    )

    for socket_id in packet.socket_id_patterns:
        socket = stack.udp_sockets.get(socket_id, None)
        if socket:
            if __debug__:
                loguru.logger.bind(object_name="socket.").debug(f"{packet.tracker} - Found matching listening socket {socket_id}")
            socket.process_packet(packet)
            return

    # Silently drop packet if it has all zero source IP address
    if packet_rx.ip.src in {Ip4Address("0.0.0.0"), Ip6Address("::")}:
        if __debug__:
            self._logger.debug(
                f"Received UDP packet from {packet_rx.ip.src}, port {packet_rx.udp.sport} to {packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping..."
            )
        return

    # Respond with ICMP Port Unreachable message if no matching socket has been found
    if __debug__:
        self._logger.debug(f"Received UDP packet from {packet_rx.ip.src} to closed port {packet_rx.udp.dport}, sending ICMPv4 Port Unreachable")

    if packet_rx.ip.ver == 6:
        self._phtx_icmp6(
            ip6_src=packet_rx.ip.dst,
            ip6_dst=packet_rx.ip.src,
            icmp6_type=icmp6.ps.ICMP6_UNREACHABLE,
            icmp6_code=icmp6.ps.ICMP6_UNREACHABLE__PORT,
            icmp6_un_data=packet_rx.ip.packet_copy,
            echo_tracker=packet_rx.tracker,
        )

    if packet_rx.ip.ver == 4:
        self._phtx_icmp4(
            ip4_src=packet_rx.ip.dst,
            ip4_dst=packet_rx.ip.src,
            icmp4_type=icmp4.ps.ICMP4_UNREACHABLE,
            icmp4_code=icmp4.ps.ICMP4_UNREACHABLE__PORT,
            icmp4_un_data=packet_rx.ip.packet_copy,
            echo_tracker=packet_rx.tracker,
        )

    return
