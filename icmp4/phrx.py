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


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING

import icmp4.fpp
import icmp4.ps
import ip4.ps
import misc.stack as stack
import udp.ps
from icmp4.fpp import Icmp4Parser
from lib.ip4_address import Ip4Address
from udp.metadata import UdpMetadata

if TYPE_CHECKING:
    from misc.packet import PacketRx


def _phrx_icmp4(self, packet_rx: PacketRx) -> None:
    """Handle inbound ICMPv4 packets"""

    Icmp4Parser(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<lg>{packet_rx.tracker}</> - {packet_rx.icmp4}")

    # ICMPv4 Echo Request packet
    if packet_rx.icmp4.type == icmp4.ps.ICMP4_ECHO_REQUEST:
        if __debug__:
            self._logger.debug(f"{packet_rx.tracker} - Received ICMPv4 Echo Request packet from {packet_rx.ip4.src}, sending reply...")

        self._phtx_icmp4(
            ip4_src=packet_rx.ip4.dst,
            ip4_dst=packet_rx.ip4.src,
            icmp4_type=icmp4.ps.ICMP4_ECHO_REPLY,
            icmp4_ec_id=packet_rx.icmp4.ec_id,
            icmp4_ec_seq=packet_rx.icmp4.ec_seq,
            icmp4_ec_data=packet_rx.icmp4.ec_data,
            echo_tracker=packet_rx.tracker,
        )
        return

    # ICMPv4 Unreachable packet
    if packet_rx.icmp4.type == icmp4.ps.ICMP4_UNREACHABLE:
        if __debug__:
            self._logger.debug(f"{packet_rx.tracker} - Received ICMPv4 Unreachable packet from {packet_rx.ip4.src}, will try to match UDP socket")

        # Quick and dirty way to validate received data and pull useful information from it
        frame = packet_rx.icmp4.un_data
        if (
            len(frame) >= ip4.ps.IP4_HEADER_LEN
            and frame[0] >> 4 == 4
            and len(frame) >= ((frame[0] & 0b00001111) << 2)
            and frame[9] == ip4.ps.IP4_PROTO_UDP
            and len(frame) >= ((frame[0] & 0b00001111) << 2) + udp.ps.UDP_HEADER_LEN
        ):
            # Create UdpMetadata object and try to find matching UDP socket
            udp_offset = (frame[0] & 0b00001111) << 2
            packet = UdpMetadata(
                local_ip_address=Ip4Address(frame[12:16]),
                remote_ip_address=Ip4Address(frame[16:20]),
                local_port=struct.unpack("!H", frame[udp_offset + 0 : udp_offset + 2])[0],
                remote_port=struct.unpack("!H", frame[udp_offset + 2 : udp_offset + 4])[0],
            )

            for socket_pattern in packet.socket_patterns:
                socket = stack.sockets.get(socket_pattern, None)
                if socket:
                    if __debug__:
                        self._logger.debug(f"{packet_rx.tracker} - Found matching listening socket {socket}")
                    socket.notify_unreachable()
                    return

            if __debug__:
                self._logger.debug(f"{packet_rx.tracker} - Unreachable data doesn't match any UDP socket")
            return

        if __debug__:
            self._logger.debug(f"{packet_rx.tracker} - Unreachable data doesn't pass basic IPv4/UDP integrity check")
        return
