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
Module contains packet handler for the inbound ICMPv4 packets.

pytcp/protocols/icmp4/phrx.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.logger import log
from pytcp.protocols.icmp4.fpp import Icmp4Parser
from pytcp.protocols.icmp4.ps import (
    ICMP4_ECHO_REPLY,
    ICMP4_ECHO_REQUEST,
    ICMP4_UNREACHABLE,
)
from pytcp.protocols.ip4.ps import IP4_HEADER_LEN, IP4_PROTO_UDP
from pytcp.protocols.udp.metadata import UdpMetadata
from pytcp.protocols.udp.ps import UDP_HEADER_LEN

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx
    from pytcp.subsystems.packet_handler import PacketHandler


def _phrx_icmp4(self: PacketHandler, packet_rx: PacketRx) -> None:
    """Handle inbound ICMPv4 packets"""

    self.packet_stats_rx.icmp4__pre_parse += 1

    Icmp4Parser(packet_rx)

    if packet_rx.parse_failed:
        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
        )
        self.packet_stats_rx.icmp4__failed_parse__drop += 1
        return

    __debug__ and log("icmp4", f"{packet_rx.tracker} - {packet_rx.icmp4}")

    # ICMPv4 Echo Request packet
    if packet_rx.icmp4.type == ICMP4_ECHO_REQUEST:
        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Received ICMPv4 Echo Request "
            f"packet from {packet_rx.ip4.src}, sending reply</>",
        )
        self.packet_stats_rx.icmp4__echo_request__respond_echo_reply += 1

        self._phtx_icmp4(
            ip4_src=packet_rx.ip4.dst,
            ip4_dst=packet_rx.ip4.src,
            icmp4_type=ICMP4_ECHO_REPLY,
            icmp4_ec_id=packet_rx.icmp4.ec_id,
            icmp4_ec_seq=packet_rx.icmp4.ec_seq,
            icmp4_ec_data=packet_rx.icmp4.ec_data,
            echo_tracker=packet_rx.tracker,
        )
        return

    # ICMPv4 Unreachable packet
    if packet_rx.icmp4.type == ICMP4_UNREACHABLE:
        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Unreachable packet "
            f"from {packet_rx.ip4.src}, will try to match UDP socket",
        )
        self.packet_stats_rx.icmp4__unreachable += 1

        # Quick and dirty way to validate received data and pull useful
        # information from it
        frame = packet_rx.icmp4.un_data
        if (
            len(frame) >= IP4_HEADER_LEN
            and frame[0] >> 4 == 4
            and len(frame) >= ((frame[0] & 0b00001111) << 2)
            and frame[9] == IP4_PROTO_UDP
            and len(frame) >= ((frame[0] & 0b00001111) << 2) + UDP_HEADER_LEN
        ):
            # Create UdpMetadata object and try to find matching UDP socket
            udp_offset = (frame[0] & 0b00001111) << 2
            packet = UdpMetadata(
                local_ip_address=Ip4Address(frame[12:16]),
                remote_ip_address=Ip4Address(frame[16:20]),
                local_port=struct.unpack(
                    "!H", frame[udp_offset + 0 : udp_offset + 2]
                )[0],
                remote_port=struct.unpack(
                    "!H", frame[udp_offset + 2 : udp_offset + 4]
                )[0],
            )

            for socket_pattern in packet.socket_patterns:
                socket = stack.sockets.get(socket_pattern, None)
                if socket:
                    __debug__ and log(
                        "icmp4",
                        f"{packet_rx.tracker} - <INFO>Found matching "
                        f"listening socket {socket}, for Unreachable "
                        f"packet from {packet_rx.ip4.src}</>",
                    )
                    socket.notify_unreachable()
                    return

            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Unreachable data doesn't match "
                "any UDP socket",
            )
            return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Unreachable data doesn't pass basic "
            "IPv4/UDP integrity check",
        )
        return
