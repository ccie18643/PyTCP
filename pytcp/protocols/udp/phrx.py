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
Module contains packet handler for the inbound UDP packets.

pytcp/protocols/udp/phrx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp4.ps import ICMP4_UNREACHABLE, ICMP4_UNREACHABLE__PORT
from pytcp.protocols.icmp6.ps import ICMP6_UNREACHABLE, ICMP6_UNREACHABLE__PORT
from pytcp.protocols.udp.fpp import UdpParser
from pytcp.protocols.udp.metadata import UdpMetadata

if TYPE_CHECKING:
    from pytcp.subsystems.packet_handler import PacketHandler


def _phrx_udp(self: PacketHandler, packet_rx: PacketRx) -> None:
    """
    Handle inbound UDP packets.
    """

    self.packet_stats_rx.udp__pre_parse += 1

    UdpParser(packet_rx)

    if packet_rx.parse_failed:
        self.packet_stats_rx.udp__failed_parse__drop += 1
        __debug__ and log(
            "udp",
            f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
        )
        return

    __debug__ and log("udp", f"{packet_rx.tracker} - {packet_rx.udp}")

    assert isinstance(
        packet_rx.udp.data, memoryview
    )  # memoryview: data type check point

    # Create UdpMetadata object and try to find matching UDP socket
    packet_rx_md = UdpMetadata(
        local_ip_address=packet_rx.ip.dst,
        local_port=packet_rx.udp.dport,
        remote_ip_address=packet_rx.ip.src,
        remote_port=packet_rx.udp.sport,
        data=bytes(
            packet_rx.udp.data
        ),  # memoryview: conversion for end-user interface
        tracker=packet_rx.tracker,
    )

    for socket_pattern in packet_rx_md.socket_patterns:
        socket = stack.sockets.get(socket_pattern, None)
        if socket:
            self.packet_stats_rx.udp__socket_match += 1
            __debug__ and log(
                "udp",
                f"{packet_rx_md.tracker} - <INFO>Found matching listening "
                f"socket [{socket}]</>",
            )
            socket.process_udp_packet(packet_rx_md)
            return

    # Silently drop packet if it's source address is unspecified
    if packet_rx.ip.src.is_unspecified:
        self.packet_stats_rx.udp__ip_source_unspecified += 1
        __debug__ and log(
            "udp",
            f"{packet_rx_md.tracker} - Received UDP packet from "
            f"{packet_rx.ip.src}, port {packet_rx.udp.sport} to "
            f"{packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping",
        )
        return

    # Handle the UDP Echo operation in case its enabled
    # (used for packet flow unit testing only).
    if config.UDP_ECHO_NATIVE_DISABLE is False and packet_rx.udp.dport == 7:
        self.packet_stats_rx.udp__echo_native__respond_udp += 1
        __debug__ and log(
            "udp",
            f"{packet_rx_md.tracker} - <INFO>Performing native "
            "UDP Echo operation</>",
        )

        self._phtx_udp(
            ip_src=packet_rx.ip.dst,
            ip_dst=packet_rx.ip.src,
            udp_sport=packet_rx.udp.sport,
            udp_dport=packet_rx.udp.dport,
            udp_data=packet_rx.udp.data,
        )
        return

    # Respond with ICMP Port Unreachable message if no matching
    # socket has been found.
    __debug__ and log(
        "udp",
        f"{packet_rx_md.tracker} - Received UDP packet from "
        f"{packet_rx.ip.src} to closed port "
        f"{packet_rx.udp.dport}, sending ICMPv4 Port Unreachable",
    )

    if packet_rx.ip.ver == 6:
        self.packet_stats_rx.udp__no_socket_match__respond_icmp6_unreachable += (
            1
        )
        self._phtx_icmp6(
            ip6_src=packet_rx.ip6.dst,
            ip6_dst=packet_rx.ip6.src,
            icmp6_type=ICMP6_UNREACHABLE,
            icmp6_code=ICMP6_UNREACHABLE__PORT,
            icmp6_un_data=packet_rx.ip.packet_copy,
            echo_tracker=packet_rx.tracker,
        )

    if packet_rx.ip.ver == 4:
        self.packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable += (
            1
        )
        self._phtx_icmp4(
            ip4_src=packet_rx.ip4.dst,
            ip4_dst=packet_rx.ip4.src,
            icmp4_type=ICMP4_UNREACHABLE,
            icmp4_code=ICMP4_UNREACHABLE__PORT,
            icmp4_un_data=packet_rx.ip.packet_copy,
            echo_tracker=packet_rx.tracker,
        )

    return
