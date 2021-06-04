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

import icmp4.ps
import icmp6.ps
import misc.stack as stack
from lib.logger import log
from misc.packet import PacketRx
from udp.fpp import UdpParser
from udp.metadata import UdpMetadata


def _phrx_udp(self, packet_rx: PacketRx) -> None:
    """Handle inbound UDP packets"""

    UdpParser(packet_rx)

    if packet_rx.parse_failed:
        log("udp", f"{self.tracker} - <CRIT>{packet_rx.parse_failed}</>")
        return

    log("udp", f"{packet_rx.tracker} - {packet_rx.udp}")

    assert isinstance(packet_rx.udp.data, memoryview)  # memoryview: data type check point

    # Create UdpMetadata object and try to find matching UDP socket
    packet_rx_md = UdpMetadata(
        local_ip_address=packet_rx.ip.dst,
        local_port=packet_rx.udp.dport,
        remote_ip_address=packet_rx.ip.src,
        remote_port=packet_rx.udp.sport,
        data=bytes(packet_rx.udp.data),  # memoryview: conversion for end-user interface
        tracker=packet_rx.tracker,
    )

    for socket_pattern in packet_rx_md.socket_patterns:
        socket = stack.sockets.get(socket_pattern, None)
        if socket:
            log("udp", f"{packet_rx_md.tracker} - <INFO>Found matching listening socket [{socket}]</>")
            socket.process_udp_packet(packet_rx_md)
            return

    # Silently drop packet if it's source address is unspecified
    if packet_rx.ip.src.is_unspecified:
        log(
            "udp",
            f"{packet_rx_md.tracker} - Received UDP packet from {packet_rx.ip.src}, port {packet_rx.udp.sport} to "
            + f"{packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping",
        )
        return

    # Respond with ICMP Port Unreachable message if no matching socket has been found
    log(
        "udp",
        f"{packet_rx_md.tracker} - Received UDP packet from {packet_rx.ip.src} to closed port " + f"{packet_rx.udp.dport}, sending ICMPv4 Port Unreachable",
    )

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
