#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# phrx_udp.py - packet handler for inbound UDP packets
#


import loguru

import ps_icmp4
import ps_icmp6
import stack
from ipv4_address import IPv4Address
from ipv6_address import IPv6Address
from udp_metadata import UdpMetadata


def phrx_udp(self, packet_rx):
    """ Handle inbound UDP packets """

    self.logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.udp}")

    # Create UdpMetadata object and try to find matching UDP socket
    packet = UdpMetadata(
        local_ip_address=packet_rx.ip.dst,
        local_port=packet_rx.udp.dport,
        remote_ip_address=packet_rx.ip.src,
        remote_port=packet_rx.udp.sport,
        raw_data=packet_rx.udp.data,
        tracker=packet_rx.tracker,
    )

    for socket_id in packet.socket_id_patterns:
        socket = stack.udp_sockets.get(socket_id, None)
        if socket:
            loguru.logger.bind(object_name="socket.").debug(f"{packet.tracker} - Found matching listening socket {socket_id}")
            socket.process_packet(packet)
            return

    # Silently drop packet if it has all zero source IP address
    if packet_rx.ip.src in {IPv4Address("0.0.0.0"), IPv6Address("::")}:
        self.logger.debug(
            f"Received UDP packet from {packet_rx.ip.src}, port {packet_rx.udp.sport} to {packet_rx.ip.dst}, port {packet_rx.udp.dport}, dropping..."
        )
        return

    # Respond with ICMPv4 Port Unreachable message if no matching socket has been found
    self.logger.debug(f"Received UDP packet from {packet_rx.ip.src} to closed port {packet_rx.udp.dport}, sending ICMPv4 Port Unreachable")

    if packet_rx.ip.ver == 6:
        self.phtx_icmp6(
            ip6_src=packet_rx.ip6.dst,
            ip6_dst=packet_rx.ip6.src,
            icmp6_type=ps_icmp6.ICMP6_UNREACHABLE,
            icmp6_code=ps_icmp6.ICMP6_UNREACHABLE__PORT,
            icmp6_un_raw_data=packet_rx.ip.packet,
            echo_tracker=packet_rx.tracker,
        )

    if packet_rx.ip.ver == 4:
        self.phtx_icmp4(
            ip4_src=packet_rx.ip.dst,
            ip4_dst=packet_rx.ip.src,
            icmp4_type=ps_icmp4.ICMP4_UNREACHABLE,
            icmp4_code=ps_icmp4.ICMP4_UNREACHABLE__PORT,
            icmp4_un_raw_data=packet_rx.ip.packet,
            echo_tracker=packet_rx.tracker,
        )

    return
