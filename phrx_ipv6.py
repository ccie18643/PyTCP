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


#
# phrx_ipv6.py - packet handler for inbound IPv6 packets
#


import ps_icmpv6
import ps_ipv6
import ps_tcp
import ps_udp


def phrx_ipv6(self, ipv6_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ipv6_packet_rx.tracker} - {ipv6_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast or multicast
    if ipv6_packet_rx.ipv6_dst not in {*self.stack_ipv6_unicast, *self.stack_ipv6_multicast}:
        self.logger.debug(f"{ipv6_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    if ipv6_packet_rx.ipv6_next == ps_ipv6.IPV6_NEXT_HEADER_ICMPV6:
        self.phrx_icmpv6(ipv6_packet_rx, ps_icmpv6.ICMPv6Packet(ipv6_packet_rx))
        return

    if ipv6_packet_rx.ipv6_next == ps_ipv6.IPV6_NEXT_HEADER_UDP:
        self.phrx_udp(ipv6_packet_rx, ps_udp.UdpPacket(ipv6_packet_rx))
        return

    if ipv6_packet_rx.ipv6_next == ps_ipv6.IPV6_NEXT_HEADER_TCP:
        self.phrx_tcp(ipv6_packet_rx, ps_tcp.TcpPacket(ipv6_packet_rx))
        return
