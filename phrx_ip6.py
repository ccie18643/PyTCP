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
# phrx_ip6.py - packet handler for inbound IPv6 packets
#


import ps_icmp6
import ps_ip6
import ps_tcp
import ps_udp


def phrx_ip6(self, ip6_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ip6_packet_rx.tracker} - {ip6_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast or multicast
    if ip6_packet_rx.ip6_dst not in {*self.stack_ip6_unicast, *self.stack_ip6_multicast}:
        self.logger.debug(f"{ip6_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    if ip6_packet_rx.ip6_next == ps_ip6.IP6_NEXT_HEADER_ICMP6 and ps_icmp6.preliminary_sanity_check(
        ip6_packet_rx.raw_data, ip6_packet_rx.ip_pseudo_header, self.logger
    ):
        self.phrx_icmp6(ip6_packet_rx, ps_icmp6.Icmp6Packet(ip6_packet_rx))
        return

    if ip6_packet_rx.ip6_next == ps_ip6.IP6_NEXT_HEADER_UDP and ps_udp.preliminary_sanity_check(
        ip6_packet_rx.raw_data, ip6_packet_rx.ip_pseudo_header, self.logger
    ):
        self.phrx_udp(ip6_packet_rx, ps_udp.UdpPacket(ip6_packet_rx))
        return

    if ip6_packet_rx.ip6_next == ps_ip6.IP6_NEXT_HEADER_TCP and ps_tcp.preliminary_sanity_check(
        ip6_packet_rx.raw_data, ip6_packet_rx.ip_pseudo_header, self.logger
    ):
        self.phrx_tcp(ip6_packet_rx, ps_tcp.TcpPacket(ip6_packet_rx))
        return
