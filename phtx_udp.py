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
# phtx_udp.py - protocol support for outbound UDP packets
#


from ipaddress import IPv4Address, IPv6Address

import ps_udp
import stack


def phtx_udp(self, ip_src, ip_dst, udp_sport, udp_dport, raw_data=b"", echo_tracker=None):
    """ Handle outbound UDP packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the IPv4 packet
    if not stack.ipv4_support and ip_dst.version == 4:
        return

    # Check if IPv6 protocol support is enabled, if not then silently drop the IPv6 packet
    if not stack.ipv6_support and ip_dst.version == 6:
        return

    udp_packet_tx = ps_udp.UdpPacket(udp_sport=udp_sport, udp_dport=udp_dport, raw_data=raw_data, echo_tracker=echo_tracker)

    self.logger.opt(ansi=True).info(f"<magenta>{udp_packet_tx.tracker}</magenta> - {udp_packet_tx}")

    assert type(ip_src) in {IPv4Address, IPv6Address}
    assert type(ip_dst) in {IPv4Address, IPv6Address}

    if ip_src.version == 6 and ip_dst.version == 6:
        self.phtx_ipv6(ipv6_src=ip_src, ipv6_dst=ip_dst, child_packet=udp_packet_tx)

    if ip_src.version == 4 and ip_dst.version == 4:
        self.phtx_ipv4(ipv4_src=ip_src, ipv4_dst=ip_dst, child_packet=udp_packet_tx)
