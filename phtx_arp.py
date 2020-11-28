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
# phtx_arp.py - packet handler for outbound ARP packets
#


import ps_arp
import stack


def phtx_arp(self, ether_src, ether_dst, arp_oper, arp_sha, arp_spa, arp_tha, arp_tpa, echo_tracker=None):
    """ Handle outbound ARP packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not stack.ipv4_support:
        return

    arp_packet_tx = ps_arp.ArpPacket(
        arp_oper=arp_oper,
        arp_sha=arp_sha,
        arp_spa=arp_spa,
        arp_tha=arp_tha,
        arp_tpa=arp_tpa,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{arp_packet_tx.tracker}</magenta> - {arp_packet_tx}")

    self.phtx_ether(ether_src=ether_src, ether_dst=ether_dst, child_packet=arp_packet_tx)
