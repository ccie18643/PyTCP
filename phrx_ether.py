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
# phrx_ether.py - packet handler for inbound Ethernet packets
#


import ps_arp
import ps_ether
import ps_ip4
import ps_ip6
import stack


def phrx_ether(self, ether_packet_rx):
    """ Handle inbound Ethernet packets """

    # Validate Ethernet packet sanity
    if ether_packet_rx.sanity_check_failed:
        self.logger.warning(f"{ether_packet_rx.tracker} - Ethernet packet sanity check failed, droping...")
        return

    self.logger.debug(f"{ether_packet_rx.tracker} - {ether_packet_rx}")

    # Check if received packet matches any of stack MAC addresses
    if ether_packet_rx.ether_dst not in {*self.stack_mac_unicast, *self.stack_mac_multicast, *self.stack_mac_broadcast}:
        self.logger.opt(ansi=True).debug(f"{ether_packet_rx.tracker} - Ethernet packet not destined for this stack, droping")
        return

    if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP and stack.ip4_support:
        self.phrx_arp(ether_packet_rx, ps_arp.ArpPacket(ether_packet_rx))
        return

    if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP4 and stack.ip4_support:
        self.phrx_ip4(ps_ip4.Ip4Packet(ether_packet_rx))
        return

    if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP6 and stack.ip6_support:
        self.phrx_ip6(ps_ip6.Ip6Packet(ether_packet_rx))
        return
