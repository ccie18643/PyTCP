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
# phtx_ether.py - packet handler for outbound Ethernet packets
#


from ipaddress import IPv4Address

import ps_ether
import ps_ipv4
import ps_ipv6
import stack
from ipv6_helper import ipv6_multicast_mac


def phtx_ether(self, child_packet, ether_src="00:00:00:00:00:00", ether_dst="00:00:00:00:00:00"):
    """ Handle outbound Ethernet packets """

    def __send_out_packet():
        self.logger.opt(depth=1).debug(f"{ether_packet_tx.tracker} - {ether_packet_tx}")
        stack.tx_ring.enqueue(ether_packet_tx, urgent=(child_packet.protocol == "ARP"))

    ether_packet_tx = ps_ether.EtherPacket(ether_src=ether_src, ether_dst=ether_dst, child_packet=child_packet)

    # Check if packet contains valid source address, fill it out if needed
    if ether_packet_tx.ether_src == "00:00:00:00:00:00":
        ether_packet_tx.ether_src = self.stack_mac_unicast[0]
        self.logger.debug(f"{ether_packet_tx.tracker} - Set source to stack MAC {ether_packet_tx.ether_src}")

    # Send out packet if it contains valid destination MAC address
    if ether_packet_tx.ether_dst != "00:00:00:00:00:00":
        self.logger.debug(f"{ether_packet_tx.tracker} - Contains valid destination MAC address")
        __send_out_packet()
        return

    # Check if we can obtain destination MAC based on IPv6 header data
    if ether_packet_tx.ether_type == ps_ether.ETHER_TYPE_IP6:
        ipv6_packet_tx = ps_ipv6.Ip6Packet(ether_packet_tx)

        # Send packet out if its destined to multicast IPv6 address
        if ipv6_packet_tx.ipv6_dst.is_multicast:
            ether_packet_tx.ether_dst = ipv6_multicast_mac(ipv6_packet_tx.ipv6_dst)
            self.logger.debug(f"{ether_packet_tx.tracker} - Resolved destiantion IPv6 {ipv6_packet_tx.ipv6_dst} to MAC {ether_packet_tx.ether_dst}")
            __send_out_packet()
            return

        # Send out packet if we are able to obtain destinaton MAC from ICMPv6 ND cache
        if mac_address := stack.icmpv6_nd_cache.find_entry(ipv6_packet_tx.ipv6_dst):
            ether_packet_tx.ether_dst = mac_address
            self.logger.debug(f"{ether_packet_tx.tracker} - Resolved destiantion IPv6 {ipv6_packet_tx.ipv6_dst} to MAC {ether_packet_tx.ether_dst}")
            __send_out_packet()
            return

    # Check if we can obtain destination MAC based on IPv4 header data
    if ether_packet_tx.ether_type == ps_ether.ETHER_TYPE_IP4:
        ipv4_packet_tx = ps_ipv4.Ip4Packet(ether_packet_tx)

        # Send out packet if its destinied to limited broadcast addresses
        if ipv4_packet_tx.ipv4_dst == IPv4Address("255.255.255.255"):
            ether_packet_tx.ether_dst = "ff:ff:ff:ff:ff:ff"
            self.logger.debug(f"{ether_packet_tx.tracker} - Resolved destiantion IPv4 {ipv4_packet_tx.ipv4_dst} to MAC {ether_packet_tx.ether_dst}")
            __send_out_packet()
            return

        # Send out packet if its destinied to directed broadcast or network addresses (in relation to its source IPv4)
        for stack_ipv4_address in self.stack_ipv4_address:
            if stack_ipv4_address.ip == ipv4_packet_tx.ipv4_src:
                if ipv4_packet_tx.ipv4_dst in {stack_ipv4_address.network[0], stack_ipv4_address.network[-1]}:
                    ether_packet_tx.ether_dst = "ff:ff:ff:ff:ff:ff"
                    self.logger.debug(f"{ether_packet_tx.tracker} - Resolved destiantion IPv4 {ipv4_packet_tx.ipv4_dst} to MAC {ether_packet_tx.ether_dst}")
                    __send_out_packet()
                    return

        # Send out packet if is destined to external network (in relation to its source IPv4) and we are able to obtain MAC of default gateway from ARP cache
        for stack_ipv4_address in self.stack_ipv4_address:
            if stack_ipv4_address.ip == ipv4_packet_tx.ipv4_src:
                if ipv4_packet_tx.ipv4_dst not in stack_ipv4_address.network:
                    if stack_ipv4_address.gateway is None:
                        self.logger.debug(f"{ether_packet_tx.tracker} - No default gateway set for {stack_ipv4_address} source address, droping packet...")
                        return
                    if mac_address := stack.arp_cache.find_entry(stack_ipv4_address.gateway):
                        ether_packet_tx.ether_dst = mac_address
                        self.logger.debug(
                            f"{ether_packet_tx.tracker} - Resolved destiantion IPv4 {ipv4_packet_tx.ipv4_dst}"
                            + f" to Default Gateway MAC {ether_packet_tx.ether_dst}"
                        )
                        __send_out_packet()
                        return

        # Send out packet if we are able to obtain destinaton MAC from ARP cache
        if mac_address := stack.arp_cache.find_entry(ipv4_packet_tx.ipv4_dst):
            ether_packet_tx.ether_dst = mac_address
            self.logger.debug(f"{ether_packet_tx.tracker} - Resolved destiantion IPv4 {ipv4_packet_tx.ipv4_dst} to MAC {ether_packet_tx.ether_dst}")
            __send_out_packet()
            return

    # Drop packet in case  we are not able to obtain valid destination MAC address
    self.logger.debug(f"{ether_packet_tx.tracker} - No valid destination MAC could be obtainedi, droping packet...")
    return
