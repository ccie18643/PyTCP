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
#  Author'w email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# phrx_arp.py - packet handler for inbound ARP packets
#


from ipaddress import IPv4Address

import ps_arp
import stack

ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = True
ARP_CACHE_UPDATE_FROM_GRATUITOUS_REPLY = True


def phrx_arp(self, ether_packet_rx, arp_packet_rx):
    """ Handle inbound ARP packets """

    if arp_packet_rx.arp_oper == ps_arp.ARP_OP_REQUEST:
        self.logger.opt(ansi=True).info(f"<green>{arp_packet_rx.tracker}</green> - {arp_packet_rx}")

        # Check if request contains our IP address in SPA field, this indicates IP address conflict
        if arp_packet_rx.arp_spa in self.stack_ipv4_unicast:
            self.logger.warning(f"IP ({arp_packet_rx.arp_spa}) conflict detected with host at {arp_packet_rx.arp_sha}")
            return

        # Check if the request is for one of our IP addresses, if so the craft ARP reply packet and send it out
        if arp_packet_rx.arp_tpa in self.stack_ipv4_unicast:
            self.phtx_arp(
                ether_src=self.stack_mac_unicast[0],
                ether_dst=arp_packet_rx.arp_sha,
                arp_oper=ps_arp.ARP_OP_REPLY,
                arp_sha=self.stack_mac_unicast[0],
                arp_spa=arp_packet_rx.arp_tpa,
                arp_tha=arp_packet_rx.arp_sha,
                arp_tpa=arp_packet_rx.arp_spa,
                echo_tracker=arp_packet_rx.tracker,
            )

            # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
            if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                self.logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
                stack.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)

            return

    # Handle ARP reply
    elif arp_packet_rx.arp_oper == ps_arp.ARP_OP_REPLY:
        self.logger.opt(ansi=True).info(f"<green>{arp_packet_rx.tracker}</green> - {arp_packet_rx}")

        # Check for ARP reply that is response to our ARP probe, that indicates that IP address we trying to claim is in use
        if ether_packet_rx.ether_dst == self.stack_mac_unicast[0]:
            if (
                arp_packet_rx.arp_spa in [_.ip for _ in self.stack_ipv4_address_candidate]
                and arp_packet_rx.arp_tha == self.stack_mac_unicast[0]
                and arp_packet_rx.arp_tpa == IPv4Address("0.0.0.0")
            ):
                self.logger.warning(f"ARP Probe detected conflict for IP {arp_packet_rx.arp_spa} with host at {arp_packet_rx.arp_sha}")
                self.arp_probe_unicast_conflict.add(arp_packet_rx.arp_spa)
                return

        # Update ARP cache with maping received as direct ARP reply
        if ether_packet_rx.ether_dst == self.stack_mac_unicast[0]:
            self.logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
            stack.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)
            return

        # Update ARP cache with maping received as gratuitous ARP reply
        if ether_packet_rx.ether_dst == "ff:ff:ff:ff:ff:ff" and arp_packet_rx.arp_spa == arp_packet_rx.arp_tpa and ARP_CACHE_UPDATE_FROM_GRATUITOUS_REPLY:
            self.logger.debug(f"Adding/refreshing ARP cache entry from gratuitous reply - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
            stack.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)
            return
