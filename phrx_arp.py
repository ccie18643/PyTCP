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
#  Author'w email: ccie18643@gmail.com                                     #
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
# phrx_arp.py - packet handler for inbound ARP packets
#


import config
import fpp_arp
from ipv4_address import IPv4Address


def _phrx_arp(self, packet_rx):
    """Handle inbound ARP packets"""

    fpp_arp.ArpPacket(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.arp}")

    if packet_rx.arp.oper == fpp_arp.ARP_OP_REQUEST:
        # Check if request contains our IP address in SPA field, this indicates IP address conflict
        if packet_rx.arp.spa in self.ip4_unicast:
            if __debug__:
                self._logger.warning(f"IP ({packet_rx.arp.spa}) conflict detected with host at {packet_rx.arp.sha}")
            return

        # Check if the request is for one of our IP addresses, if so the craft ARP reply packet and send it out
        if packet_rx.arp.tpa in self.ip4_unicast:
            self._phtx_arp(
                ether_src=self.mac_unicast,
                ether_dst=packet_rx.arp.sha,
                arp_oper=fpp_arp.ARP_OP_REPLY,
                arp_sha=self.mac_unicast,
                arp_spa=packet_rx.arp.tpa,
                arp_tha=packet_rx.arp.sha,
                arp_tpa=packet_rx.arp.spa,
                echo_tracker=packet_rx.tracker,
            )

            # Update ARP cache with the mapping learned from the received ARP request that was destined to this stack
            if config.arp_cache_update_from_direct_request:
                if __debug__:
                    self._logger.debug(f"Adding/refreshing ARP cache entry from direct request - {packet_rx.arp.spa} -> {packet_rx.arp.sha}")
                self.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)

            return

    # Handle ARP reply
    elif packet_rx.arp.oper == fpp_arp.ARP_OP_REPLY:
        # Check for ARP reply that is response to our ARP probe, that indicates that IP address we trying to claim is in use
        if packet_rx.ether.dst == self.mac_unicast:
            if (
                packet_rx.arp.spa in [_.ip for _ in self.ip4_address_candidate]
                and packet_rx.arp.tha == self.mac_unicast
                and packet_rx.arp.tpa == IPv4Address("0.0.0.0")
            ):
                if __debug__:
                    self._logger.warning(f"ARP Probe detected conflict for IP {packet_rx.arp.spa} with host at {packet_rx.arp.sha}")
                self.arp_probe_unicast_conflict.add(packet_rx.arp.spa)
                return

        # Update ARP cache with mapping received as direct ARP reply
        if packet_rx.ether.dst == self.mac_unicast:
            if __debug__:
                self._logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {packet_rx.arp.spa} -> {packet_rx.arp.sha}")
            self.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return

        # Update ARP cache with mapping received as gratuitous ARP reply
        if packet_rx.ether.dst == "ff:ff:ff:ff:ff:ff" and packet_rx.arp.spa == packet_rx.arp.tpa and config.arp_cache_update_from_gratuitious_reply:
            if __debug__:
                self._logger.debug(f"Adding/refreshing ARP cache entry from gratuitous reply - {packet_rx.arp.spa} -> {packet_rx.arp.sha}")
            self.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return
