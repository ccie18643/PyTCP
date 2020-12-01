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
# icmp6_nd_cache.py - module contains class supporting ICMPv6 Neighbor Discovery cache
#


import time
from ipaddress import IPv6Address

import loguru

import ps_icmp6
import stack
from ip_helper import ip6_solicited_node_multicast

ND_ENTRY_MAX_AGE = 3600
ND_ENTRY_REFRESH_TIME = 300


class ICMPv6NdCache:
    """ Support for ICMPv6 ND cache operations """

    class CacheEntry:
        """ Container class fo cache entries """

        def __init__(self, mac_address, permanent=False):
            self.mac_address = mac_address
            self.permanent = permanent
            self.creation_time = time.time()
            self.hit_count = 0

    def __init__(self):
        """ Class constructor """

        stack.icmp6_nd_cache = self

        self.nd_cache = {}

        self.logger = loguru.logger.bind(object_name="icmp6_nd_cache.")

        # Setup timer to execute ND Cache maintainer every second
        stack.stack_timer.register_method(method=self.maintain_cache, delay=1000)

        self.logger.debug("Started ICMPv6 Neighbor Discovery cache")

    def maintain_cache(self):
        """ Method responsible for maintaining ND cache entries """

        for ip6_address in list(self.nd_cache):

            # Skip permanent entries
            if self.nd_cache[ip6_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if time.time() - self.nd_cache[ip6_address].creation_time > ND_ENTRY_MAX_AGE:
                mac_address = self.nd_cache.pop(ip6_address).mac_address
                self.logger.debug(f"Discarded expired ICMPv6 ND cache entry - {ip6_address} -> {mac_address}")

            # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
            elif (time.time() - self.nd_cache[ip6_address].creation_time > ND_ENTRY_MAX_AGE - ND_ENTRY_REFRESH_TIME) and self.nd_cache[ip6_address].hit_count:
                self.nd_cache[ip6_address].hit_count = 0
                self.__send_icmp6_neighbor_solicitation(ip6_address)
                self.logger.debug(f"Trying to refresh expiring ICMPv6 ND cache entry for {ip6_address} -> {self.nd_cache[ip6_address].mac_address}")

    def add_entry(self, ip6_address, mac_address):
        """ Add / refresh entry in cache """

        self.nd_cache[ip6_address] = self.CacheEntry(mac_address)

    def find_entry(self, ip6_address):
        """ Find entry in cache and return MAC address """

        if nd_entry := self.nd_cache.get(ip6_address, None):
            nd_entry.hit_count += 1
            self.logger.debug(
                f"Found {ip6_address} -> {nd_entry.mac_address} entry, age {time.time() - nd_entry.creation_time:.0f}s, hit_count {nd_entry.hit_count}"
            )
            return nd_entry.mac_address

        self.logger.debug(f"Unable to find entry for {ip6_address}, sending ICMPv6 Neighbor Solicitation message")
        self.__send_icmp6_neighbor_solicitation(ip6_address)
        return None

    @staticmethod
    def __send_icmp6_neighbor_solicitation(icmp6_ns_target_address):
        """ Enqueue ICMPv6 Neighbor Solicitation packet with TX ring """

        # Pick apropriate source address
        ip6_src = IPv6Address("::")
        for stack_ip6_address in stack.packet_handler.stack_ip6_address:
            if icmp6_ns_target_address in stack_ip6_address.network:
                ip6_src = stack_ip6_address.ip

        # Send out ND Solicitation message
        stack.packet_handler.phtx_icmp6(
            ip6_src=ip6_src,
            ip6_dst=ip6_solicited_node_multicast(icmp6_ns_target_address),
            ip6_hop=255,
            icmp6_type=ps_icmp6.ICMP6_NEIGHBOR_SOLICITATION,
            icmp6_ns_target_address=icmp6_ns_target_address,
            icmp6_nd_options=[ps_icmp6.Icmp6NdOptSLLA(opt_slla=stack.packet_handler.stack_mac_unicast[0])]
        )
