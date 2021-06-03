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
# arp_cache.py - module contains class supporting ARP cache
#


import time

import loguru

import fpa_arp
import stack
from ipv4_address import IPv4Address

ARP_ENTRY_MAX_AGE = 3600
ARP_ENTRY_REFRESH_TIME = 300


class ArpCache:
    """Support for ARP cache operations"""

    class CacheEntry:
        """Container class for cache entries"""

        def __init__(self, mac_address, permanent=False):
            self.mac_address = mac_address
            self.permanent = permanent
            self.creation_time = time.time()
            self.hit_count = 0

    def __init__(self, packet_handler):
        """Class constructor"""

        self.packet_handler = packet_handler

        self.arp_cache = {}

        if __debug__:
            self._logger = loguru.logger.bind(object_name="arp_cache.")

        # Setup timer to execute ARP Cache maintainer every second
        stack.timer.register_method(method=self._maintain_cache, delay=1000)

        if __debug__:
            self._logger.debug("Started ARP cache")

    def _maintain_cache(self):
        """Method responsible for maintaining ARP cache entries"""

        for ip4_address in list(self.arp_cache):

            # Skip permanent entries
            if self.arp_cache[ip4_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if time.time() - self.arp_cache[ip4_address].creation_time > ARP_ENTRY_MAX_AGE:
                mac_address = self.arp_cache.pop(ip4_address).mac_address
                if __debug__:
                    self._logger.debug(f"Discarded expired ARP cache entry - {ip4_address} -> {mac_address}")

            # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
            elif (time.time() - self.arp_cache[ip4_address].creation_time > ARP_ENTRY_MAX_AGE - ARP_ENTRY_REFRESH_TIME) and self.arp_cache[
                ip4_address
            ].hit_count:
                self.arp_cache[ip4_address].hit_count = 0
                self._send_arp_request(ip4_address)
                if __debug__:
                    self._logger.debug(f"Trying to refresh expiring ARP cache entry for {ip4_address} -> {self.arp_cache[ip4_address].mac_address}")

    def add_entry(self, ip4_address, mac_address):
        """Add / refresh entry in cache"""

        self.arp_cache[ip4_address] = self.CacheEntry(mac_address)

    def find_entry(self, ip4_address):
        """Find entry in cache and return MAC address"""

        if arp_entry := self.arp_cache.get(ip4_address, None):
            arp_entry.hit_count += 1
            if __debug__:
                self._logger.debug(
                    f"Found {ip4_address} -> {arp_entry.mac_address} entry, age {time.time() - arp_entry.creation_time:.0f}s, hit_count {arp_entry.hit_count}"
                )
            return arp_entry.mac_address

        if __debug__:
            self._logger.debug(f"Unable to find entry for {ip4_address}, sending ARP request")
        self._send_arp_request(ip4_address)
        return None

    def _send_arp_request(self, arp_tpa):
        """Enqueue ARP request packet with TX ring"""

        self.packet_handler._phtx_arp(
            ether_src=self.packet_handler.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=fpa_arp.ARP_OP_REQUEST,
            arp_sha=self.packet_handler.mac_unicast,
            arp_spa=self.packet_handler.ip4_unicast[0] if self.packet_handler.ip4_unicast else IPv4Address("0.0.0.0"),
            arp_tha="00:00:00:00:00:00",
            arp_tpa=arp_tpa,
        )
