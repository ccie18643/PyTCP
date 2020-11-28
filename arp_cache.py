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
# arp_cache.py - module contains class supporting ARP cache
#


import loguru
import time

import ps_arp
import stack


ARP_ENTRY_MAX_AGE = 3600
ARP_ENTRY_REFRESH_TIME = 300


class ArpCache:
    """ Support for ARP cache operations """

    class __Entry:
        def __init__(self, mac_address, permanent=False):
            self.mac_address = mac_address
            self.permanent = permanent
            self.creation_time = time.time()
            self.hit_count = 0

    def __init__(self):
        """ Class constructor """

        self.arp_cache = {}

        self.logger = loguru.logger.bind(object_name="arp_cache.")

        # Setup timer to execute ARP Cache maintainer every second
        stack.stack_timer.register_method(method=self.maintain_cache, delay=1000)

        self.logger.debug("Started ARP cache")

    def maintain_cache(self):
        """ Method responsible for maintaining ARP cache entries """

        for ipv4_address in list(self.arp_cache):

            # Skip permanent entries
            if self.arp_cache[ipv4_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if time.time() - self.arp_cache[ipv4_address].creation_time > ARP_ENTRY_MAX_AGE:
                mac_address = self.arp_cache.pop(ipv4_address).mac_address
                self.logger.debug(f"Discarded expired ARP cache entry - {ipv4_address} -> {mac_address}")

            # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
            elif (time.time() - self.arp_cache[ipv4_address].creation_time > ARP_ENTRY_MAX_AGE - ARP_ENTRY_REFRESH_TIME) and self.arp_cache[
                ipv4_address
            ].hit_count:
                self.arp_cache[ipv4_address].hit_count = 0
                self.__send_arp_request(ipv4_address)
                self.logger.debug(f"Trying to refresh expiring ARP cache entry for {ipv4_address} -> {self.arp_cache[ipv4_address].mac_address}")

    def __send_arp_request(self, arp_tpa):
        """ Enqueue ARP request packet with TX ring """

        stack.packet_handler.phtx_arp(
            ether_src=stack.packet_handler.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=stack.packet_handler.stack_mac_unicast[0],
            arp_spa=stack.packet_handler.stack_ipv4_unicast[0] if stack.packet_handler.stack_ipv4_unicast else "0.0.0.0",
            arp_tha="00:00:00:00:00:00",
            arp_tpa=arp_tpa,
        )

    def add_entry(self, ipv4_address, mac_address):
        """ Add / refresh entry in cache """

        self.arp_cache[ipv4_address] = self.__Entry(mac_address)

    def find_entry(self, ipv4_address):
        """ Find entry in cache and return MAC address """

        if arp_entry := self.arp_cache.get(ipv4_address, None):
            arp_entry.hit_count += 1
            self.logger.debug(
                f"Found {ipv4_address} -> {arp_entry.mac_address} entry, age {time.time() - arp_entry.creation_time:.0f}s, hit_count {arp_entry.hit_count}"
            )
            return arp_entry.mac_address

        else:
            self.logger.debug(f"Unable to find entry for {ipv4_address}, sending ARP request")
            self.__send_arp_request(ipv4_address)
