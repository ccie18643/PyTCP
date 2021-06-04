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


#
# arp/cache.py - module contains class supporting ARP cache
#


from __future__ import annotations  # Required by Python ver < 3.10

import time
from typing import Optional

import arp.ps
import config
import misc.stack as stack
from lib.ip4_address import Ip4Address
from lib.logger import log
from lib.mac_address import MacAddress


class ArpCache:
    """Support for ARP cache operations"""

    class CacheEntry:
        """Container class for cache entries"""

        def __init__(self, mac_address: MacAddress, permanent: bool = False) -> None:
            """Class constructor"""

            self.mac_address: MacAddress = mac_address
            self.permanent: bool = permanent
            self.creation_time: float = time.time()
            self.hit_count: int = 0

    def __init__(self) -> None:
        """Class constructor"""

        self.arp_cache: dict[Ip4Address, ArpCache.CacheEntry] = {}

        # Setup timer to execute ARP Cache maintainer every second
        stack.timer.register_method(method=self._maintain_cache, delay=1000)

        log("arp-c", "Started ARP cache")

    def _maintain_cache(self) -> None:
        """Method responsible for maintaining ARP cache entries"""

        for ip4_address in list(self.arp_cache):

            # Skip permanent entries
            if self.arp_cache[ip4_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if time.time() - self.arp_cache[ip4_address].creation_time > config.arp_cache_entry_max_age:
                mac_address = self.arp_cache.pop(ip4_address).mac_address
                log("arp-c", f"Discarded expir ARP cache entry - {ip4_address} -> {mac_address}")

            # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
            elif (
                time.time() - self.arp_cache[ip4_address].creation_time > config.arp_cache_entry_max_age - config.arp_cache_entry_refresh_time
            ) and self.arp_cache[ip4_address].hit_count:
                self.arp_cache[ip4_address].hit_count = 0
                self._send_arp_request(ip4_address)
                log("arp-c", f"Trying to refresh expiring ARP cache entry for {ip4_address} -> {self.arp_cache[ip4_address].mac_address}")

    def add_entry(self, ip4_address: Ip4Address, mac_address: MacAddress) -> None:
        """Add / refresh entry in cache"""

        log("arp-c", f"<INFO>Adding/refreshing ARP cache entry - {ip4_address} -> {mac_address}</>")
        self.arp_cache[ip4_address] = self.CacheEntry(mac_address)

    def find_entry(self, ip4_address: Ip4Address) -> Optional[MacAddress]:
        """Find entry in cache and return MAC address"""

        if arp_entry := self.arp_cache.get(ip4_address, None):
            arp_entry.hit_count += 1
            log(
                "arp-c",
                f"Found {ip4_address} -> {arp_entry.mac_address} entry, age "
                + f"{time.time() - arp_entry.creation_time:.0f}s, hit_count {arp_entry.hit_count}",
            )
            return arp_entry.mac_address

        log("arp-c", f"Unable to find entry for {ip4_address}, sending ARP request")
        self._send_arp_request(ip4_address)
        return None

    def _send_arp_request(self, arp_tpa: Ip4Address) -> None:
        """Enqueue ARP request packet with TX ring"""

        stack.packet_handler._phtx_arp(
            ether_src=stack.packet_handler.mac_unicast,
            ether_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            arp_oper=arp.ps.ARP_OP_REQUEST,
            arp_sha=stack.packet_handler.mac_unicast,
            arp_spa=stack.packet_handler.ip4_unicast[0] if stack.packet_handler.ip4_unicast else Ip4Address("0.0.0.0"),
            arp_tha=MacAddress("00:00:00:00:00:00"),
            arp_tpa=arp_tpa,
        )
