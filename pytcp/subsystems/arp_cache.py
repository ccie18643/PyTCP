#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = too-few-public-methods
# pylint: disable = expression-not-assigned
# pylint: disable = protected-access

"""
Module contains class supporting ARP cache operations.

pytcp/protocols/arp/cache.py

ver 2.7
"""


from __future__ import annotations

import threading
import time

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.arp.ps import ARP_OP_REQUEST


class ArpCache:
    """
    Support for ARP cache operations.
    """

    class CacheEntry:
        """
        Container class for cache entries.
        """

        def __init__(
            self, mac_address: MacAddress, permanent: bool = False
        ) -> None:
            """
            Class constructor.
            """
            self.mac_address: MacAddress = mac_address
            self.permanent: bool = permanent
            self.creation_time: float = time.time()
            self.hit_count: int = 0

    def __init__(self) -> None:
        """
        Class constructor.
        """
        self._arp_cache: dict[Ip4Address, ArpCache.CacheEntry] = {}
        self._run_thread: bool = False

    def start(self) -> None:
        """
        Start ARP cache thread.
        """
        __debug__ and log("stack", "Starting ARP cache")
        self._run_thread = True
        threading.Thread(target=self.__thread_maintain_cache).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop ARP cache thread.
        """
        __debug__ and log("stack", "Stopping ARP cache")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_maintain_cache(self) -> None:
        """
        Thread responsible for maintaining ARP cache entries.
        """

        __debug__ and log("stack", "Started ARP cache")

        while self._run_thread:
            for ip4_address in list(self._arp_cache):
                # Skip permanent entries
                if self._arp_cache[ip4_address].permanent:
                    continue

                # If entry age is over maximum age then discard the entry
                if (
                    time.time() - self._arp_cache[ip4_address].creation_time
                    > config.ARP_CACHE_ENTRY_MAX_AGE
                ):
                    mac_address = self._arp_cache.pop(ip4_address).mac_address
                    __debug__ and log(
                        "arp-c",
                        f"Discarded expir ARP cache entry - {ip4_address} -> "
                        f"{mac_address}",
                    )

                # If entry age is close to maximum age but the entry has been
                # used since last refresh then send out request in attempt
                # to refresh it.
                elif (
                    time.time() - self._arp_cache[ip4_address].creation_time
                    > config.ARP_CACHE_ENTRY_MAX_AGE
                    - config.ARP_CACHE_ENTRY_REFRESH_TIME
                ) and self._arp_cache[ip4_address].hit_count:
                    self._arp_cache[ip4_address].hit_count = 0
                    self._send_arp_request(ip4_address)
                    __debug__ and log(
                        "arp-c",
                        "Trying to refresh expiring ARP cache entry for "
                        f"{ip4_address} -> "
                        f"{self._arp_cache[ip4_address].mac_address}",
                    )

            # Put thread to sleep for a 10 milliseconds
            time.sleep(0.1)

        __debug__ and log("stack", "Stopped ARP cache")

    def add_entry(
        self, ip4_address: Ip4Address, mac_address: MacAddress
    ) -> None:
        """
        Add / refresh entry in cache.
        """
        __debug__ and log(
            "arp-c",
            f"<INFO>Adding/refreshing ARP cache entry - {ip4_address} -> "
            f"{mac_address}</>",
        )
        self._arp_cache[ip4_address] = self.CacheEntry(mac_address)

    def find_entry(self, ip4_address: Ip4Address) -> MacAddress | None:
        """
        Find entry in cache and return MAC address.
        """

        if arp_entry := self._arp_cache.get(ip4_address, None):
            arp_entry.hit_count += 1
            __debug__ and log(
                "arp-c",
                f"Found {ip4_address} -> {arp_entry.mac_address} entry, "
                f"age {time.time() - arp_entry.creation_time:.0f}s, "
                f"hit_count {arp_entry.hit_count}",
            )
            return arp_entry.mac_address

        __debug__ and log(
            "arp-c",
            f"Unable to find entry for {ip4_address}, sending ARP request",
        )
        self._send_arp_request(ip4_address)
        return None

    def _send_arp_request(self, arp_tpa: Ip4Address) -> None:
        """Enqueue ARP request packet with TX ring."""
        stack.packet_handler._phtx_arp(
            ether_src=stack.packet_handler.mac_unicast,
            ether_dst=MacAddress(0xFFFFFFFFFFFF),
            arp_oper=ARP_OP_REQUEST,
            arp_sha=stack.packet_handler.mac_unicast,
            arp_spa=(
                stack.packet_handler.ip4_unicast[0]
                if stack.packet_handler.ip4_unicast
                else Ip4Address(0)
            ),
            arp_tha=MacAddress(0),
            arp_tpa=arp_tpa,
        )
