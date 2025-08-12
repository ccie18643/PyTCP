#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains class supporting ARP Cache operations.

pytcp/stack/arp_cache.py

ver 3.0.3
"""


from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import override

from net_addr import Ip4Address, MacAddress
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.subsystem import Subsystem


@dataclass
class CacheEntry:
    """
    Container class for cache entries.
    """

    mac_address: MacAddress
    permanent: bool = False
    create_time: int = field(
        init=False,
        default_factory=lambda: int(time.time()),
    )
    hit_count: int = 0


class ArpCache(Subsystem):
    """
    Support for ARP Cache operations.
    """

    _subsystem_name = "ARP Cache"

    _arp_cache: dict[Ip4Address, CacheEntry]
    _event__stop_subsystem: threading.Event

    def __init__(self) -> None:
        """
        Initialize ARP Cache.
        """

        super().__init__()

        self._arp_cache = {}

    def __repr__(self) -> str:
        """
        Return string representation of the ARP Cache.
        """

        return repr(self._arp_cache)

    @override
    def _subsystem_loop(self) -> None:
        """
        Maintain the ARP Cache entries.
        """

        for ip4_address in list(self._arp_cache):
            # Skip permanent entries
            if self._arp_cache[ip4_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if (
                int(time.time()) - self._arp_cache[ip4_address].create_time
                > stack.ARP__CACHE__ENTRY_MAX_AGE
            ):
                mac_address = self._arp_cache.pop(ip4_address).mac_address
                __debug__ and log(
                    "arp-c",
                    f"Discarded expir ARP Cache entry - {ip4_address} -> "
                    f"{mac_address}",
                )

            # If entry age is close to maximum age but the entry has been
            # used since last refresh then send out request in attempt
            # to refresh it.
            elif (
                int(time.time()) - self._arp_cache[ip4_address].create_time
                > stack.ARP__CACHE__ENTRY_MAX_AGE
                - stack.ARP__CACHE__ENTRY_REFRESH_TIME
            ) and self._arp_cache[ip4_address].hit_count:
                self._arp_cache[ip4_address].hit_count = 0
                stack.packet_handler.send_arp_request(arp__tpa=ip4_address)
                __debug__ and log(
                    "arp-c",
                    "Trying to refresh expiring ARP Cache entry for "
                    f"{ip4_address} -> "
                    f"{self._arp_cache[ip4_address].mac_address}",
                )

        # Put thread to sleep for a 100 milliseconds
        self._event__stop_subsystem.wait(0.1)

    def add_entry(
        self,
        *,
        ip4_address: Ip4Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Add / refresh entry in cache.
        """

        __debug__ and log(
            "arp-c",
            f"<INFO>Adding/refreshing ARP Cache entry - {ip4_address} -> "
            f"{mac_address}</>",
        )

        self._arp_cache[ip4_address] = CacheEntry(mac_address)

    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None:
        """
        Find entry in cache and return MAC address.
        """

        if arp_entry := self._arp_cache.get(ip4_address, None):
            arp_entry.hit_count += 1
            __debug__ and log(
                "arp-c",
                f"Found {ip4_address} -> {arp_entry.mac_address} entry, "
                f"age {int(time.time()) - arp_entry.create_time}s, "
                f"hit_count {arp_entry.hit_count}",
            )
            return arp_entry.mac_address

        __debug__ and log(
            "arp-c",
            f"Unable to find entry for {ip4_address}, sending ARP request",
        )
        stack.packet_handler.send_arp_request(arp__tpa=ip4_address)
        return None
