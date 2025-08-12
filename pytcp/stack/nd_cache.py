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
Module contains class supporting ICMPv6 Neighbor Discovery cache operations.

pycp/stack/nd_cache.py

ver 3.0.2
"""


from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import override

from net_addr import Ip6Address, MacAddress
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


class NdCache(Subsystem):
    """
    Support for ICMPv6 ND Cache operations.
    """

    _subsystem_name = "ICMPv6 ND Cache"

    _nd_cache: dict[Ip6Address, CacheEntry]
    _event__stop_subsystem: threading.Event

    def __init__(self) -> None:
        """
        Initialize IPv6 ND Cache.
        """

        super().__init__()

        self._nd_cache = {}

    def __repr__(self) -> str:
        """
        Return string representation of the ARP Cache.
        """

        return repr(self._nd_cache)

    @override
    def _subsystem_loop(self) -> None:
        """
        Maintain IPv6 ND Cache entries.
        """

        for ip6_address in list(self._nd_cache):
            # Skip permanent entries
            if self._nd_cache[ip6_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if (
                int(time.time()) - self._nd_cache[ip6_address].create_time
                > stack.ICMP6__ND__CACHE__ENTRY_MAX_AGE
            ):
                mac_address = self._nd_cache.pop(ip6_address).mac_address
                __debug__ and log(
                    "nd-c",
                    "Discarded expir ICMPv6 ND Cache entry - "
                    f"{ip6_address} -> {mac_address}",
                )

            # If entry age is close to maximum age but the entry has been
            # used since last refresh then send out request in attempt
            # to refresh it.
            elif (
                int(time.time()) - self._nd_cache[ip6_address].create_time
                > stack.ICMP6__ND__CACHE__ENTRY_MAX_AGE
                - stack.ICMP6__ND__CACHE__ENTRY_REFRESH_TIME
            ) and self._nd_cache[ip6_address].hit_count:
                self._nd_cache[ip6_address].hit_count = 0
                stack.packet_handler.send_icmp6_neighbor_solicitation(
                    icmp6_ns_target_address=ip6_address
                )
                __debug__ and log(
                    "nd-c",
                    f"Trying to refresh expiring ICMPv6 ND Cache entry for "
                    f"{ip6_address} -> "
                    f"{self._nd_cache[ip6_address].mac_address}",
                )

        # Put thread to sleep for a 100 milliseconds
        self._event__stop_subsystem.wait(0.1)

    def add_entry(
        self,
        *,
        ip6_address: Ip6Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Add / refresh entry in cache.
        """

        __debug__ and log(
            "nd-c",
            f"<INFO>Adding/refreshing ARP cache entry from direct reply - "
            f"{ip6_address} -> {mac_address}</>",
        )

        self._nd_cache[ip6_address] = CacheEntry(mac_address)

    def find_entry(self, *, ip6_address: Ip6Address) -> MacAddress | None:
        """
        Find entry in cache and return MAC address.
        """

        if nd_entry := self._nd_cache.get(ip6_address, None):
            nd_entry.hit_count += 1
            __debug__ and log(
                "nd-c",
                f"Found {ip6_address} -> {nd_entry.mac_address} entry, "
                f"age {int(time.time()) - nd_entry.create_time}s, "
                f"hit_count {nd_entry.hit_count}",
            )
            return nd_entry.mac_address

        __debug__ and log(
            "nd-c",
            f"Unable to find entry for {ip6_address}, sending ICMPv6 "
            "Neighbor Solicitation message",
        )
        stack.packet_handler.send_icmp6_neighbor_solicitation(
            icmp6_ns_target_address=ip6_address
        )

        return None
