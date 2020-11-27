#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
icmpv6_nd_cache.py - module contains class supporting ICMPv6 Neighbor Discovery cache

"""

import loguru
import time

from ipaddress import IPv6Address

import ps_icmpv6
import stack

from ipv6_helper import ipv6_solicited_node_multicast


ND_ENTRY_MAX_AGE = 3600
ND_ENTRY_REFRESH_TIME = 300


class ICMPv6NdCache:
    """ Support for ICMPv6 ND cache operations """

    class __Entry:
        def __init__(self, mac_address, permanent=False):
            self.mac_address = mac_address
            self.permanent = permanent
            self.creation_time = time.time()
            self.hit_count = 0

    def __init__(self):
        """ Class constructor """

        self.nd_cache = {}

        self.logger = loguru.logger.bind(object_name="icmpv6_nd_cache.")

        # Setup timer to execute ND Cache maintainer every second
        stack.stack_timer.register_method(method=self.maintain_cache, delay=1000)

        self.logger.debug("Started ICMPv6 Neighbor Discovery cache")

    def maintain_cache(self):
        """ Method responsible for maintaining ND cache entries """

        for ipv6_address in list(self.nd_cache):

            # Skip permanent entries
            if self.nd_cache[ipv6_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry
            if time.time() - self.nd_cache[ipv6_address].creation_time > ND_ENTRY_MAX_AGE:
                mac_address = self.nd_cache.pop(ipv6_address).mac_address
                self.logger.debug(f"Discarded expired ICMPv6 ND cache entry - {ipv6_address} -> {mac_address}")

            # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
            elif (time.time() - self.nd_cache[ipv6_address].creation_time > ND_ENTRY_MAX_AGE - ND_ENTRY_REFRESH_TIME) and self.nd_cache[ipv6_address].hit_count:
                self.nd_cache[ipv6_address].hit_count = 0
                self.__send_icmpv6_neighbor_solicitation(ipv6_address)
                self.logger.debug(f"Trying to refresh expiring ICMPv6 ND cache entry for {ipv6_address} -> {self.nd_cache[ipv6_address].mac_address}")

    def __send_icmpv6_neighbor_solicitation(self, icmpv6_ns_target_address):
        """ Enqueue ICMPv6 Neighbor Solicitation packet with TX ring """

        stack.packet_handler.phtx_icmpv6(
            ipv6_src=IPv6Address("::"),
            ipv6_dst=ipv6_solicited_node_multicast(icmpv6_nd_target_address),
            ipv6_hop=255,
            icmpv6_type=ps_icmpv6.ICMPV6_NEIGHBOR_SOLICITATION,
            icmpv6_ns_target_address=icmpv6_ns_target_address,
        )

    def add_entry(self, ipv6_address, mac_address):
        """ Add / refresh entry in cache """

        self.nd_cache[ipv6_address] = self.__Entry(mac_address)

    def find_entry(self, ipv6_address):
        """ Find entry in cache and return MAC address """

        if nd_entry := self.nd_cache.get(ipv6_address, None):
            nd_entry.hit_count += 1
            self.logger.debug(
                f"Found {ipv6_address} -> {nd_entry.mac_address} entry, age {time.time() - nd_entry.creation_time:.0f}s, hit_count {nd_entry.hit_count}"
            )
            return nd_entry.mac_address

        else:
            self.logger.debug(f"Unable to find entry for {ipv6_address}, sending ICMPv6 Neighbor Solicitation message")
            self.__send_icmpv6_neighbor_solicitation(ipv6_address)
