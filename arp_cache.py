#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ap_cache.py - module contains class supporting ARP cache

"""

import os
import loguru
import time
import asyncio


ARP_ENTRY_MAX_AGE = 60
ARP_ENTRY_REFRESH_TIME = 10


class ArpCache:
    """ Support for ARP cahe operations """

    def __init__(self):
        """ Class constructor """

        self.arp_cache = {}
        self.tx_ring = None
        self.logger = loguru.logger.bind(object_name="arp_cache.")

    def add_entry(self, ip_address, mac_address):
        """ Add / refresh entry in cache """

        self.arp_cache[ip_address] = [ip_address, mac_address, time.time(), 0]

    def get_mac_address(self, ip_address):
        """ Find entry in cache """

        if arp_entry := self.arp_cache.get(ip_address, None):
            arp_entry[3] += 1
            return arp_entry[1]

    async def handler(self):
        """ Maintain arp entries """
        
        while True:
            arp_cache_entries = self.arp_cache.values()
            for arp_entry in arp_cache_entries:

                # If entry age is over maximum age then discard the entry
                if time.time() - arp_entry[2] > ARP_ENTRY_MAX_AGE:
                    self.arp_cache.pop(arp_entry[0])
                    self.logger.debug(f"Discarded expired ARP cache entry - {arp_entry[0]} -> {arp_entry[1]}")

                # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
                elif (time.time() - arp_entry[2] > ARP_ENTRY_MAX_AGE - ARP_ENTRY_REFRESH_TIME) and arp_entry[3]:
                    arp_entry[3] = 0
                    self.tx_ring.enqueue_arp_request(arp_entry[0])
                    self.logger.debug(f"Trying to refresh expiring ARP cache entry for {arp_entry[0]} -> {arp_entry[1]}")
            
            await asyncio.sleep(1)
