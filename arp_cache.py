#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
arp_cache.py - module contains class supporting ARP cache

"""

import loguru
import time
import threading

import ps_arp
import stack


ARP_ENTRY_MAX_AGE = 3600
ARP_ENTRY_REFRESH_TIME = 300


class ArpCache:
    """ Support for ARP cahe operations """

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

        threading.Thread(target=self.__thread_maintain_cache).start()
        self.logger.debug("Started ARP cache")

    def __thread_maintain_cache(self):
        """ Thread responsible for maintaining ARP entries """

        while True:
            for ip_address in list(self.arp_cache):

                # Skip permanent entries
                if self.arp_cache[ip_address].permanent:
                    continue

                # If entry age is over maximum age then discard the entry
                if time.time() - self.arp_cache[ip_address].creation_time > ARP_ENTRY_MAX_AGE:
                    mac_address = self.arp_cache.pop(ip_address).mac_address
                    self.logger.debug(f"Discarded expired ARP cache entry - {ip_address} -> {mac_address}")

                # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
                elif (time.time() - self.arp_cache[ip_address].creation_time > ARP_ENTRY_MAX_AGE - ARP_ENTRY_REFRESH_TIME) and self.arp_cache[
                    ip_address
                ].hit_count:
                    self.arp_cache[ip_address].hit_count = 0
                    self.__send_arp_request(ip_address)
                    self.logger.debug(f"Trying to refresh expiring ARP cache entry for {ip_address} -> {self.arp_cache[ip_address].mac_address}")

            time.sleep(1)

    def __send_arp_request(self, arp_tpa):
        """ Enqueue ARP request with TX ring """

        stack.packet_handler.phtx_arp(
            ether_src=stack.packet_handler.stack_mac_address,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=stack.packet_handler.stack_mac_address,
            arp_spa=stack.packet_handler.stack_ip_unicast[0] if stack.packet_handler.stack_ip_unicast else "0.0.0.0",
            arp_tha="00:00:00:00:00:00",
            arp_tpa=arp_tpa,
        )

    def add_entry(self, ip_address, mac_address):
        """ Add / refresh entry in cache """

        self.arp_cache[ip_address] = self.__Entry(mac_address)

    def find_entry(self, ip_address):
        """ Find entry in cache and return MAC address """

        arp_entry = self.arp_cache.get(ip_address, None)
        if arp_entry:
            arp_entry.hit_count += 1
            self.logger.debug(
                f"Found {ip_address} -> {arp_entry.mac_address} entry, age {time.time() - arp_entry.creation_time:.0f}s, hit_count {arp_entry.hit_count}"
            )
            return arp_entry.mac_address

        else:
            self.logger.debug(f"Unable to find entry for {ip_address}, sending ARP request")
            self.__send_arp_request(ip_address)
