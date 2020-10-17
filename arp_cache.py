#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ap_cache.py - module contains class supporting ARP cache

"""

import os
import loguru
import time
import asyncio

import ph_ether
import ph_arp

ARP_ENTRY_MAX_AGE = 60
ARP_ENTRY_REFRESH_TIME = 10


class ArpCache:
    """ Support for ARP cahe operations """

    def __init__(self, stack_mac_address, stack_ip_address):
        """ Class constructor """

        self.stack_mac_address = stack_mac_address
        self.stack_ip_address = stack_ip_address

        self.arp_cache = {}
        self.tx_ring = None
        self.logger = loguru.logger.bind(object_name="arp_cache.")

    def send_arp_request(self, hdr_tpa):
        """ Enqueue ARP request with TX ring """

        arp_packet_tx = ph_arp.ArpPacketTx(
            hdr_operation=ph_arp.ARP_OP_REQUEST,
            hdr_sha=self.stack_mac_address,
            hdr_spa=self.stack_ip_address,
            hdr_tha="00:00:00:00:00:00",
            hdr_tpa=hdr_tpa,
        )

        ether_packet_tx = ph_ether.EtherPacketTx(
            hdr_src=self.stack_mac_address, hdr_dst="ff:ff:ff:ff:ff:ff", hdr_type=ph_ether.ETHER_TYPE_ARP, raw_data=arp_packet_tx.raw_packet
        )

        self.logger.debug(f"{ether_packet_tx.serial_number_tx} - {ether_packet_tx.log}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} </magenta> - {arp_packet_tx.log}")
        self.tx_ring.enqueue(ether_packet_tx, urgent=True)

    def add_entry(self, ip_address, mac_address):
        """ Add / refresh entry in cache """

        self.arp_cache[ip_address] = [ip_address, mac_address, time.time(), 0]

    def get_mac_address(self, ip_address):
        """ Find entry in cache """

        if arp_entry := self.arp_cache.get(ip_address, None):
            arp_entry[3] += 1
            self.logger.debug(f"Resolved {ip_address} to {arp_entry[1]}")
            return arp_entry[1]

        else:
            self.logger.debug(f"Unable to resolve {ip_address}, sending ARP request")
            self.send_arp_request(ip_address)

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
                    self.send_arp_request(arp_entry[0])
                    self.logger.debug(f"Trying to refresh expiring ARP cache entry for {arp_entry[0]} -> {arp_entry[1]}")
            
            await asyncio.sleep(1)
