#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ap_cache.py - module contains class supporting ARP cache

"""

import os
import loguru
import time
import threading

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

        threading.Thread(target=self.__maintain).start()

    def __maintain(self):
        """ Thread responsible for maintaining ARP entries """
        
        while True:
            for ip_address in list(self.arp_cache):

                # If entry age is over maximum age then discard the entry
                if time.time() - self.arp_cache[ip_address][1] > ARP_ENTRY_MAX_AGE:
                    mac_address = self.arp_cache.pop(ip_address)[0]
                    self.logger.debug(f"Discarded expired ARP cache entry - {ip_address} -> {mac_address}")

                # If entry age is close to maximum age but the entry has been used since last refresh then send out request in attempt to refresh it
                elif (time.time() - self.arp_cache[ip_address][1] > ARP_ENTRY_MAX_AGE - ARP_ENTRY_REFRESH_TIME) and self.arp_cache[ip_address][2]:
                    self.arp_cache[ip_address][2] = 0
                    self.send_arp_request(ip_address)
                    self.logger.debug(f"Trying to refresh expiring ARP cache entry for {ip_address} -> {self.arp_cache[ip_address][0]}")
            
            time.sleep(1)

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

        self.arp_cache[ip_address] = [mac_address, time.time(), 0]

    def get_mac_address(self, ip_address):
        """ Find entry in cache """

        if arp_entry := self.arp_cache.get(ip_address, None):
            arp_entry[2] += 1
            self.logger.debug(f"Found {ip_address} -> {arp_entry[0]} entry")
            return arp_entry[0]

        else:
            self.logger.debug(f"Unable to find entry for {ip_address}, sending ARP request")

            if self.tx_ring:
                self.send_arp_request(ip_address)

