#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tx_ring.py - module contains class supporting TX operations

"""

import os
import time
import loguru
import threading

import ps_ether
import ps_ip


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap, stack_mac_address, arp_cache):
        """ Initialize access to tap interface and the outbound queue """

        self.tap = tap
        self.stack_mac_address = stack_mac_address
        self.arp_cache = arp_cache

        # Update ARP cache object with reference to ths TX ring so ARP cache can send request packets
        self.arp_cache.tx_ring = self

        self.tx_ring = []
        self.logger = loguru.logger.bind(object_name="tx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__transmit).start()
        self.logger.debug("Started TX ring")

    def __transmit(self):
        """ Dequeue packet from TX ring """

        while True:

            # Wait till packets is avaiable int he queue the pick it up
            self.packet_enqueued.acquire()
            ether_packet_tx = self.tx_ring.pop(0)

            # Check if packet contains valid source address, fill it out if needed
            if ether_packet_tx.hdr_src == "00:00:00:00:00:00":
                ether_packet_tx.hdr_src = self.stack_mac_address
                self.logger.debug(f"Set source to stack MAC {ether_packet_tx.hdr_src}")

            # Check if packet contains valid destination MAC address
            if ether_packet_tx.hdr_dst != "00:00:00:00:00:00":
                self.logger.debug(f"Contains valid destination MAC address")

            # In case packe doesn't contain valid destination MAC address try to obtain it from ARP cache
            elif ether_packet_tx.hdr_type == ps_ether.ETHER_TYPE_IP:
                ip_packet_tx = ps_ip.IpPacket(ether_packet_tx)

                mac_address = self.arp_cache.find_entry(ip_packet_tx.hdr_dst)
                if mac_address:
                    ether_packet_tx.hdr_dst = mac_address
                    self.logger.debug(f"Resolved destiantion IP {ip_packet_tx.hdr_dst} to MAC {ether_packet_tx.hdr_dst}")

            # If we not able to obtain valid destination MAC address from the cache then drop packet and continue the loop
            else:
                self.logger.debug(f"Droping packet, no valid destination MAC could be obtained")
                continue

            # In case packet contains or we are able to obtain valid destination MAC address send the packet out
            os.write(self.tap, ether_packet_tx.get_raw_packet())
            self.logger.opt(ansi=True).debug(f"<magenta>[TX] {ether_packet_tx.tracker}</magenta> <yellow>{ether_packet_tx.tracker.latency}</yellow> - {len(ether_packet_tx)} bytes")

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)

        else:
            self.tx_ring.append(ether_packet_tx)

        self.packet_enqueued.release()
