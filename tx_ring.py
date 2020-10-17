#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tx_ring.py - module contains class supporting TX operations

"""

import os
import loguru
import time
import time
import threading

import ph_ether
import ph_arp
import ph_ip


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap, stack_mac_address, stack_ip_address, arp_cache):
        """ Initialize access to tap interface and the outbound queue """

        self.tap = tap
        self.stack_mac_address = stack_mac_address
        self.stack_ip_address = stack_ip_address
        self.arp_cache = arp_cache

        # Update ARP cache object with reference to ths TX ring so ARP cache can send request packets
        self.arp_cache.tx_ring = self

        self.tx_ring = []
        self.logger = loguru.logger.bind(object_name="tx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        thread_tx_ring = threading.Thread(target=self.__transmit)
        thread_tx_ring.start()

    def __transmit(self):
        """ Dequeue packet from TX ring """

        while True:

            # Wait till packets is avaiable int he queue the pick it up
            self.packet_enqueued.acquire()
            ether_packet_tx = self.tx_ring.pop(0)

            # Check if packet contains valid destination MAC address
            if ether_packet_tx.hdr_dst != "00:00:00:00:00:00":
                self.logger.debug(f"{ether_packet_tx.serial_number_tx} Contains valid destination MAC address")

            # In case packe doesn't contain valid destination MAC address try to obtain it from ARP cache
            elif ether_packet_tx.hdr_type == ph_ether.ETHER_TYPE_IP:
                ip_packet_tx = ph_ip.IpPacketRx(ether_packet_tx.raw_data)

                if mac_address := self.arp_cache.get_mac_address(ip_packet_tx.hdr_dst):
                    ether_packet_tx.hdr_dst = mac_address
                    self.logger.debug(f"{ether_packet_tx.serial_number_tx} Resolved destiantion IP {ip_packet_tx.hdr_dst} to MAC ({ether_packet_tx.hdr_dst})")

            # If we not able to obtain valid destination MAC address from the cache then drop packet and continue the loop
            else:
                self.logger.debug(f"{ether_packet_tx.serial_number_tx} Droping packet, no valid destination MAC could be obtained")
                continue

            # In case packet contains or we are able to obtain valid destination MAC address send the packet out
            os.write(self.tap, ether_packet_tx.raw_packet)
            if hasattr(ether_packet_tx, "timestamp_rx"):
                self.logger.opt(ansi=True).debug(
                    f"<magenta>[TX]</magenta> {ether_packet_tx.serial_number_tx} <yellow>({ether_packet_tx.serial_number_rx}"
                    + f", {(time.time() - ether_packet_tx.timestamp_rx) * 1000:.3f}ms)</yellow> - {ether_packet_tx.log}"
                )
            else:
                self.logger.opt(ansi=True).debug(f"<magenta>[TX]</magenta> {ether_packet_tx.serial_number_tx} - {ether_packet_tx.log}")

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        ether_packet_tx.enqueue_timestamp = time.time()

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)

        else:
            self.tx_ring.append(ether_packet_tx)

        self.packet_enqueued.release()
