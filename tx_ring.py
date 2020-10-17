#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tx_ring.py - module contains class supporting TX operations

"""

import os
import loguru
import time
import threading

import ph_ether
import ph_arp
import ph_ip


TX_RING_MAX_RETRY_COUNT = 3
TX_RING_RETRY_DELAY = 0.25


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

    def enqueue_arp_request(self, hdr_tpa):
        """ Enqueue ARP request """

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

        self.logger.debug(f"{ether_packet_tx.serial_number} - {ether_packet_tx.log}")
        self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number} </magenta> - {arp_packet_tx.log}")
        self.enqueue(ether_packet_tx, urgent=True)

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)

        else:
            self.tx_ring.append(ether_packet_tx)

        self.packet_enqueued.release()

    def dequeue(self):
        """ Dequeue packet from TX ring """

        while True:
            self.packet_enqueued.acquire()

            ether_packet_tx = self.tx_ring.pop(0)

            # Check if packet should be delayed
            if time.time() < ether_packet_tx.retry_time:
                self.enqueue(ether_packet_tx)
                continue

            # In case Ethernet packet contains valid destination MAC send it out
            if ether_packet_tx.hdr_dst != "00:00:00:00:00:00":
                self.logger.debug(f"{ether_packet_tx.serial_number} Contains valid destination MAC address")
                return ether_packet_tx

            # If above is not true then check if Ethernet packet carries IP packet and if so try to resolve destination MAC based on IP address
            if ether_packet_tx.hdr_type == ph_ether.ETHER_TYPE_IP:
                ip_packet_tx = ph_ip.IpPacketRx(ether_packet_tx.raw_data)

                # Try to resolve destination MAC using ARP cache
                if mac_address := self.arp_cache.get_mac_address(ip_packet_tx.hdr_dst):
                    ether_packet_tx.hdr_dst = mac_address
                    self.logger.debug(f"{ether_packet_tx.serial_number} Resolved destiantion IP {ip_packet_tx.hdr_dst} to MAC ({ether_packet_tx.hdr_dst})")
                    return ether_packet_tx

                # If we don't have valid ARP cache entry for given destination IP send out ARP request for it and delay the packet if appropriate
                else:
                    self.logger.debug(
                        f"{ether_packet_tx.serial_number} Unable to resolve destiantion IP to MAC, sending ARP request for {ip_packet_tx.hdr_dst}"
                    )

                    # In case this is first time we trying to send this packet then sent out arp request to resolve its destiantion
                    if ether_packet_tx.retry_count == 0:
                        self.enqueue_arp_request(ip_packet_tx.hdr_dst)

                    # Incremet retry counter and if its within the limit enqueue original packet with current timestamp
                    ether_packet_tx.retry_count += 1

                    if ether_packet_tx.retry_count <= TX_RING_MAX_RETRY_COUNT:
                        ether_packet_tx.retry_time = time.time() + TX_RING_RETRY_DELAY
                        self.enqueue(ether_packet_tx)
                        self.logger.debug(
                            f"{ether_packet_tx.serial_number} Delaying packet for {TX_RING_RETRY_DELAY}s, retry counter {ether_packet_tx.retry_count}"
                        )
                        continue

            self.logger.debug(f"{ether_packet_tx.serial_number} Droping packet, no valid destination MAC could be obtained")

    def handler(self):
        """ Thread responsible for dequeuing and sending outgoing packets """

        while True:
            ether_packet_tx = self.dequeue()
            os.write(self.tap, ether_packet_tx.raw_packet)
            self.logger.opt(ansi=True).debug(f"<magenta>[TX]</magenta> {ether_packet_tx.serial_number} - {ether_packet_tx.log}")
