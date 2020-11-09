#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tx_ring.py - module contains class supporting TX operations

"""

import os
import loguru
import threading


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap, stack_mac_address):
        """ Initialize access to tap interface and the outbound queue """

        self.tap = tap
        self.stack_mac_address = stack_mac_address

        self.tx_ring = []
        self.logger = loguru.logger.bind(object_name="tx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_dequeue).start()
        self.logger.debug("Started TX ring")

    def __thread_dequeue(self):
        """ Dequeue packet from TX ring """

        while True:
            # Wait till packets is avaiable int he queue the pick it up
            self.packet_enqueued.acquire()
            ether_packet_tx = self.tx_ring.pop(0)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}")
            self.__transmit(ether_packet_tx)

    def __transmit(self, ether_packet_tx):
        """ Transmit packet """

        os.write(self.tap, ether_packet_tx.get_raw_packet())
        self.logger.opt(ansi=True).debug(
            f"<magenta>[TX]</> {ether_packet_tx.tracker}<yellow>{ether_packet_tx.tracker.latency}</> - {len(ether_packet_tx)} bytes"
        )

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}, priority: Urgent, queue len: {len(self.tx_ring)}")

        else:
            self.tx_ring.append(ether_packet_tx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}, priorty: Normal, queue len: {len(self.tx_ring)}")

        self.packet_enqueued.release()
