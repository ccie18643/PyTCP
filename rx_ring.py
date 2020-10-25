#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
rx_ring.py - module contains class supporting RX operations

"""

import os
import loguru
import threading

import ps_ether


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap, stack_mac_address):
        """ Initialize access to tap interface and the inbound queue """

        self.tap = tap
        self.stack_mac_address = stack_mac_address
        self.rx_ring = []
        self.logger = loguru.logger.bind(object_name="rx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__receive).start()
        self.logger.debug("Started RX ring")

    def __enqueue(self, ether_packet_rx):
        """ Enqueue packet for further processing """

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP:
            self.rx_ring.insert(0, ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"<green>[RX] {ether_packet_rx.tracker}</green>, priority: Urgent, queue len: {len(self.rx_ring)}")
        else:
            self.rx_ring.append(ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"<green>[RX] {ether_packet_rx.tracker}</green>, priority: Normal, queue len: {len(self.rx_ring)}")

        self.packet_enqueued.release()


    def __receive(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:

            # Wait till there is any packet comming and pick it up
            ether_packet_rx = ps_ether.EtherPacket(os.read(self.tap, 2048))
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.tracker} - {len(ether_packet_rx)} bytes")
            self.__enqueue(ether_packet_rx)

    def dequeue(self):
        """ Dequeue inboutd packet from RX ring """

        self.packet_enqueued.acquire()

        return self.rx_ring.pop(0)
