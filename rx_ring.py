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

    def __receive(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:

            # Wait till there is any packet comming and pick it up
            ether_packet_rx = ps_ether.EtherPacket(os.read(self.tap, 2048))

            # Check if received packet uses valid Ethernet II format
            if ether_packet_rx.hdr_type < ps_ether.ETHER_TYPE_MIN:
                self.logger.opt(ansi=True).debug(f"<green>[RX]</green> Packet doesn't comply with the Ethernet II standard - {ether_packet_rx}")
                continue

            # Check if received packet has been sent to us directly or by broadcast
            if ether_packet_rx.hdr_dst not in {self.stack_mac_address, "ff:ff:ff:ff:ff:ff"}:
                self.logger.opt(ansi=True).debug(f"<green>[RX]</green> Packet not destined for this stack - {ether_packet_rx}")
                continue

            # Put the packet into queue
            self.rx_ring.append(ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.tracker} - {len(ether_packet_rx)} bytes")
            self.packet_enqueued.release()

    def dequeue(self):
        """ Dequeue inboutd packet from RX ring """

        self.packet_enqueued.acquire()

        return self.rx_ring.pop(0)
