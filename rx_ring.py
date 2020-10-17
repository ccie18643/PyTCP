#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
rx_ring.py - module contains class supporting RX operations

"""

import os
import loguru
import asyncio
import time
import threading

import ph_ether


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap, stack_mac_address):
        """ Initialize access to tap interface and the inbound queue """

        self.tap = tap
        self.stack_mac_address = stack_mac_address
        self.rx_ring = asyncio.Queue()
        self.logger = loguru.logger.bind(object_name="rx_ring.")

        thread_rx_ring = threading.Thread(target=self.__receive)
        thread_rx_ring.start()

    def __receive(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:

            # Wait till there is any packet comming and pick it up
            ether_packet_rx = ph_ether.EtherPacketRx(os.read(self.tap, 2048))

            # Check if received packet uses valid Ethernet II format
            if ether_packet_rx.hdr_type < ph_ether.ETHER_TYPE_MIN:
                self.logger.opt(ansi=True).debug(f"<green>[RX]</green> Packet doesn't comply with the Ethernet II standard - {ether_packet_rx.log}")
                continue

            # Check if received packet has been sent to us directly or by broadcast
            if ether_packet_rx.hdr_dst not in {self.stack_mac_address, "ff:ff:ff:ff:ff:ff"}:
                self.logger.opt(ansi=True).debug(f"<green>[RX]</green> Packet not destined for this stack - {ether_packet_rx.log}")
                continue

            # Put the packet into queue
            self.rx_ring.put_nowait(ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.serial_number_rx} - {ether_packet_rx.log}")

    async def dequeue(self):
        """ Dequeue inboutd packet from RX ring - asyncio coroutine"""

        return await self.rx_ring.get()
