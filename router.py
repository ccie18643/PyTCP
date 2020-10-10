#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stiack simulation version 0.1 - 2020, Sebastian Majewski
router.py - contains class responsible for emulating network in between the hosts

"""

import asyncio


class Router:
    """ Class responsible for routing packet in between hosts """

    def __init__():
        """ Class constructor """

        self.packet_queue = []
        self.routing_table = {}

    def add_route(destination, receiver):
        """ Populate routing table with IP - receiver mapings """

        routing_table[destination] = receiver

    def receiver(packet):
        """ Inbound packet receiver """

        self.packet_queue.append(packet)

    async def sender():
       """ Coroutine responsible for sending out packets """

       packet = self.packet_queue.pop(0)

       self.routing_table[packet.dst_addr](packet)

       await asyncio.sleep(1)


