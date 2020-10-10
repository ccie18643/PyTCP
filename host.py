#!/usr/bin/env python3
  
"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
host.py - contains class responsible for emulating host

"""

import asyncio


class Host:
    """ Class responsible for emulating host """

    def __init__():
        """ Class constructor """
        pass

    def receiver(packet):
        """ Inbound packet receiver """
        pass


    async def sender():
       """ Coroutine responsible for sending out packets """

       packet = self.packet_queue.pop(0)

       self.routing_table[packet.dst_addr](packet)

       await asyncio.sleep(1)


