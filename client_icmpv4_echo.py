#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_icmpv4_echo.py - 'user space' client for ICMPv4 echo

"""


import threading
import random
import time

from datetime import datetime

import stack


class ClientIcmpEcho:
    """ ICMPv4 Echo client support class """

    def __init__(self, local_ipv4_address, remote_ipv4_address, local_port=0, remote_port=7, message_count=None):
        """ Class constructor """

        threading.Thread(target=self.__thread_client, args=(local_ipv4_address, remote_ipv4_address, message_count)).start()

    def __thread_client(self, local_ipv4_address, remote_ipv4_address, message_count):

        icmpv4_id = random.randint(0, 65535)

        i = 0
        while message_count is None or i < message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")
            stack.packet_handler.phtx_icmpv4(
                ipv4_src=local_ipv4_address,
                ipv4_dst=remote_ipv4_address,
                icmpv4_type=8,
                icmpv4_code=0,
                icmpv4_id=icmpv4_id,
                icmpv4_seq=i,
                icmpv4_raw_data=message,
            )
            print(f"Client ICMPv4 Echo: Sent ICMPv4 Echo to {remote_ipv4_address} - {message}")
            time.sleep(1)
            i += 1
