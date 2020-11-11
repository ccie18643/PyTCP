#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_icmp_echo.py - 'user space' client for ICMP echo

"""


import threading
import random
import time

from datetime import datetime

import stack


class ClientIcmpEcho:
    """ ICMP Echo client support class """

    def __init__(self, local_ip_address, remote_ip_address, local_port=0, remote_port=7, message_count=None):
        """ Class constructor """

        threading.Thread(target=self.__thread_client, args=(local_ip_address, remote_ip_address, message_count)).start()

    def __thread_client(self, local_ip_address, remote_ip_address, message_count):

        icmp_id = random.randint(0, 65535)

        i = 0
        while message_count is None or i < message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")
            stack.packet_handler.phtx_icmp(
                ip_src=local_ip_address, ip_dst=remote_ip_address, icmp_type=8, icmp_code=0, icmp_id=icmp_id, icmp_seq=i, icmp_raw_data=message
            )
            print(f"Client ICMP Echo: Sent ICMP Echo to {remote_ip_address} - {message}")
            time.sleep(1)
            i += 1
