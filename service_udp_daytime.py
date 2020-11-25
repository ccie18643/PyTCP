#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_udp_daytime.py - 'user space' service UDP Daytime (RFC 867)

"""

import threading

from datetime import datetime

import udp_socket

from tracker import Tracker
from udp_metadata import UdpMetadata


class ServiceUdpDaytime:
    """ UDP Daytime service support class """

    def __init__(self, local_ipv4_address="0.0.0.0", local_port=13):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ipv4_address, local_port)).start()

    def __thread_service(self, local_ipv4_address, local_port):
        """ Service initialization and rx/tx loop """

        socket = udp_socket.UdpSocket()
        socket.bind(local_ipv4_address, local_port)
        print(f"Service UDP Daytime: Socket created, bound to {local_ipv4_address}:{local_port}")

        while True:
            packet_rx = socket.receive_from()
            packet_tx = UdpMetadata(
                local_ipv4_address=packet_rx.local_ipv4_address,
                local_port=packet_rx.local_port,
                remote_ipv4_address=packet_rx.remote_ipv4_address,
                remote_port=packet_rx.remote_port,
                raw_data=bytes(str(datetime.now()), "utf-8"),
                tracker=Tracker("TX", echo_tracker=packet_rx.tracker),
            )
            socket.send_to(packet_tx)
            print(f"Service UDP Daytime: Sent daytime message to {packet_tx.remote_ipv4_address}:{packet_tx.remote_port} -", packet_tx.raw_data)
