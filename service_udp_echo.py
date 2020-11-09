#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_udp_echo.py - 'user space' service UDP Echo (RFC 862)

"""

import threading

import udp_socket

from udp_packet import UdpPacket
from tracker import Tracker


class ServiceUdpEcho:
    """ UDP Echo service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=7):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization and rx/tx loop """

        socket = udp_socket.UdpSocket()
        socket.bind(local_ip_address, local_port)
        print(f"Service UDP Echo: Socket created, bound to {local_ip_address}:{local_port}")

        while True:
            packet_rx = socket.receive_from()
            print(f"Service UDP Echo: Received message from {packet_rx.remote_ip_address}:{packet_rx.remote_port} -", packet_rx.raw_data)
            packet_tx = UdpPacket(
                local_ip_address=packet_rx.local_ip_address,
                local_port=packet_rx.local_port,
                remote_ip_address=packet_rx.remote_ip_address,
                remote_port=packet_rx.remote_port,
                raw_data=packet_rx.raw_data,
                tracker=Tracker("TX", echo_tracker=packet_rx.tracker),
            )
            socket.send_to(packet_tx)
            print(f"Service UDP Echo: Echo'ed message back to {packet_tx.remote_ip_address}:{packet_tx.remote_port} -", packet_tx.raw_data)
