#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_udp_discard.py - 'user space' service UDP Discard (RFC 863)

"""

import threading

import udp_socket


class ServiceUdpDiscard:
    """ UDP Discard service support class """

    def __init__(self, local_ipv4_address="0.0.0.0", local_port=9):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ipv4_address, local_port)).start()

    def __thread_service(self, local_ipv4_address, local_port):
        """ Service initialization and rx/tx loop """

        socket = udp_socket.UdpSocket()
        socket.bind(local_ipv4_address, local_port)
        print(f"Service UDP Discard: Socket created, bound to {local_ipv4_address}:{local_port}")

        while True:
            packet = socket.receive_from()
            print(f"Service UDP Discard: Discarded message from {packet.remote_ipv4_address}:{packet.remote_port} -", packet.raw_data)
