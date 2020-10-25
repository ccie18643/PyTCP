#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
service_udp_echo.py - 'user space' service UDP echo, single threaded version

"""

import threading

import udp_socket


class ServiceUdpEcho:
    """ UDP Echo service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=7):
        """ Class constructor """

        self.socket = udp_socket.UdpSocket(local_ip_address, local_port)

        threading.Thread(target=self.__service).start()

    def __service(self):
        while True:
            udp_message = self.socket.receive_from()
            # print(udp_message.raw_data)
            self.socket.send_to(udp_message)
