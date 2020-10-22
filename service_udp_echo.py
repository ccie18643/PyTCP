#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
service_udp_echo.py - 'user space' service UDP echo

"""

import time
import threading

import udp_socket


class ServiceUdpEcho:
    """ UDP Echo service support class """

    def __init__(self):
        """ Class constructor """

        self.socket = udp_socket.socket()
        self.socket.bind(("192.168.9.7", 7))

        threading.Thread(target=self.__service).start()

    def __service(self):

        while True:

            data = self.socket.recvfrom()
            self.socket.sendto(data[0], data[1])

