#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
service_udp_echo.py - 'user space' service UDP echo

"""

import threading

import udp_socket


class ServiceUdpEcho:
    """ UDP Echo service support class """

    def __init__(self):
        """ Class constructor """

        self.socket = udp_socket.UdpSocket("192.168.9.7", 7)

        threading.Thread(target=self.__service).start()

    def __service(self):
        while True:
            udp_message = self.socket.receive()
            print(udp_message.raw_data)
            # self.socket.send(udp_message)
