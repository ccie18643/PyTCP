#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_tcp_echo.py - 'user space' service TCP echo, multi threaded version

"""

import threading

import tcp_socket


class ServiceTcpEcho:
    """ TCP Echo service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=7):
        """ Class constructor """

        self.socket = tcp_socket.TcpSocket(local_ip_address, local_port)
        # threading.Thread(target=self.__service).start()

    def __connection(self, socket):
        if socket.accept():
            print("Service TCP Echo: New connection established")

            while True:
                raw_data = socket.receive()
                if raw_data == b"\n":
                    break
                print("Service TCP Echo: Received message", raw_data)
                socket.send(raw_data)

            socket.close()
            print("Service TCP Echo: Closed connection")

    def __service(self):
        while True:
            new_socket = self.socket.listen()
            print("Service TCP Echo: New connection incomming")
            threading.Thread(target=self.__connection, args=(new_socket,)).start()
