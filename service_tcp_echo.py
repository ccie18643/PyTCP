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
        print("Service TCP Echo: Listening socket created")

        threading.Thread(target=self.__service).start()

    def __connection(self):
        socket = self.socket.accept()

        if socket:
            print("Service TCP Echo: New connection established")

            while True:
                raw_data = socket.receive()
                if raw_data is None:
                    break
                print("Service TCP Echo: Received message", raw_data)
                socket.send(raw_data)
                print("Service TCP Echo: Sent out message", raw_data)

            socket.close()
            print("Service TCP Echo: Closed connection")

    def __service(self):
        while True:
            self.socket.listen()
            print("Service TCP Echo: Session established")

            threading.Thread(target=self.__connection).start()
