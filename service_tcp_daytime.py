#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_tcp_daytime.py - 'user space' service TCP Daytime (RFC 867)

"""

import threading

from datetime import datetime

import tcp_socket


class ServiceTcpDaytime:
    """ TCP Daytime service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=13):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Daytime: Socket created, bound to {local_ip_address}:{local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Daytime: Inbound connection received from {new_socket.remote_ip_address}:{new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket):
        """ Inbound connection handler """

        daytime = bytes(str(datetime.now()) + "\n", "utf-8")
        for _ in range(3):
            socket.send(daytime)
            print(f"Service TCP Daytime: Sent daytime message to {socket.remote_ip_address}:{socket.remote_port} -", daytime)
            from time import sleep
            sleep(1)
        socket.close()
        print(f"Service TCP Daytime: Closed connection from {socket.remote_ip_address}:{socket.remote_port}")
