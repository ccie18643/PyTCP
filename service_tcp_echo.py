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

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        print("Service TCP Echo: Socket created")

        socket.bind(local_ip_address, local_port)
        print(f"Service TCP Echo: Socket bound to {local_ip_address} on port {local_port}")

        socket.listen()
        print("Service TCP Echo: Socket set to listening mode")

        while True:
            new_socket = socket.accept()
            print("Service TCP Echo: Inbound connection received")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket):
        """ Inbound connection handler """

        while True:
            data_segment = socket.receive()

            if data_segment is None:
                break

            socket.send(data_segment)
            print("Service TCP Echo: Echo'ed out message", data_segment)

        socket.close()
        print("Service TCP Echo: Connection has been closed")
