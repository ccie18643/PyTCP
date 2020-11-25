#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_tcp_daytime.py - 'user space' service TCP Daytime (RFC 867)

"""

import threading
import time
from datetime import datetime

import tcp_socket


class ServiceTcpDaytime:
    """ TCP Daytime service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=13, message_count=1, message_delay=0, message_size=1):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port, message_count, message_delay, message_size)).start()

    def __thread_service(self, local_ip_address, local_port, message_count, message_delay, message_size):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Daytime: Socket created, bound to {local_ip_address}:{local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Daytime: Inbound connection received from {new_socket.remote_ip_address}:{new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket, message_count, message_delay, message_size)).start()

    def __thread_connection(self, socket, message_count, message_delay, message_size):
        """ Inbound connection handler """

        while message_count:
            # daytime = "bytes(str(datetime.now()) + "\n", "utf-8") * message_size

            message = "[------START------] "
            for i in range(message_size - 2):
                message += f"[------{i + 1:05}------] "
            message += "[-------END-------]\n"
            daytime = bytes(message, "utf-8")

            if result := socket.send(daytime):
                print(f"Service TCP Daytime: Sent daytime message to {socket.remote_ip_address}:{socket.remote_port}")
                time.sleep(message_delay)
                message_count = min(message_count, message_count - 1)
                if result == -1:
                    print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}:{socket.remote_port} has been closed by remote peer")
                    break
            else:
                print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}:{socket.remote_port} has failed")
                break

        socket.close()
        print(f"Service TCP Daytime: Closed connection to {socket.remote_ip_address}:{socket.remote_port}")
