#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_tcp_echo.py - 'user space' client for TCP echo, it activelly connects to service and sends messages

"""


import threading
from datetime import datetime

from tcp_socket import TcpSocket


class ClientTcpEcho:
    """ TCP Echo client support class """

    def __init__(self, local_ip_address, remote_ip_address, local_port=0, remote_port=7):
        """ Class constructor """

        threading.Thread(target=self.__thread_client, args=(local_ip_address, local_port, remote_ip_address, remote_port)).start()

    def __thread_client(self, local_ip_address, local_port, remote_ip_address, remote_port):
        socket = TcpSocket()
        socket.bind(local_ip_address, 0)

        print(f"Client TCP Echo: opening connection to {remote_ip_address}:{remote_port}")
        if socket.connect(remote_ip_address=remote_ip_address, remote_port=remote_port):
            print(f"Client TCP Echo: Connection to {remote_ip_address}:{remote_port} has been established")
        else:
            print(f"Client TCP Echo: Connection to {remote_ip_address}:{remote_port} failed")
            return

        i = 1
        while i <= 10:
            message = bytes(str(datetime.now()) + "\n", "utf-8")
            if socket.send(message):
                print(f"Client TCP Echo: Sent data to {remote_ip_address}:{remote_port} - {message}")
                time.sleep(1)
                i += 1
            else:
                print(f"Client TCP Echo: Peer {remote_ip_address}:{remote_port} closed connection")
                break

        socket.close()
        print(f"Client TCP Echo: Closed connection to {remote_ip_address}:{remote_port}")
