#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_tcp_echo.py - 'user space' client for TCP echo, it activelly connects to service and sends messages

"""

import time
import threading

import tcp_socket


class ClientTcpEcho:
    """ TCP Echo client support class """

    def __init__(self, local_ip_address, remote_ip_address, remote_port=7):
        """ Class constructor """

        self.local_ip_address = local_ip_address
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        threading.Thread(target=self.__client).start()

    def __client(self):
        socket = tcp_socket.TcpSocket(local_ip_address=self.local_ip_address, remote_ip_address=self.remote_ip_address, remote_port=self.remote_port)

        print(f"Client TCP Echo: opening connection ({socket.socket_id})")
        if socket.connect(timeout=180):
            print(f"Client TCP Echo: Connection established ({socket.socket_id})")
        else:
            print(f"Client TCP Echo: Connection timed out ({socket.socket_id})")
            return

        i = 1
        while i <= 3:
            socket.send(b"DUPA " + bytes([48 + i]) + b"\n")
            print(f"Client TCP Echo: Sent data out ({socket.socket_id})")
            time.sleep(1)
            i += 1

        socket.close()
        print(f"Client TCP Echo: Closed socket ({socket.socket_id})")
