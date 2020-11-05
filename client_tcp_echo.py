#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_tcp_echo.py - 'user space' client for TCP echo, it activelly connects to service and sends messages

"""

import tcp_socket


class ClientTcpEcho:
    """ TCP Echo client support class """

    def __init__(self, local_ip_address, remote_ip_address, local_port=None, remote_port=7):
        """ Class constructor """

        socket = tcp_socket.TcpSocket(local_ip_address, local_port, remote_ip_address, remote_port)
        print("Client TCP Echo: Socket created")

        if socket.connect(timeout=30):
            print("Client TCP Echo: Connection established")
