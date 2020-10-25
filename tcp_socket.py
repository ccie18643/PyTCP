#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading


class TcpMessage:
    """ Store TCP message in socket """

    def __init__(self, raw_data, remote_ip_address, remote_port):
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data


class TcpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self, local_ip_address, local_port):
        """ Class constructor """

        self.data_rx = []
        self.data_ready_rx = threading.Semaphore(0)
        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0"

        TcpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def enqueue(self, src_ip_address, src_port, raw_data):
        """ Put data into socket RX queue and release semaphore """

        self.data_rx.append(TcpMessage(raw_data, src_ip_address, src_port))
        self.data_ready_rx.release()

    def send(self, tcp_message):
        """ Put data into TX ring """

        self.packet_handler.phtx_tcp(
            ip_dst=tcp_message.remote_ip_address, tcp_sport=self.local_port, tcp_dport=tcp_message.remote_port, raw_data=tcp_message.raw_data
        )

    def receive(self):
        """ Read data from socket """

        # Wait till data is available
        self.data_ready_rx.acquire()

        return self.data_rx.pop(0)

    def close(self):
        """ Close socket """

        TcpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed TCP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        TcpSocket.packet_handler = packet_handler

    @staticmethod
    def match_listening(local_ip_address, local_port, tracker):
        """ Class method - Return listening socket that matches incoming packet """

        socket_id = f"TCP/{local_ip_address}/{local_port}/0.0.0.0/0"
        socket = TcpSocket.open_sockets.get(socket_id, None)
        if socket:
            logger = loguru.logger.bind(object_name="socket.")
            logger.debug(f"{tracker} - Found matching listening socket {socket_id}")
            return socket

    @staticmethod
    def match_established(local_ip_address, local_port, remote_ip_address, remote_port, tracker):
        """ Class method - Return listening socket that matches incoming packet """

        socket_id = f"TCP/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}"
        socket = TcpSocket.open_sockets.get(socket_id, None)
        if socket:
            logger = loguru.logger.bind(object_name="socket.")
            logger.debug(f"{tracker} - Found matching established socket {socket_id}")
            return socket
