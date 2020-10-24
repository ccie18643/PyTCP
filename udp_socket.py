#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
udp_socket.py - module contains class supporting TCP and UDP sockets

"""

import loguru
import threading


MTU = 1500


class UdpMessage:
    """ Store UDP message in socket """

    def __init__(self, raw_data, remote_ip_address, remote_port):
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data


class UdpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self, local_ip_address, local_port):
        """ Class constructor """

        self.data_rx = []
        self.data_ready_rx = threading.Semaphore(0)
        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        self.socket_id = f"UDP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0"

        UdpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    def enqueue(self, src_ip_address, src_port, raw_data):
        """ Put data into socket RX queue and release semaphore """

        self.data_rx.append(UdpMessage(raw_data, src_ip_address, src_port))
        self.data_ready_rx.release()

    def send(self, udp_message):
        """ Put data into TX ring """

        self.packet_handler.phtx_udp(
            ip_dst=udp_message.remote_ip_address, udp_sport=self.local_port, udp_dport=udp_message.remote_port, raw_data=udp_message.raw_data
        )

    def receive(self):
        """ Read data from socket """

        # Wait till data is available
        self.data_ready_rx.acquire()

        return self.data_rx.pop(0)

    def close(self):
        """ Close socket """

        UdpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        UdpSocket.packet_handler = packet_handler

    @staticmethod
    def match_listening(local_ip_address, local_port, tracker):
        """ Class method - Return listening socket that matches incoming packet """

        socket_id = f"UDP/{local_ip_address}/{local_port}/0.0.0.0/0"
        socket = UdpSocket.open_sockets.get(socket_id, None)
        if socket:
            logger = loguru.logger.bind(object_name="socket.")
            logger.debug(f"{tracker} - Found matching listening socket {socket_id}")
            return socket
