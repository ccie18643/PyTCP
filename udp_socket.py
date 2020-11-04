#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
udp_socket.py - module contains class supporting UDP sockets

"""

import loguru
import threading


class UdpPacketMetadata:
    """ Store UDP packet metadata """

    def __init__(self, local_ip_address, local_port, remote_ip_address, remote_port, raw_data, tracker):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data
        self.tracker = tracker


class UdpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    packet_handler = None

    def __init__(self, local_ip_address, local_port, remote_ip_address="0.0.0.0", remote_port=0):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        self.metadata_rx = []
        self.metadata_rx_ready = threading.Semaphore(0)

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket_id = f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        UdpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    def send_to(self, metadata):
        """ Put data from UdpPacketMetadata structure into TX ring """

        self.packet_handler.phtx_udp(
            ip_src=metadata.local_ip_address,
            udp_sport=metadata.local_port,
            ip_dst=metadata.remote_ip_address,
            udp_dport=metadata.remote_port,
            raw_data=metadata.raw_data,
        )

    def receive_from(self, timeout=None):
        """ Read data from listening socket and return UdpMessage structure """

        if self.metadata_rx_ready.acquire(timeout=timeout):
            return self.metadata_rx.pop(0)

    def close(self):
        """ Close socket """

        UdpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        UdpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(metadata):
        """ Class method - Check if incoming data belongs to any socket, if so enqueue it """

        socket_ids = [
            f"UDP/{metadata.local_ip_address}/{metadata.local_port}/{metadata.remote_ip_address}/{metadata.remote_port}",
            f"UDP/{metadata.local_ip_address}/{metadata.local_port}/0.0.0.0/0",
            f"UDP/0.0.0.0/{metadata.local_port}/0.0.0.0/{metadata.remote_port}",
            f"UDP/0.0.0.0/{metadata.local_port}/0.0.0.0/0",
        ]

        for socket_id in socket_ids:
            socket = UdpSocket.open_sockets.get(socket_id, None)
            if socket:
                loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - Found matching listening socket {socket_id}")
                socket.metadata_rx.append(metadata)
                socket.metadata_rx_ready.release()
                return True
