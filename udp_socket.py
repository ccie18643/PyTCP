#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
udp_socket.py - module contains class supporting UDP sockets

"""

import loguru
import threading


class UdpMessage:
    """ Store UDP message in socket """

    def __init__(self, raw_data, local_ip_address, local_port, remote_ip_address, remote_port):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data


class UdpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self, local_ip_address, local_port, remote_ip_address="0.0.0.0", remote_port=0):
        """ Class constructor """

        self.messages = []
        self.messages_ready = threading.Semaphore(0)
        self.logger = loguru.logger.bind(object_name="udp_socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket_id = f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        UdpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    def send_to(self, udp_message):
        """ Put data from UdpMessage structure into TX ring """

        self.packet_handler.phtx_udp(
            ip_src=udp_message.local_ip_address,
            udp_sport=udp_message.local_port,
            ip_dst=udp_message.remote_ip_address,
            udp_dport=udp_message.remote_port,
            raw_data=udp_message.raw_data,
        )

    def receive_from(self, timeout = None):
        """ Read data from listening socket and return UdpMessage structure """

        self.messages_ready.acquire(timeout)
        return self.messages.pop(0)

    def close(self):
        """ Close socket """

        UdpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        UdpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(local_ip_address, local_port, remote_ip_address, remote_port, raw_data, tracker):
        """ Class method - Check if incoming data belongs to any socket, if so enqueue it """

        socket_ids = [
            f"UDP/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}",
            f"UDP/{local_ip_address}/{local_port}/0.0.0.0/0",
            f"UDP/0.0.0.0/{local_port}/0.0.0.0/{remote_port}",
            f"UDP/0.0.0.0/{local_port}/0.0.0.0/0",
        ]

        for socket_id in socket_ids:
            socket = UdpSocket.open_sockets.get(socket_id, None)
            if socket:
                logger = loguru.logger.bind(object_name="socket.")
                logger.debug(f"{tracker} - Found matching listening socket {socket_id}")
                socket.messages.append(UdpMessage(raw_data, local_ip_address, local_port, remote_ip_address, remote_port))
                socket.messages_ready.release()
                return True
