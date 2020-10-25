#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
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
        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

        self.socket_id = f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        UdpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    def enqueue(self, local_ip_address, local_port, remote_ip_address, remote_port, raw_data):
        """ Put data into socket message queue and release semaphore """

        self.messages.append(UdpMessage(raw_data, local_ip_address, local_port, remote_ip_address, remote_port))
        self.messages_ready.release()

    def send_to(self, udp_message):
        """ Put data from UdpMessage structure into TX ring """

        self.packet_handler.phtx_udp(
            ip_src=udp_message.local_ip_address,
            udp_sport=udp_message.local_port,
            ip_dst=udp_message.remote_ip_address,
            udp_dport=udp_message.remote_port,
            raw_data=udp_message.raw_data,
        )

    def receive_from(self):
        """ Read data from listening socket and return UdpMessage structure """

        self.messages_ready.acquire()
        return self.messages.pop(0)

    def send(self, raw_data):
        """ Put raw_data into TX ring """

        self.packet_handler.phtx_udp(
            ip_src=self.local_ip_address,
            udp_sport=self.local_port,
            ip_dst=self.remote_ip_address,
            udp_dport=self.remote_port,
            raw_data=raw_data,
        )

    def receive(self):
        """ Read data from established socket and return raw_data """

        self.messages_ready.acquire()
        return self.messages.pop(0).raw_data

    def listen(self):
        """ Wait for incoming connection to listening socket, once its received create new socket and return it """

        self.messages_ready.acquire()
        message = self.messages.pop(0)

        established_socket = UdpSocket(message.local_ip_address, message.local_port, message.remote_ip_address, message.remote_port)
        established_socket.enqueue(message.local_ip_address, message.local_port, message.remote_ip_address, message.remote_port, message.raw_data)

        return established_socket

    def close(self):
        """ Close socket """

        UdpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        UdpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(local_ip_address, local_port, remote_ip_address, remote_port, tracker):
        """ Class method - Return opened socket that best matches incoming packet """

        socket_ids = [
            f"UDP/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}",
            f"UDP/{local_ip_address}/{local_port}/0.0.0.0/0",
            f"UDP/0.0.0.0/{local_port}/0.0.0.0/0",
        ]

        for socket_id in socket_ids:
            socket = UdpSocket.open_sockets.get(socket_id, None)
            if socket:
                logger = loguru.logger.bind(object_name="socket.")
                logger.debug(f"{tracker} - Found matching socket {socket_id}")
                return socket
