#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading

from ps_tcp import TcpOptMss


class TcpMessage:
    """ Store TCP message in socket """

    def __init__(self, local_ip_address, local_port, remote_ip_address, remote_port, tcp_packet_rx):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.tcp_packet_rx = tcp_packet_rx


class TcpSocket:
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

        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

        TcpSocket.open_sockets[self.socket_id] = self

        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def send(self, raw_data):
        """ Put raw_data into TX ring """

        pass

    def receive(self):
        """ Read data from established socket and return raw_data """

        self.messages_ready.acquire()
        return self.messages.pop(0).raw_data

    def listen(self):
        """ Wait for incoming connection to listening socket, once its received create new socket and return it """

        self.messages_ready.acquire()
        message = self.messages.pop(0)

        established_socket = TcpSocket(message.local_ip_address, message.local_port, message.remote_ip_address, message.remote_port)
        established_socket.messages.append(message.tcp_packet_rx)
        established_socket.messages_ready.release()

        return established_socket

    def accept(self):
        """ Wait for connection to be fully established """

        # Wait for initial SYN packet and respnd to it
        self.messages_ready.acquire()
        tcp_packet_rx = self.messages.pop(0)
        self.local_seq_num = 0
        self.remote_seq_num = tcp_packet_rx.tcp_seq_num

        self.logger.info(f"*** SYN received ***")
        self.packet_handler.phtx_tcp(
            ip_src=self.local_ip_address,
            ip_dst=self.remote_ip_address,
            tcp_sport=self.local_port,
            tcp_dport=self.remote_port,
            tcp_flag_syn=True,
            tcp_flag_ack=True,
            tcp_seq_num=self.local_seq_num,
            tcp_ack_num=self.remote_seq_num + 1,
            tcp_options=[TcpOptMss(opt_size=1460)],
        )

        self.logger.info(f"*** SYN/ACK sent ***")

        # Wait for ACK packet for our SYN and verify it
        self.messages_ready.acquire()
        tcp_packet_rx = self.messages.pop(0)
        if tcp_packet_rx.tcp_flag_ack and tcp_packet_rx.tcp_ack_num == self.local_seq_num + 1:
            self.logger.info(f"*** ACK Received ***")
            self.remote_seq_num = tcp_packet_rx.tcp_seq_num
            return True

    def close(self):
        """ Close socket """

        TcpSocket.open_sockets.pop(self.socket_id, None)
        self.logger.debug(f"Closed TCP socket {self.socket_id}")

    @staticmethod
    def set_packet_handler(packet_handler):
        """ Class method - Sets packet handler object to be available for sockets """

        TcpSocket.packet_handler = packet_handler

    @staticmethod
    def match_socket(local_ip_address, local_port, remote_ip_address, remote_port, tcp_packet_rx):
        """ Class method - Try to match incoming packet with either established or listening socket """

        # Check if packet is part of established connection
        socket_id = f"TCP/{local_ip_address}/{local_port}/{remote_ip_address}/{remote_port}"

        socket = TcpSocket.open_sockets.get(socket_id, None)
        if socket:
            logger = loguru.logger.bind(object_name="socket.")
            logger.debug(f"{tcp_packet_rx.tracker} - Found matching established socket {socket_id}")
            socket.messages.append(tcp_packet_rx)
            socket.messages_ready.release()
            return True

        # Check if incoming packet is the initial SYN packet
        if tcp_packet_rx.tcp_flag_syn:

            # Check if packet matches any of listening sockets
            socket_ids = [
                f"TCP/{local_ip_address}/{local_port}/0.0.0.0/0",
                f"TCP/0.0.0.0/{local_port}/0.0.0.0/0",
            ]

            for socket_id in socket_ids:
                socket = TcpSocket.open_sockets.get(socket_id, None)
                if socket:
                    logger = loguru.logger.bind(object_name="socket.")
                    logger.debug(f"{tcp_packet_rx.tracker} - Found matching listening socket {socket_id}")
                    socket.messages.append(TcpMessage(local_ip_address, local_port, remote_ip_address, remote_port, tcp_packet_rx))
                    socket.messages_ready.release()
                    return True
