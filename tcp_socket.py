#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading

from ps_tcp import TcpOptMss


class TcpPacketMetadata:
    """ Store TCP metadata """

    def __init__(
        self, local_ip_address, local_port, remote_ip_address, remote_port, flag_syn, flag_ack, flag_fin, flag_rst, seq_num, ack_num, win, raw_data, tracker
    ):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.flag_syn = flag_syn
        self.flag_ack = flag_ack
        self.flag_fin = flag_fin
        self.flag_rst = flag_rst
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.win = win
        self.raw_data = raw_data
        self.tracker = tracker

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def listening_socket_ids(self):
        """ Session ID """

        return [
            f"TCP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0",
            f"TCP/0.0.0.0/{self.local_port}/0.0.0.0/0",
        ]


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, metadata):
        """ Class constructor """

        self.local_ip_address = metadata.local_ip_address
        self.local_port = metadata.local_port
        self.remote_ip_address = metadata.remote_ip_address
        self.remote_port = metadata.remote_port

        self.state = None

    def __str__(self):
        """ String representation """

        return self.session_id

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"


class TcpSocket:
    """ Support for Socket operations """

    tcp_sessions = {}
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

        self.logger.info("*** SYN received ***")
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

        self.logger.info("*** SYN/ACK sent ***")

        # Wait for ACK packet for our SYN and verify it
        self.messages_ready.acquire()
        tcp_packet_rx = self.messages.pop(0)
        if tcp_packet_rx.tcp_flag_ack and tcp_packet_rx.tcp_ack_num == self.local_seq_num + 1:
            self.logger.info("*** ACK Received ***")
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
    def match_socket(metadata):
        """ Class method - Try to match incoming packet with either established or listening socket """

        # Check if incoming packet is part of existing session
        session = TcpSocket.tcp_sessions.get(metadata.session_id, None)

        if session:
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} TCP packet is part of existing session {session}")
            return True

        # Check if incoming packet contains intial SYN and there is listening socket that matches it, if so create new session
        if metadata.flag_syn and any(_ in metadata.listening_socket_ids for _ in TcpSocket.open_sockets):
            session = TcpSocket.tcp_sessions[metadata.session_id] = TcpSession(metadata)
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} TCP packet with SYN flag, created new session {session}")
            return True
