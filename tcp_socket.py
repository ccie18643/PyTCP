#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading
import random

from tcp_session import TcpSession


class TcpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self, local_ip_address=None, local_port=None, remote_ip_address=None, remote_port=None, tcp_session=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        self.tcp_session_established = threading.Semaphore(0)

        # Create established socket based on established TCP session, used by listening sockets only
        if tcp_session:
            self.tcp_session = tcp_session
            self.tcp_session_established.release()
            self.local_ip_address = tcp_session.local_ip_address
            self.local_port = tcp_session.local_port
            self.remote_ip_address = tcp_session.remote_ip_address
            self.remote_port = tcp_session.remote_port

        # Create established socket and start new TCP session
        elif all((local_ip_address, remote_ip_address, remote_port)):
            self.tcp_session = None
            self.local_ip_address = local_ip_address
            self.local_port = self.__pick_random_local_port()
            self.remote_ip_address = remote_ip_address
            self.remote_port = remote_port

        # Create listening socket
        else:
            self.tcp_sessions = {}
            self.local_ip_address = local_ip_address
            self.local_port = local_port
            self.remote_ip_address = "0.0.0.0"
            self.remote_port = 0

        self.socket_id = f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"
        TcpSocket.open_sockets[self.socket_id] = self
        self.logger.debug(f"Opened TCP socket {self.socket_id}")

    def connect(self, timeout=None):
        """ Attempt to establish TCP connection """

        self.tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port,
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )

        return self.tcp_session.connect()

    def __pick_random_local_port(self):
        """ Pick random local port, making sure it is not already being used by any socket """

        used_ports = {int(_.split("/")[2]) for _ in TcpSocket.open_sockets if _.split("/")[1] in {"0.0.0.0", self.local_ip_address}}

        while (port := random.randint(1024, 65535)) not in used_ports:
            return port

    def send(self, raw_data):
        """ Pass raw_data to TCP session """

        self.tcp_session.send(raw_data)

    def receive(self, timeout=None):
        """ Read data from established socket and return raw_data """

        if self.tcp_session.data_rx_ready.acquire(timeout=timeout):
            return self.tcp_session.data_rx.pop(0)

    def listen(self, timeout=None):
        """ Wait till there is session established on listening socket """

        self.logger.debug(f"Waiting till we have established TCP connection in listening socket {self.socket_id}")

        return self.tcp_session_established.acquire(timeout=timeout)

    def accept(self):
        """ Pick up established session from listening socket and create new established socket for it """

        for session_id, session in self.tcp_sessions.items():
            if session.state == "ESTABLISHED":
                return TcpSocket(tcp_session=self.tcp_sessions.pop(session_id))

    def close(self):
        """ Close session """

        if hasattr(self, "tcp_session"):
            self.tcp_session.close()

        if hasattr(self, "tcp_sessions"):
            self.tcp_sessions.clear()
            TcpSocket.open_sockets.pop(self.socket_id)

    @staticmethod
    def match_socket(metadata):
        """ Class method - Try to match incoming packet with either established or listening socket """

        # Check if incoming packet matches any established socket
        if socket := TcpSocket.open_sockets.get(metadata.session_id, None):
            loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of established sessin {metadata.session_id}")
            socket.tcp_session.tcp_fsm(metadata=metadata)
            return True

        # Check if incoming packet is an initial SYN packet and matches any listening socket, if so create new session and assign it to that socket
        if all({metadata.flag_syn}) and not any({metadata.flag_ack, metadata.flag_fin, metadata.flag_rst}):
            for socket_id in metadata.listening_socket_ids:
                if socket := TcpSocket.open_sockets.get(socket_id, None):
                    tcp_session = TcpSession(metadata=metadata, socket=socket)
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet with SYN flag, created new session {tcp_session}")
                    socket.tcp_sessions[tcp_session.session_id] = tcp_session
                    tcp_session.listen()
                    tcp_session.tcp_fsm(metadata=metadata)
                    return True

        # Check if incoming packet matches any listening socket
        for socket_id in metadata.listening_socket_ids:
            if socket := TcpSocket.open_sockets.get(socket_id, None):
                if tcp_session := socket.tcp_sessions.get(metadata.session_id, None):
                    loguru.logger.bind(object_name="socket.").debug(f"{metadata.tracker} - TCP packet is part of existing session {tcp_session}")
                    tcp_session.tcp_fsm(metadata=metadata)
                    return True
