#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
tcp_socket.py - module contains class supporting TCP sockets

"""

import loguru
import threading
import random

import stack

from tcp_session import TcpSession


EPHEMERAL_PORT_RANGE = (32168, 60999)


class TcpSocket:
    """ Support for Socket operations """

    def __init__(self, tcp_session=None):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        # Create established socket based on established TCP session, used by listening sockets only
        if tcp_session:
            tcp_session.socket = self
            self.tcp_session = tcp_session
            self.local_ip_address = tcp_session.local_ip_address
            self.local_port = tcp_session.local_port
            self.remote_ip_address = tcp_session.remote_ip_address
            self.remote_port = tcp_session.remote_port

        # Fresh socket initialization
        else:
            self.local_ip_address = None
            self.local_port = None
            self.remote_ip_address = None
            self.remote_port = None

        self.event_tcp_session_established = threading.Semaphore(0)

        self.logger.debug(f"Created TCP socket {self.socket_id}")

    def __pick_random_local_port(self):
        """ Pick random local port, making sure it is not already being used by any socket """

        used_ports = {int(_.split("/")[2]) for _ in stack.tcp_sessions if _.split("/")[1] in {"0.0.0.0", self.local_ip_address}}
        while (port := random.randint(*EPHEMERAL_PORT_RANGE)) not in used_ports:
            return port

    @property
    def socket_id(self):
        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def bind(self, local_ip_address, local_port):
        """ Bind the socket to local address """

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.logger.debug(f"{self.socket_id} - Socket bound to local address")

    def listen(self):
        """ Starts to listen for incomming connections """

        self.remote_ip_address = "0.0.0.0"
        self.remote_port = 0
        tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port,
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )
        stack.tcp_sessions[tcp_session.tcp_session_id] = tcp_session
        self.logger.debug(f"{self.socket_id} -  Socket starting to listen for inbound connections")
        tcp_session.listen()

    def connect(self, remote_ip_address, remote_port):
        """ Attempt to establish TCP connection """

        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port if self.local_port else self.__pick_random_local_port(),
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )
        self.tcp_session = tcp_session
        stack.tcp_sessions[tcp_session.tcp_session_id] = tcp_session
        self.logger.debug(f"{self.socket_id} -  Socket attempting connection to {remote_ip_address}:{remote_port}")
        return tcp_session.connect()

    def accept(self):
        """ Wait for the established inbound connection, then create new socket for it and return it """

        self.logger.debug(f"{self.socket_id} - Waiting for established inbound connection")
        self.event_tcp_session_established.acquire()
        for tcp_session_id, tcp_session in stack.tcp_sessions.items():
            if tcp_session.socket is self and tcp_session.state == "ESTABLISHED":
                return TcpSocket(tcp_session=tcp_session)

    def receive(self, byte_count=None):
        """ Receive data from socket """

        if (data_rx := self.tcp_session.receive(byte_count)) is None:
            self.logger.debug(f"{self.socket_id} - Received close event from TCP session")
            return None

        self.logger.debug(f"{self.socket_id} - Received {len(data_rx)} bytes of data")
        return data_rx

    def send(self, data_segment):
        """ Pass data_segment to TCP session """

        if bytes_sent := self.tcp_session.send(data_segment):
            self.logger.debug(f"{self.socket_id} - Sent data segment, len {bytes_sent}")
            return bytes_sent

    def close(self):
        """ Close socket and the TCP session(s) it owns """

        self.tcp_session.close()
        self.logger.debug(f"{self.socket_id} - Closed socket")
