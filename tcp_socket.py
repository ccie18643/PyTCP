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

        self.logger.debug(f"Created TCP socket {self.socket_id}")

        """
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
        """

    @property
    def socket_id(self):
        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def bind(self, local_ip_address, local_port):
        """ Bind the socket to locall address """

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
        tcp_session.listen()
        stack.tcp_sessions[tcp_session.tcp_session_id] = tcp_session
        self.tcp_session_established = threading.Semaphore(0)
        self.logger.debug("{self.socket_id} =  Socket started to listen for inbound connections")

    def accept(self):
        """ Wait for the established inbound connection, then create new socket for it and return it """

        self.logger.debug(f"{self.socket_id} - Waiting for established inbound connection")
        self.tcp_session_established.acquire()
        for tcp_session_id, tcp_session in stack.tcp_sessions.items():
            if tcp_session.socket is self and tcp_session.state == "ESTABLISHED":
                return TcpSocket(tcp_session=tcp_session)

    def receive(self, timeout=None):
        """ Receive data segment from socket """

        if self.tcp_session.data_rx_ready.acquire(timeout=timeout):
            self.logger.debug(f"{self.socket_id} - Received data segment")
            return self.tcp_session.data_rx.pop(0)

    def send(self, data_segment):
        """ Pass data_segment to TCP session """

        self.tcp_session.send(data_segment)
        self.logger.debug(f"{self.socket_id} - Sent data segment")

    def close(self):
        """ Close socket and the TCP session(s) it owns """

        self.tcp_session.close()
        self.logger.debug(f"{self.socket_id} - Closed socket")

    '''
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
    '''
