#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# tcp_socket.py - module contains class supporting TCP sockets
#


import random
import threading

import loguru

import stack
from tcp_session_alt import TcpSession


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

    @property
    def socket_id(self):
        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def bind(self, local_ip_address, local_port=None):
        """ Bind the socket to local address and port """

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.logger.debug(f"{self.socket_id} - Socket bound to local address")

    def listen(self):
        """ Starts to listen for incomming connections """

        self.remote_ip_address = "*"
        self.remote_port = "*"
        tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port,
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )
        self.logger.debug(f"{self.socket_id} -  Socket starting to listen for inbound connections")
        tcp_session.listen()

    def connect(self, remote_ip_address, remote_port):
        """ Attempt to establish TCP connection """

        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        tcp_session = TcpSession(
            local_ip_address=self.local_ip_address,
            local_port=self.local_port,
            remote_ip_address=self.remote_ip_address,
            remote_port=self.remote_port,
            socket=self,
        )
        self.tcp_session = tcp_session
        self.logger.debug(f"{self.socket_id} -  Socket attempting connection to {remote_ip_address}, port {remote_port}")
        return tcp_session.connect()

    def accept(self):
        """ Wait for the established inbound connection, then create new socket for it and return it """

        self.logger.debug(f"{self.socket_id} - Waiting for established inbound connection")
        self.event_tcp_session_established.acquire()
        for tcp_session in stack.tcp_sessions.values():
            if tcp_session.socket is self and tcp_session.state == "ESTABLISHED":
                return TcpSocket(tcp_session=tcp_session)
        return None

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
        return None

    def close(self):
        """ Close socket and the TCP session(s) it owns """

        self.tcp_session.close()
        self.logger.debug(f"{self.socket_id} - Closed socket")
