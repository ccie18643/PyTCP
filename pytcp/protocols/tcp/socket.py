#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = expression-not-assigned
# pylint: disable = too-many-instance-attributes
# pylint: disable = fixme

"""
Module contains BSD like socket interface for the stack.

pytcp/protocols/tcp/socket.py

ver 2.7
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address, Ip4AddressFormatError
from pytcp.lib.ip6_address import Ip6Address, Ip6AddressFormatError
from pytcp.lib.logger import log
from pytcp.lib.socket import AF_INET4, AF_INET6, SOCK_STREAM, Socket, gaierror
from pytcp.protocols.tcp.session import FsmState, TcpSession, TcpSessionError

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.lib.socket import AddressFamily, IpAddress, SocketType
    from pytcp.protocols.tcp.metadata import TcpMetadata


class TcpSocket(Socket):
    """
    Support for IPv6/IPv4 TCP socket operations.
    """

    def __init__(
        self, family: AddressFamily, tcp_session: TcpSession | None = None
    ) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._family: AddressFamily = family
        self._type: SocketType = SOCK_STREAM
        self._event_tcp_session_established: Semaphore = threading.Semaphore(0)
        self._tcp_accept: list[Socket] = []
        self._tcp_session: TcpSession | None
        self._local_ip_address: IpAddress
        self._remote_ip_address: IpAddress
        self._local_port: int
        self._remote_port: int
        self._parent_socket: Socket

        # Create established socket based on established TCP session, called by
        # listening sockets only
        if tcp_session:
            self._tcp_session = tcp_session
            self._local_ip_address = tcp_session.local_ip_address
            self._remote_ip_address = tcp_session.remote_ip_address
            self._local_port = tcp_session.local_port
            self._remote_port = tcp_session.remote_port
            self._parent_socket = tcp_session.socket
            stack.sockets[str(self)] = self

        # Fresh socket initialization
        else:
            if self._family is AF_INET6:
                self._local_ip_address = Ip6Address(0)
                self._remote_ip_address = Ip6Address(0)
            if self._family is AF_INET4:
                self._local_ip_address = Ip4Address(0)
                self._remote_ip_address = Ip4Address(0)
            self._local_port = 0
            self._remote_port = 0
            self._tcp_session = None

        __debug__ and log("socket", f"<g>[{self}]</> - Create socket")

    @property
    def state(self) -> FsmState:
        """
        Return FSM state of associated TCP session.
        """
        if self.tcp_session is not None:
            return self.tcp_session.state
        return FsmState.CLOSED

    @property
    def tcp_session(self) -> TcpSession | None:
        """
        Getter for the '_tcp_session' attribute.
        """
        return self._tcp_session

    @property
    def parent_socket(self) -> Socket | None:
        """
        Getter for the '_parent_socket' attribute.
        """
        return self._parent_socket

    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address and specific local port in case provided port equals zero
        # port value will be picked automatically.

        # Check if "bound" already
        if self._local_port in range(1, 65536):
            raise OSError(
                "[Errno 22] Invalid argument - "
                "[Socket bound to specific port already]"
            )

        local_ip_address: IpAddress

        if self._family is AF_INET6:
            try:
                if (local_ip_address := Ip6Address(address[0])) not in set(
                    stack.packet_handler.ip6_unicast
                ) | {Ip6Address(0)}:
                    raise OSError(
                        "[Errno 99] Cannot assign requested address - "
                        "[Local IP address not owned by stack]"
                    )
            except Ip6AddressFormatError as error:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed local IP address]"
                ) from error

        if self._family is AF_INET4:
            try:
                if (local_ip_address := Ip4Address(address[0])) not in set(
                    stack.packet_handler.ip4_unicast
                ) | {Ip4Address(0)}:
                    raise OSError(
                        "[Errno 99] Cannot assign requested address - "
                        "[Local IP address not owned by stack]"
                    )
            except Ip4AddressFormatError as error:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed local IP address]"
                ) from error

        # Sanity check on local port number
        if address[1] not in range(0, 65536):
            raise OverflowError(
                "bind(): port must be 0-65535. - [Port out of range]"
            )

        # Confirm or pick local port number
        if (local_port := address[1]) > 0:
            if self._is_address_in_use(local_ip_address, local_port):
                raise OSError(
                    "[Errno 98] Address already in use - "
                    "[Local address already in use]"
                )
        else:
            local_port = self._pick_local_port()

        # Assigning local port makes socket "bound"
        stack.sockets.pop(str(self), None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets[str(self)] = self

        __debug__ and log("socket", f"<g>[{self}]</> - Bound socket")

    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect local socket to remote socket.
        """

        # The 'connect' call will bind socket to specific local ip address
        # (will rebind if necessary), specific local port, specific remote
        # IP address and specific remote port.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError(
                "connect(): port must be 0-65535. - [Port out of range]"
            )

        # Assigning local port makes socket "bound" if not "bound" already
        if (local_port := self._local_port) not in range(1, 65536):
            local_port = self._pick_local_port()

        # Set local and remote ip addresses appropriately
        local_ip_address, remote_ip_address = self._set_ip_addresses(
            address, self._local_ip_address, local_port, remote_port
        )

        # Re-register socket with new socket id
        stack.sockets.pop(str(self), None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[str(self)] = self

        self._tcp_session = TcpSession(
            local_ip_address=self._local_ip_address,
            local_port=self._local_port,
            remote_ip_address=self._remote_ip_address,
            remote_port=self._remote_port,
            socket=self,
        )

        __debug__ and log(
            "socket", f"<g>[{self}]</> - Socket attempting connection"
        )

        try:
            self._tcp_session.connect()
        except TcpSessionError as error:
            if str(error) == "Connection refused":
                raise ConnectionRefusedError(
                    "[Errno 111] Connection refused - "
                    "[Received RST packet from remote host]"
                ) from error
            if str(error) == "Connection timeout":
                raise TimeoutError(
                    "[Errno 110] Connection timed out - "
                    "[No valid response received from remote host]"
                ) from error

        __debug__ and log("socket", f"<g>[{self}]</> - Bound")

    def listen(self) -> None:
        """
        Starts to listen for incoming connections.
        """

        self._tcp_session = TcpSession(
            local_ip_address=self._local_ip_address,
            local_port=self._local_port,
            remote_ip_address=self._remote_ip_address,
            remote_port=self._remote_port,
            socket=self,
        )

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Socket starting to listen for inbound "
            "connections",
        )

        stack.sockets[str(self)] = self
        self._tcp_session.listen()

    def accept(self) -> tuple[Socket, tuple[str, int]]:
        """
        Wait for the established inbound connection, once available return
        it's socket.
        """

        __debug__ and log(
            "socket", f"<g>[{self}]</> - Waiting for inbound connection"
        )

        self._event_tcp_session_established.acquire()
        socket = self._tcp_accept.pop(0)

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Socket accepted connection from "
            f"{(str(socket.remote_ip_address), socket.remote_port)}",
        )

        return socket, (str(socket.remote_ip_address), socket.remote_port)

    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.

        if self._remote_ip_address.is_unspecified or self._remote_port == 0:
            raise OSError("send(): Destination address require")

        assert self._tcp_session is not None

        try:
            bytes_sent = self._tcp_session.send(data)
        except TcpSessionError as error:
            raise BrokenPipeError(
                f"[Errno 32] Broken pipe - [{error}]"
            ) from error

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Sent data segment, len {bytes_sent}",
        )
        return bytes_sent

    def recv(
        self, bufsize: int | None = None, timeout: float | None = None
    ) -> bytes:
        """
        Receive data from socket.
        """

        # TODO - Consider implementing timeout

        assert self._tcp_session is not None

        if data_rx := self._tcp_session.receive(bufsize):
            __debug__ and log(
                "socket",
                f"<g>[{self}]</> - Received {len(data_rx)} bytes of data",
            )
        else:
            __debug__ and log(
                "socket",
                f"<g>[{self}]</> - Received empty data byte string, remote "
                "end closed connection",
            )

        return data_rx

    def close(self) -> None:
        """
        Close socket and the TCP session(s) it owns.
        """
        assert self._tcp_session is not None
        self._tcp_session.close()
        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def process_tcp_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process incoming packet's metadata.
        """
        if self._tcp_session:
            self._tcp_session.tcp_fsm(packet_rx_md)
