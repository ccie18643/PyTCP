#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains BSD like TCP socket interface for the stack.

pytcp/socket/tcp__socket.py

ver 3.0.2
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, cast, override

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp.lib import stack
from pytcp.lib.ip_helper import (
    is_address_in_use,
    pick_local_ip_address,
    pick_local_port,
)
from pytcp.lib.logger import log
from pytcp.socket.socket import (
    AddressFamily,
    IpProto,
    Socket,
    SocketType,
    gaierror,
)
from pytcp.socket.tcp__session import FsmState, TcpSession, TcpSessionError

if TYPE_CHECKING:
    from threading import Semaphore

    from net_addr import IpAddress
    from pytcp.socket.tcp__metadata import TcpMetadata


class TcpSocket(Socket):
    """
    Support for IPv6/IPv4 TCP socket operations.
    """

    _socket_type = SocketType.SOCK_STREAM
    _ip_proto = IpProto.IPPROTO_TCP

    def __init__(
        self,
        *,
        address_family: AddressFamily,
        tcp_session: TcpSession | None = None,
    ) -> None:
        """
        Class constructor.
        """

        self._address_family = address_family
        self._event_tcp_session_established: Semaphore = threading.Semaphore(0)
        self._tcp_accept: list[Socket] = []
        self._tcp_session: TcpSession | None

        # Create established socket based on established TCP session, called by
        # listening sockets only
        if tcp_session:
            self._tcp_session = tcp_session
            self._local_ip_address = tcp_session.local_ip_address
            self._remote_ip_address = tcp_session.remote_ip_address
            self._local_port = tcp_session.local_port
            self._remote_port = tcp_session.remote_port
            self._parent_socket = tcp_session.socket
            stack.sockets[self.id] = self

        # Fresh socket initialization
        else:
            match self._address_family:
                case AddressFamily.AF_INET6:
                    self._local_ip_address = Ip6Address()
                    self._remote_ip_address = Ip6Address()
                case AddressFamily.AF_INET4:
                    self._local_ip_address = Ip4Address()
                    self._remote_ip_address = Ip4Address()

            self._local_port = 0
            self._remote_port = 0
            self._tcp_session = None

        __debug__ and log("socket", f"<g>[{self}]</> - Create socket")

    @override
    def __str__(self) -> str:
        """
        Get TCP socket log string.
        """

        return (
            f"{self._address_family}/{self._type}/{self._ip_proto}/{self._local_ip_address}/"
            f"{self._local_port}/{self._remote_ip_address}/{self._remote_port}"
        )

    @property
    def id(self) -> tuple[Any, ...]:
        """
        Get the socket ID.
        """

        return (
            self._address_family,
            self._type,
            self._ip_proto,
            self._local_ip_address,
            self._local_port,
            self._remote_ip_address,
            self._remote_port,
        )

    @property
    def local_ip_address(self) -> IpAddress:
        """
        Get the '_local_ip_address' attribute.
        """

        return self._local_ip_address

    @property
    def remote_ip_address(self) -> IpAddress:
        """
        Get the '_remote_ip_address' attribute.
        """

        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Get the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Get the '_remote_port' attribute.
        """

        return self._remote_port

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
    def parent_socket(self) -> TcpSocket | None:
        """
        Getter for the '_parent_socket' attribute.
        """

        return self._parent_socket

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address | Ip4Address, Ip6Address | Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._address_family is AddressFamily.AF_INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror(
                "[Errno -2] Name or service not known - "
                "[Malformed remote IP address]"
            ) from error

        if remote_ip_address.is_unspecified:
            raise ConnectionRefusedError(
                "[Errno 111] Connection refused - "
                "[Unspecified remote IP address]"
            )

        if self._local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address)
            if local_ip_address.is_unspecified:
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed remote IP address]"
                )

        assert isinstance(local_ip_address, (Ip6Address, Ip4Address))

        return local_ip_address, remote_ip_address

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

        match self._address_family:
            case AddressFamily.AF_INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(
                        stack.packet_handler.ip6_unicast
                    ) | {Ip6Address()}:
                        raise OSError(
                            "[Errno 99] Cannot assign requested address - "
                            "[Local IP address not owned by stack]"
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror(
                        "[Errno -2] Name or service not known - "
                        "[Malformed local IP address]"
                    ) from error

            case AddressFamily.AF_INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(
                        stack.packet_handler.ip4_unicast
                    ) | {Ip4Address()}:
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
            if is_address_in_use(
                local_ip_address=local_ip_address,
                local_port=local_port,
                address_family=self._address_family,
                socket_type=self._type,
            ):
                raise OSError(
                    "[Errno 98] Address already in use - "
                    "[Local address already in use]"
                )
        else:
            local_port = pick_local_port()

        # Assigning local port makes socket "bound"
        stack.sockets.pop(self.id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets[self.id] = self

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
            local_port = pick_local_port()

        # Set local and remote ip addresses aproprietely
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Re-register socket with new socket id
        stack.sockets.pop(self.id, None)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets[self.id] = self

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

        stack.sockets[self.id] = self
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
        socket = cast(TcpSocket, self._tcp_accept.pop(0))

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
