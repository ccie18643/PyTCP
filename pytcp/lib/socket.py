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

# pylint: disable=invalid-name
# pylint: disable=redefined-builtin
# pylint: disable=import-outside-toplevel
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-public-methods
# pylint: disable=protected-access
# pylint: disable=too-many-boolean-expressions

"""
Module contains BSD like socket interface for the stack.

pytcp/lib/socket.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.ip_helper import pick_local_ip_address
from pytcp.lib.net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp.protocols.tcp.tcp__metadata import TcpMetadata
from pytcp.protocols.tcp.tcp__session import FsmState, TcpSession
from pytcp.protocols.udp.udp__metadata import UdpMetadata

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.lib.net_addr import IpAddress


class gaierror(OSError):
    """
    BSD Socket's error for compatibility.
    """


class ReceiveTimeout(Exception):
    """
    Timeout of receive operation.
    """


class AddressFamily(IntEnum):
    """
    Address family identifier enum.
    """

    AF_UNSPECIFIED = 0
    AF_INET4 = 1
    AF_INET6 = 2

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return str(self.name)


AF_INET = AddressFamily.AF_INET4
AF_INET4 = AddressFamily.AF_INET4
AF_INET6 = AddressFamily.AF_INET6


class SocketType(IntEnum):
    """
    Socket type identifier enum.
    """

    SOCK_UNSPECIFIED = 0
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return str(self.name)


SOCK_STREAM = SocketType.SOCK_STREAM
SOCK_DGRAM = SocketType.SOCK_DGRAM


class IpProto(IntEnum):
    """
    IP protocol identifier enum.
    """

    IPPROTO_UNSPECIFIED = 0
    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_IGMP = 2
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17
    IPPROTO_IPV6 = 41
    IPPROTO_RAW = 255

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return str(self.name)


IPPROTO_IP = IpProto.IPPROTO_IP
IPPROTO_ICMP = IpProto.IPPROTO_ICMP
IPPROTO_IGMP = IpProto.IPPROTO_IGMP
IPPROTO_TCP = IpProto.IPPROTO_TCP
IPPROTO_UDP = IpProto.IPPROTO_UDP
IPPROTO_IPV6 = IpProto.IPPROTO_IPV6
IPPROTO_RAW = IpProto.IPPROTO_RAW


def socket(
    family: AddressFamily = AF_INET4,
    type: SocketType = SOCK_STREAM,
    protocol: IpProto = IPPROTO_IP,
) -> Socket:
    """
    Return Socket class object.
    """

    from pytcp.protocols.tcp.tcp__socket import TcpSocket
    from pytcp.protocols.udp.udp__socket import UdpSocket

    match type, protocol:
        case SocketType.SOCK_STREAM, IpProto.IPPROTO_IP | IpProto.IPPROTO_TCP:
            return TcpSocket(family=family)
        case SocketType.SOCK_DGRAM, IpProto.IPPROTO_IP | IpProto.IPPROTO_UDP:
            return UdpSocket(family=family)
        case SocketType.SOCK_DGRAM, IpProto.IPPROTO_ICMP:
            raise NotImplementedError
        case SocketType.SOCK_RAW, _:
            raise NotImplementedError
        case _:
            raise ValueError("Invalid socket type.")


class Socket(ABC):
    """
    Base class for other socket classes.
    """

    _family: AddressFamily
    _type: SocketType
    _local_ip_address: IpAddress
    _remote_ip_address: IpAddress
    _local_port: int
    _remote_port: int
    _parent_socket: Socket
    _tcp_session: TcpSession | None
    _tcp_accept: list[Socket]
    _event_tcp_session_established: Semaphore
    _unreachable: bool

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return (
            f"{self._family}/{self._type}/{self._local_ip_address}/"
            f"{self._local_port}/{self._remote_ip_address}/{self._remote_port}"
        )

    @property
    def family(self) -> AddressFamily:
        """
        Getter for the '_family' attribute.
        """

        return self._family

    @property
    def type(self) -> SocketType:
        """
        Getter for the '_type' attribute.
        """

        return self._type

    @property
    def local_ip_address(self) -> IpAddress:
        """
        Getter for the '_local_ip_address' attribute.
        """

        return self._local_ip_address

    @property
    def remote_ip_address(self) -> IpAddress:
        """
        Getter for the '_remote_ip_address' attribute.
        """

        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Getter for the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Getter for the '_remote_port' attribute.
        """

        return self._remote_port

    def _pick_local_port(self) -> int:
        """
        Pick ephemeral local port, making sure it is not already being used
        by any socket.
        """

        available_ephemeral_ports = set(config.EPHEMERAL_PORT_RANGE) - {
            int(_.split("/")[3]) for _ in stack.sockets
        }

        if len(available_ephemeral_ports):
            return available_ephemeral_ports.pop()

        raise OSError(
            "[Errno 98] Address already in use - [Unable to find free "
            "local ephemeral port]"
        )

    def _is_address_in_use(
        self,
        *,
        local_ip_address: IpAddress,
        local_port: int,
    ) -> bool:
        """
        Check if IP address / port combination is already in use.
        """

        for opened_socket in stack.sockets.values():
            if (
                opened_socket.family == self._family
                and opened_socket._type == self._type
                and (
                    (
                        opened_socket._local_ip_address.is_unspecified
                        or opened_socket._local_ip_address == local_ip_address
                    )
                    or local_ip_address.is_unspecified
                )
                and opened_socket._local_port == local_port
            ):
                return True

        return False

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
        local_ip_address: IpAddress,
        local_port: int,
    ) -> tuple[Ip6Address | Ip4Address, Ip6Address | Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._family is AF_INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror(
                "[Errno -2] Name or service not known - "
                "[Malformed remote IP address]"
            ) from error

        # This contraption here is to mimic behavior
        # of BSD socket implementation.
        if remote_ip_address.is_unspecified:
            if self._type is SOCK_STREAM:
                raise ConnectionRefusedError(
                    "[Errno 111] Connection refused - "
                    "[Unspecified remote IP address]"
                )
            if self._type is SOCK_DGRAM:
                self._unreachable = True

        if local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address)
            if local_ip_address.is_unspecified and not (
                local_port == 68 and remote_address[1] == 67
            ):
                raise gaierror(
                    "[Errno -2] Name or service not known - "
                    "[Malformed remote IP address]"
                )

        assert isinstance(local_ip_address, (Ip6Address, Ip4Address))

        return local_ip_address, remote_ip_address

    @abstractmethod
    def bind(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'bind()' socket API method placeholder.
        """

        raise NotImplementedError

    @abstractmethod
    def connect(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'connect()' socket API method placeholder.
        """

        raise NotImplementedError

    @abstractmethod
    def send(
        self,
        data: bytes,
    ) -> int:
        """
        The 'send()' socket API method placeholder.
        """

        raise NotImplementedError

    @abstractmethod
    def recv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """
        The 'recv()' socket API method placeholder.
        """

        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """
        The 'close()' socket API placeholder.
        """

        raise NotImplementedError

    if TYPE_CHECKING:

        def listen(self) -> None:
            """
            The 'listen()' socket API placeholder.
            """

            raise NotImplementedError

        def accept(self) -> tuple[Socket, tuple[str, int]]:
            """
            The 'accept()' socket API placeholder.
            """

            raise NotImplementedError

        def sendto(self, data: bytes, address: tuple[str, int]) -> int:
            """
            The 'sendto()' socket API placeholder.
            """

            raise NotImplementedError

        def recvfrom(
            self,
            bufsize: int | None = None,
            timeout: float | None = None,
        ) -> tuple[bytes, tuple[str, int]]:
            """
            The 'recvfrom()' socket API placeholder.
            """

            raise NotImplementedError

        def process_udp_packet(self, packet_rx_md: UdpMetadata) -> None:
            """
            The 'process_udp_packet()' method plceholder.
            """

            raise NotImplementedError

        def process_tcp_packet(self, packet_rx_md: TcpMetadata) -> None:
            """
            The 'process_tcp_packet()' method plceholder.
            """
            raise NotImplementedError

        def notify_unreachable(self) -> None:
            """
            The 'notify_unreachable()' method plceholder.
            """

            raise NotImplementedError

        @property
        def tcp_session(self) -> TcpSession | None:
            """
            The 'tcp_session' property plceholder.
            """

            raise NotImplementedError

        @property
        def state(self) -> FsmState:
            """
            The 'state' property plceholder.
            """

            raise NotImplementedError

        @property
        def parent_socket(self) -> Socket | None:
            """
            The 'parent_socket' property plceholder.
            """

            raise NotImplementedError
