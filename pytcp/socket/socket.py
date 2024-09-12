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
Module contains BSD like socket interface for the stack.

pytcp/lib/socket.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from pytcp.lib.name_enum import NameEnum

if TYPE_CHECKING:
    from net_addr import IpAddress


class gaierror(OSError):
    """
    BSD Socket error for compatibility.
    """


class ReceiveTimeout(Exception):
    """
    Timeout of receive operation.
    """


class AddressFamily(NameEnum):
    """
    Address family identifier.
    """

    AF_UNSPECIFIED = 0
    AF_INET4 = 1
    AF_INET6 = 2


class SocketType(NameEnum):
    """
    Socket type identifier.
    """

    SOCK_UNSPECIFIED = 0
    SOCK_STREAM = 1
    SOCK_DGRAM = 2
    SOCK_RAW = 3


class IpProto(NameEnum):
    """
    IP protocol identifier.
    """

    IPPROTO_UNSPECIFIED = 0
    IPPROTO_IP = 0
    IPPROTO_ICMP = 1
    IPPROTO_IGMP = 2
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17
    IPPROTO_IPV6 = 41
    IPPROTO_RAW = 255


class Socket(ABC):
    """
    Base class for all socket classes. It contains only the methods that are relevant
    for the BSD socket API. The rest of the methods and actual socket logic are
    implemented in the derived classes.
    """

    _family: AddressFamily
    _type: SocketType
    _local_ip_address: IpAddress
    _remote_ip_address: IpAddress
    _local_port: int
    _remote_port: int

    @abstractmethod
    def __str__(self) -> str:
        """
        Get socket log string.
        """

        raise NotImplementedError

    # BSD socket API methods.

    @property
    def family(self) -> AddressFamily:
        """
        Get the '_family' attribute.
        """

        return self._family

    @property
    def type(self) -> SocketType:
        """
        Get the '_type' attribute.
        """

        return self._type

    def getsockname(self) -> tuple[str, int]:
        """
        Get the local address and port.
        """

        return str(self._local_ip_address), self._local_port

    def getpeername(self) -> tuple[str, int]:
        """
        Get the remote address and port.
        """

        return str(self._remote_ip_address), self._local_port

    def bind(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'bind()' socket API method placeholder.
        """

        raise NotImplementedError

    def connect(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'connect()' socket API method placeholder.
        """

        raise NotImplementedError

    def send(
        self,
        data: bytes,
    ) -> int:
        """
        The 'send()' socket API method placeholder.
        """

        raise NotImplementedError

    def recv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """
        The 'recv()' socket API method placeholder.
        """

        raise NotImplementedError

    def close(self) -> None:
        """
        The 'close()' socket API placeholder.
        """

        raise NotImplementedError

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
