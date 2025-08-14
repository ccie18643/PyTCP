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

# pylint: disable=unused-import


"""
Module contains the PyTCP socket class.

pytcp/socket/__init__.py

ver 3.0.2
"""


from pytcp.socket.socket import gaierror  # pyright: ignore[reportUnusedImport]
from pytcp.socket.socket import (  # noqa: F401
    AddressFamily,
    IpProto,
    Socket,
    SocketType,
)

AF_INET = AddressFamily.INET4
AF_INET4 = AddressFamily.INET4
AF_INET6 = AddressFamily.INET6

SOCK_STREAM = SocketType.STREAM
SOCK_DGRAM = SocketType.DGRAM
SOCK_RAW = SocketType.RAW

IPPROTO_IP = IpProto.IP4
IPPROTO_IP4 = IpProto.IP4
IPPROTO_ICMP = IpProto.ICMP4
IPPROTO_ICMP4 = IpProto.ICMP4
IPPROTO_TCP = IpProto.TCP
IPPROTO_UDP = IpProto.UDP
IPPROTO_IPV6 = IpProto.IP6
IPPROTO_IP6 = IpProto.IP6
IPPROTO_ICMPV6 = IpProto.ICMP6
IPPROTO_ICMP6 = IpProto.ICMP6
IPPROTO_RAW = IpProto.RAW


def socket(
    family: AddressFamily = AddressFamily.INET4,
    type: SocketType = SocketType.STREAM,
    protocol: IpProto | None = None,
) -> Socket:
    """
    Return Socket class object.
    """

    from pytcp.socket.raw__socket import RawSocket
    from pytcp.socket.tcp__socket import TcpSocket
    from pytcp.socket.udp__socket import UdpSocket

    match family, type, protocol:
        case _, SocketType.STREAM, None | IpProto.TCP:
            return TcpSocket(address_family=family)

        case _, SocketType.DGRAM, None | IpProto.UDP:
            return UdpSocket(address_family=family)

        case _, SocketType.DGRAM, IpProto.ICMP4 | IpProto.ICMP6:
            raise NotImplementedError

        case AddressFamily.INET4, SocketType.RAW, None:
            return RawSocket(address_family=family, ip_proto=IpProto.IP4)

        case AddressFamily.INET6, SocketType.RAW, None:
            return RawSocket(address_family=family, ip_proto=IpProto.IP6)

        case _, SocketType.RAW, _ if protocol is not None:
            return RawSocket(address_family=family, ip_proto=protocol)

        case _:
            raise ValueError("Invalid socket type.")
