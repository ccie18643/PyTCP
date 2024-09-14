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


from pytcp.socket.socket import (  # noqa: F401
    AddressFamily,
    IpProto,
    ReceiveTimeout,
    Socket,
    SocketType,
    gaierror,
)

AF_INET = AddressFamily.AF_INET4
AF_INET4 = AddressFamily.AF_INET4
AF_INET6 = AddressFamily.AF_INET6

SOCK_STREAM = SocketType.SOCK_STREAM
SOCK_DGRAM = SocketType.SOCK_DGRAM

IPPROTO_IP = IpProto.IPPROTO_IP
IPPROTO_ICMP = IpProto.IPPROTO_ICMP
IPPROTO_IGMP = IpProto.IPPROTO_IGMP
IPPROTO_TCP = IpProto.IPPROTO_TCP
IPPROTO_UDP = IpProto.IPPROTO_UDP
IPPROTO_IPV6 = IpProto.IPPROTO_IPV6
IPPROTO_RAW = IpProto.IPPROTO_RAW


def socket(
    family: AddressFamily = AddressFamily.AF_INET4,
    type: SocketType = SocketType.SOCK_STREAM,
    protocol: IpProto = IpProto.IPPROTO_IP,
) -> Socket:
    """
    Return Socket class object.
    """

    from pytcp.socket.tcp__socket import TcpSocket
    from pytcp.socket.udp__socket import UdpSocket

    match type, protocol:
        case SocketType.SOCK_STREAM, IpProto.IPPROTO_IP | IpProto.IPPROTO_TCP:
            return TcpSocket(address_family=family)

        case SocketType.SOCK_DGRAM, IpProto.IPPROTO_IP | IpProto.IPPROTO_UDP:
            return UdpSocket(address_family=family)

        case SocketType.SOCK_DGRAM, IpProto.IPPROTO_ICMP:
            raise NotImplementedError

        case SocketType.SOCK_RAW, _:
            raise NotImplementedError

        case _:
            raise ValueError("Invalid socket type.")
