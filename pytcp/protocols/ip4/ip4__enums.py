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
This module contains the IPv4 packet enum classes.

pytcp/protocols/ip4/ip4__enums.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from pytcp.lib.proto import Proto
from pytcp.lib.proto_enum import ProtoEnumByte
from pytcp.protocols.icmp4.icmp4__base import Icmp4
from pytcp.protocols.raw.raw__base import Raw
from pytcp.protocols.tcp.tcp__base import Tcp
from pytcp.protocols.udp.udp__base import Udp


class Ip4Proto(ProtoEnumByte):
    """
    The IPv4 header 'proto' field values.
    """

    ICMP4 = 1
    TCP = 6
    UDP = 17
    RAW = 255

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Ip4Proto.ICMP4:
                name = "ICMPv4"
            case Ip4Proto.TCP:
                name = "TCP"
            case Ip4Proto.UDP:
                name = "UDP"
            case Ip4Proto.RAW:
                name = "Raw"

        return f"{self.value}{'' if self.is_unknown else f' ({name})'}"

    @staticmethod
    def from_proto(proto: Proto) -> Ip4Proto:
        """
        Get the Ip4Proto enum from a protocol object.
        """

        if isinstance(proto, Tcp):
            return Ip4Proto.TCP

        if isinstance(proto, Udp):
            return Ip4Proto.UDP

        if isinstance(proto, Icmp4):
            return Ip4Proto.ICMP4

        if isinstance(proto, Raw):
            return Ip4Proto.RAW

        raise ValueError(f"Unknown protocol: {type(proto)}")
