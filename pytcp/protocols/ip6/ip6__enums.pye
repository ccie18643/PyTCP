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
This module contains the IPv6 protocol enum classes.

pytcp/protocols/ip6_common/ip6__enums.py

ver 3.0.0
"""


from __future__ import annotations

from typing import override

from pytcp.lib.proto import Proto
from pytcp.lib.proto_enum import ProtoEnumByte


class Ip6Next(ProtoEnumByte):
    """
    The IPv6 header 'next' field values.
    """

    TCP = 6
    UDP = 17
    FRAG = 44
    ICMP6 = 58
    RAW = 255

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Ip6Next.TCP:
                name = "TCP"
            case Ip6Next.UDP:
                name = "UDP"
            case Ip6Next.FRAG:
                name = "Frag"
            case Ip6Next.ICMP6:
                name = "ICMPv6"
            case Ip6Next.RAW:
                name = "Raw"

        return f"{self.value}{'' if self.is_unknown else f' ({name})'}"

    @staticmethod
    def from_proto(proto: Proto) -> Ip6Next:
        """
        Get the Ip6Next enum from a protocol object.
        """

        from pytcp.protocols.icmp6.icmp6__base import Icmp6
        from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__base import Ip6ExtFrag
        from pytcp.protocols.raw.raw__base import Raw
        from pytcp.protocols.tcp.tcp__base import Tcp
        from pytcp.protocols.udp.udp__base import Udp

        if isinstance(proto, Tcp):
            return Ip6Next.TCP

        if isinstance(proto, Udp):
            return Ip6Next.UDP

        if isinstance(proto, Icmp6):
            return Ip6Next.ICMP6

        if isinstance(proto, Ip6ExtFrag):
            return Ip6Next.FRAG

        if isinstance(proto, Raw):
            return Ip6Next.RAW

        raise ValueError(f"Unknown protocol: {type(proto)}")
