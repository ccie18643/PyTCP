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
This module contains protocols related enums.

pytcp/protocols/enums.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from pytcp.lib.proto import Proto
from pytcp.lib.proto_enum import ProtoEnumByte, ProtoEnumWord


class EtherType(ProtoEnumWord):
    """
    The EtherType values.
    """

    ARP = 0x0806
    IP4 = 0x0800
    IP6 = 0x86DD
    RAW = 0xFFFF

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case EtherType.ARP:
                name = "ARP"
            case EtherType.IP4:
                name = "IPv4"
            case EtherType.IP6:
                name = "IPv6"
            case EtherType.RAW:
                name = "Raw"

        return f"0x{self.value:0>4x}" if self.is_unknown else name

    @staticmethod
    def from_proto(proto: Proto) -> EtherType:
        """
        Get the EtherType enum from a protocol object.
        """

        from pytcp.protocols.arp.arp__base import Arp
        from pytcp.protocols.ip4.ip4__base import Ip4
        from pytcp.protocols.ip6.ip6__base import Ip6
        from pytcp.protocols.raw.raw__base import Raw

        if isinstance(proto, Ip6):
            return EtherType.IP6

        if isinstance(proto, Ip4):
            return EtherType.IP4

        if isinstance(proto, Arp):
            return EtherType.ARP

        if isinstance(proto, Raw):
            return EtherType.RAW

        assert False, f"Unknown protocol: {type(proto)}"


class IpProto(ProtoEnumByte):
    """
    The IpProto values.
    """

    IP4 = 0
    ICMP4 = 1
    TCP = 6
    UDP = 17
    IP6 = 41
    IP6_FRAG = 44
    ICMP6 = 58
    RAW = 255

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case IpProto.IP4:
                name = "IPv4"
            case IpProto.ICMP4:
                name = "ICMPv4"
            case IpProto.TCP:
                name = "TCP"
            case IpProto.UDP:
                name = "UDP"
            case IpProto.IP6:
                name = "IPv6"
            case IpProto.IP6_FRAG:
                name = "IPv6_Frag"
            case IpProto.ICMP6:
                name = "ICMPv6"
            case IpProto.RAW:
                name = "Raw"

        return f"{self.value}" if self.is_unknown else name

    @staticmethod
    def from_proto(proto: Proto) -> IpProto:
        """
        Get the IpProto enum from a protocol object.
        """

        from pytcp.protocols.icmp4.icmp4__base import Icmp4
        from pytcp.protocols.icmp6.icmp6__base import Icmp6
        from pytcp.protocols.ip4.ip4__base import Ip4
        from pytcp.protocols.ip6.ip6__base import Ip6
        from pytcp.protocols.ip6_frag.ip6_frag__base import Ip6Frag
        from pytcp.protocols.raw.raw__base import Raw
        from pytcp.protocols.tcp.tcp__base import Tcp
        from pytcp.protocols.udp.udp__base import Udp

        if isinstance(proto, Ip4):
            return IpProto.IP4

        if isinstance(proto, Icmp4):
            return IpProto.ICMP4

        if isinstance(proto, Tcp):
            return IpProto.TCP

        if isinstance(proto, Udp):
            return IpProto.UDP

        if isinstance(proto, Ip6):
            return IpProto.IP4

        if isinstance(proto, Ip6Frag):
            return IpProto.IP6_FRAG

        if isinstance(proto, Icmp6):
            return IpProto.ICMP6

        if isinstance(proto, Raw):
            return IpProto.RAW

        raise ValueError(f"Unknown protocol: {type(proto)}")
