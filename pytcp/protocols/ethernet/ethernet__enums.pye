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
This module contains the Ethernet II enum classes.

pytcp/protocols/ethernet/ethernet__enums.py

ver 3.0.0
"""


from __future__ import annotations

from typing import override

from pytcp.lib.proto import Proto
from pytcp.lib.proto_enum import ProtoEnumWord
from pytcp.protocols.arp.arp__base import Arp
from pytcp.protocols.ip4.ip4__base import Ip4
from pytcp.protocols.ip6.ip6__base import Ip6
from pytcp.protocols.raw.raw__base import Raw


class EthernetType(ProtoEnumWord):
    """
    The Ethernet header 'type' field.
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
            case EthernetType.ARP:
                name = "ARP"
            case EthernetType.IP4:
                name = "IPv4"
            case EthernetType.IP6:
                name = "IPv6"
            case EthernetType.RAW:
                name = "Raw"

        return (
            f"0x{int(self.value):0>4x}{'' if self.is_unknown else f' ({name})'}"
        )

    @staticmethod
    def from_proto(proto: Proto) -> EthernetType:
        """
        Get the EthernetType enum from a protocol object.
        """

        if isinstance(proto, Ip6):
            return EthernetType.IP6

        if isinstance(proto, Ip4):
            return EthernetType.IP4

        if isinstance(proto, Arp):
            return EthernetType.ARP

        if isinstance(proto, Raw):
            return EthernetType.RAW

        assert False, f"Unknown protocol: {type(proto)}"
