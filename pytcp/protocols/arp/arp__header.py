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
This module contains the ARP packet header class.

pytcp/protocols/arp/arp__header.py

ver 3.0.3
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass, field
from typing import override

from net_addr import Ip4Address, MacAddress
from pytcp.lib.proto_struct import ProtoStruct
from pytcp.protocols.arp.arp__enums import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__PROTOCOL_LEN__IP4,
    ArpHardwareType,
    ArpOperation,
)
from pytcp.protocols.enums import EtherType

# The ARP packet header [RFC 826].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Hardware type         |         Protocol type         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hw length   |  Proto length |           Operation           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +        Sender MAC address     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |       Sender IP address       >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Target MAC address      |
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Target IP address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ARP__HEADER__LEN = 28
ARP__HEADER__STRUCT = "! HH BBH 6s L 6s L"


@dataclass(frozen=True, kw_only=True, slots=True)
class ArpHeader(ProtoStruct):
    """
    The ARP packet header.
    """

    hrtype: ArpHardwareType = field(
        repr=False,
        init=False,
        default=ArpHardwareType.ETHERNET,
    )
    prtype: EtherType = field(
        repr=False,
        init=False,
        default=EtherType.IP4,
    )
    hrlen: int = field(
        repr=False,
        init=False,
        default=ARP__HARDWARE_LEN__ETHERNET,
    )
    prlen: int = field(
        repr=False,
        init=False,
        default=ARP__PROTOCOL_LEN__IP4,
    )
    oper: ArpOperation
    sha: MacAddress
    spa: Ip4Address
    tha: MacAddress
    tpa: Ip4Address

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ARP header fields.
        """

        assert isinstance(
            self.oper, ArpOperation
        ), f"The 'oper' field must be an ArpOperation. Got: {type(self.oper)!r}"

        assert isinstance(
            self.sha, MacAddress
        ), f"The 'sha' field must be a MacAddress. Got: {type(self.sha)!r}"

        assert isinstance(
            self.spa, Ip4Address
        ), f"The 'spa' field must be an Ip4Address. Got: {type(self.spa)!r}"

        assert isinstance(
            self.tha, MacAddress
        ), f"The 'tha' field must be a MacAddress. Got: {type(self.tha)!r}"

        assert isinstance(
            self.tpa, Ip4Address
        ), f"The 'tpa' field must be an Ip4Address. Got: {type(self.tpa)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ARP header length.
        """

        return ARP__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ARP header as bytes.
        """

        return struct.pack(
            ARP__HEADER__STRUCT,
            int(self.hrtype),
            int(self.prtype),
            self.hrlen,
            self.prlen,
            int(self.oper),
            bytes(self.sha),
            int(self.spa),
            bytes(self.tha),
            int(self.tpa),
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> ArpHeader:
        """
        Initialize the ARP header from bytes.
        """

        _, _, _, _, oper, sha, spa, tha, tpa = struct.unpack(
            ARP__HEADER__STRUCT, _bytes[:ARP__HEADER__LEN]
        )

        return ArpHeader(
            oper=ArpOperation.from_int(oper),
            sha=MacAddress(sha),
            spa=Ip4Address(spa),
            tha=MacAddress(tha),
            tpa=Ip4Address(tpa),
        )


class ArpHeaderProperties(ABC):
    """
    Properties used to access ARP header fields.
    """

    _header: ArpHeader

    @property
    def hrtype(self) -> ArpHardwareType:
        """
        Get the ARP header 'hrtype' field.
        """

        return self._header.hrtype

    @property
    def prtype(self) -> EtherType:
        """
        Get the ARP header 'prtype' field.
        """

        return self._header.prtype

    @property
    def hrlen(self) -> int:
        """
        Get the ARP header 'hrlen' field.
        """

        return self._header.hrlen

    @property
    def prlen(self) -> int:
        """
        Get the ARP header 'prlen' field.
        """

        return self._header.prlen

    @property
    def oper(self) -> ArpOperation:
        """
        Get the ARP header 'oper' field.
        """

        return self._header.oper

    @property
    def sha(self) -> MacAddress:
        """
        Get the ARP header 'sha' field.
        """

        return self._header.sha

    @property
    def spa(self) -> Ip4Address:
        """
        Get the ARP header 'spa' field.
        """

        return self._header.spa

    @property
    def tha(self) -> MacAddress:
        """
        Get the ARP header 'tha' field.
        """

        return self._header.tha

    @property
    def tpa(self) -> Ip4Address:
        """
        Get the ARP header 'tpa' field.
        """

        return self._header.tpa
