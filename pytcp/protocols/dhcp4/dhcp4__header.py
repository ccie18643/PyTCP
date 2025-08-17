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
This module contains the DHCPv4 header class.

pytcp/protocols/dhcp4/dhcp4__header.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass, field
from typing import override

from net_addr.ip4_address import Ip4Address
from net_addr.mac_address import MacAddress

from pytcp.lib.int_checks import is_uint8, is_uint16, is_uint32
from pytcp.lib.proto_struct import ProtoStruct
from pytcp.protocols.dhcp4.dhcp4__enums import (
    DHCP4__HARDWARE_LEN__ETHERNET,
    Dhcp4HardwareType,
    Dhcp4Operation,
)

# The DHCPv4 packet header (RFC 2131).

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Operation   |    HW Type    |     HW Len    |     Hops      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                     Transaction Identifier                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Seconds Elapsed       |B|          Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Client IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Your IP Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Server IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      Gateway IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                            Client                             |
# |                          HW Address                           |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                             Server                            |
# |                            Hostname                           |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                          Bootfile                             |
# |                            Name                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Magic Cookie                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__HEADER__LEN = 240
DHCP4__HEADER__STRUCT = "! BBBB L HH L L L L 16s 64s 128s 4s"
DHCP4__HEADER__MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP4__HEADER__SNAME__MAX_LEN = 64
DHCP4__HEADER__FILE__MAX_LEN = 128


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Header(ProtoStruct):
    """
    The DHCPv4 header.
    """

    oper: Dhcp4Operation
    hrtype: Dhcp4HardwareType = field(
        repr=False,
        init=False,
        default=Dhcp4HardwareType.ETHERNET,
    )
    hrlen: int = field(
        repr=False,
        init=False,
        default=DHCP4__HARDWARE_LEN__ETHERNET,
    )
    hops: int
    xid: int
    secs: int
    flag_b: bool
    ciaddr: Ip4Address
    yiaddr: Ip4Address
    siaddr: Ip4Address
    giaddr: Ip4Address
    chaddr: MacAddress
    sname: str
    file: str
    magic_cookie: bytes = field(
        repr=False,
        init=False,
        default=DHCP4__HEADER__MAGIC_COOKIE,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ARP header fields.
        """

        assert isinstance(
            self.oper, Dhcp4Operation
        ), f"The 'oper' field must be a Dhcp4Operation. Got: {type(self.oper)!r}"

        assert is_uint8(self.hops), (
            "The 'hops' field must be an 8-bit unsigned integer. "
            f"Got: {self.hops!r}"
        )

        assert is_uint32(self.xid), (
            "The 'xid' field must be a 32-bit unsigned integer. "
            f"Got: {self.xid!r}"
        )

        assert is_uint16(self.secs), (
            "The 'secs' field must be a 16-bit unsigned integer. "
            f"Got: {self.secs!r}"
        )

        assert isinstance(self.flag_b, bool), (
            "The 'flag_b' field must be a boolean. "
            f"Got: {type(self.flag_b)!r}"
        )

        assert isinstance(self.ciaddr, Ip4Address), (
            "The 'ciaddr' field must be an Ip4Address. "
            f"Got: {type(self.ciaddr)!r}"
        )

        assert isinstance(self.yiaddr, Ip4Address), (
            "The 'yiaddr' field must be an Ip4Address. "
            f"Got: {type(self.yiaddr)!r}"
        )

        assert isinstance(self.siaddr, Ip4Address), (
            "The 'siaddr' field must be an Ip4Address. "
            f"Got: {type(self.siaddr)!r}"
        )

        assert isinstance(self.giaddr, Ip4Address), (
            "The 'giaddr' field must be an Ip4Address. "
            f"Got: {type(self.giaddr)!r}"
        )

        assert isinstance(self.chaddr, MacAddress), (
            "The 'chaddr' field must be a MacAddress. "
            f"Got: {type(self.chaddr)!r}"
        )

        assert isinstance(
            self.sname, str
        ), f"The 'sname' field must be a string. Got: {type(self.sname)!r}"

        assert len(self.sname) <= DHCP4__HEADER__SNAME__MAX_LEN, (
            "The 'sname' field length must less or equal to "
            f"{DHCP4__HEADER__SNAME__MAX_LEN!r}. Got: {len(self.sname)!r}"
        )

        assert isinstance(
            self.file, str
        ), f"The 'file' field must be a string. Got: {type(self.file)!r}"

        assert len(self.file) <= DHCP4__HEADER__FILE__MAX_LEN, (
            "The 'file' field length must less or equal to "
            f"{DHCP4__HEADER__FILE__MAX_LEN!r}. Got: {len(self.file)!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ARP header length.
        """

        return DHCP4__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ARP header as bytes.
        """

        return struct.pack(
            DHCP4__HEADER__STRUCT,
            self.oper,
            self.hrtype,
            self.hrlen,
            self.hops,
            self.xid,
            self.secs,
            self.flag_b << 15,
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
            bytes(self.chaddr) + b"\0" * 10,
            bytes(self.sname, encoding="ascii")
            + b"\0" * (64 - len(self.sname)),
            bytes(self.file, encoding="ascii") + b"\0" * (128 - len(self.file)),
            self.magic_cookie,
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> Dhcp4Header:
        """
        Initialize the ARP header from bytes.
        """

        (
            oper,
            hrtype,
            hrlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            magic_cookie,
        ) = struct.unpack(DHCP4__HEADER__STRUCT, _bytes[:DHCP4__HEADER__LEN])

        assert (
            value := Dhcp4HardwareType.from_int(hrtype)
        ) == Dhcp4HardwareType.ETHERNET, (
            f"Invalid DHCPv4 hardware type. Expected: {Dhcp4HardwareType.ETHERNET!r}. "
            f"Got: {value!r}"
        )

        assert hrlen == DHCP4__HARDWARE_LEN__ETHERNET, (
            f"Invalid DHCPv4 hardware length. Expected: {DHCP4__HARDWARE_LEN__ETHERNET!r}. "
            f"Got: {hrlen!r}"
        )

        assert magic_cookie == DHCP4__HEADER__MAGIC_COOKIE, (
            f"Invalid DHCPv4 magic cookie. Expected: {DHCP4__HEADER__MAGIC_COOKIE!r}. "
            f"Got: {magic_cookie!r}"
        )

        return Dhcp4Header(
            oper=Dhcp4Operation(oper),
            hops=hops,
            xid=xid,
            secs=secs,
            flag_b=flags >> 15,
            ciaddr=Ip4Address(ciaddr),
            yiaddr=Ip4Address(yiaddr),
            siaddr=Ip4Address(siaddr),
            giaddr=Ip4Address(giaddr),
            chaddr=MacAddress(chaddr),
            sname=str(sname),
            file=str(file),
        )


class Dhcp4HeaderProperties(ABC):
    """
    Properties used to access the DHCPv4 header fields.
    """

    _header: Dhcp4Header

    @property
    def oper(self) -> Dhcp4Operation:
        """
        Get the DHCPv4 operation.
        """

        return self._header.oper

    @property
    def hrtype(self) -> Dhcp4HardwareType:
        """
        Get the DHCPv4 hardware type.
        """

        return self._header.hrtype

    @property
    def hrlen(self) -> int:
        """
        Get the DHCPv4 hardware length.
        """

        return self._header.hrlen

    @property
    def hops(self) -> int:
        """
        Get the DHCPv4 hops.
        """

        return self._header.hops

    @property
    def xid(self) -> int:
        """
        Get the DHCPv4 transaction identifier.
        """

        return self._header.xid

    @property
    def secs(self) -> int:
        """
        Get the DHCPv4 seconds elapsed.
        """

        return self._header.secs

    @property
    def flag_b(self) -> bool:
        """
        Get the DHCPv4 flag B.
        """

        return self._header.flag_b

    @property
    def ciaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 client IP address.
        """

        return self._header.ciaddr

    @property
    def yiaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 your IP address.
        """

        return self._header.yiaddr

    @property
    def siaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 server IP address.
        """

        return self._header.siaddr

    @property
    def giaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 gateway IP address.
        """

        return self._header.giaddr

    @property
    def chaddr(self) -> MacAddress:
        """
        Get the DHCPv4 client hardware address.
        """

        return self._header.chaddr

    @property
    def sname(self) -> str:
        """
        Get the DHCPv4 server hostname.
        """

        return self._header.sname

    @property
    def file(self) -> str:
        """
        Get the DHCPv4 bootfile name.
        """

        return self._header.file

    @property
    def magic_cookie(self) -> bytes:
        """
        Get the DHCPv4 magic cookie.
        """

        return DHCP4__HEADER__MAGIC_COOKIE
