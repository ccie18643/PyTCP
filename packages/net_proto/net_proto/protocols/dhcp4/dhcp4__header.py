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

net_proto/protocols/dhcp4/dhcp4__header.py

ver 3.0.8
"""

import struct
from abc import ABC
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Address, MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint8, is_uint16, is_uint32
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.dhcp4.dhcp4__enums import (
    DHCP4__HARDWARE_LEN__ETHERNET,
    Dhcp4HardwareType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError

# The DHCPv4 packet header [RFC 2131].

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
DHCP4__HEADER__CHADDR__MAX_LEN = 16
DHCP4__HEADER__SNAME__MAX_LEN = 64
DHCP4__HEADER__FILE__MAX_LEN = 128


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Header(ProtoStruct):
    """
    The DHCPv4 header.
    """

    operation: Dhcp4Operation
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
        Ensure integrity of the DHCPv4 header fields.
        """

        assert isinstance(
            self.operation, Dhcp4Operation
        ), f"The 'operation' field must be a Dhcp4Operation. Got: {type(self.operation)!r}"

        assert is_uint8(self.hops), f"The 'hops' field must be an 8-bit unsigned integer. Got: {self.hops!r}"

        assert is_uint32(self.xid), f"The 'xid' field must be a 32-bit unsigned integer. Got: {self.xid!r}"

        assert is_uint16(self.secs), f"The 'secs' field must be a 16-bit unsigned integer. Got: {self.secs!r}"

        assert isinstance(self.flag_b, bool), f"The 'flag_b' field must be a boolean. Got: {type(self.flag_b)!r}"

        assert isinstance(
            self.ciaddr, Ip4Address
        ), f"The 'ciaddr' field must be an Ip4Address. Got: {type(self.ciaddr)!r}"

        assert isinstance(
            self.yiaddr, Ip4Address
        ), f"The 'yiaddr' field must be an Ip4Address. Got: {type(self.yiaddr)!r}"

        assert isinstance(
            self.siaddr, Ip4Address
        ), f"The 'siaddr' field must be an Ip4Address. Got: {type(self.siaddr)!r}"

        assert isinstance(
            self.giaddr, Ip4Address
        ), f"The 'giaddr' field must be an Ip4Address. Got: {type(self.giaddr)!r}"

        assert isinstance(
            self.chaddr, MacAddress
        ), f"The 'chaddr' field must be a MacAddress. Got: {type(self.chaddr)!r}"

        assert isinstance(self.sname, str), f"The 'sname' field must be a string. Got: {type(self.sname)!r}"

        assert len(self.sname) <= DHCP4__HEADER__SNAME__MAX_LEN, (
            f"The 'sname' field length must be less than or equal to "
            f"{DHCP4__HEADER__SNAME__MAX_LEN!r}. Got: {len(self.sname)!r}"
        )

        assert isinstance(self.file, str), f"The 'file' field must be a string. Got: {type(self.file)!r}"

        assert len(self.file) <= DHCP4__HEADER__FILE__MAX_LEN, (
            f"The 'file' field length must be less than or equal to "
            f"{DHCP4__HEADER__FILE__MAX_LEN!r}. Got: {len(self.file)!r}"
        )

        # NB: an `isascii()` check on 'sname' / 'file' is deliberately
        # NOT enforced here. The parser path uses
        # `bytes.decode("ascii", errors="replace")` to tolerantly
        # decode arbitrary wire bytes (RFC 2132 §9.3 Option Overload
        # stuffs option bytes into these BOOTP fields), which
        # produces `�` replacement chars. A non-ASCII assert on
        # this dataclass would break RX. The strict-ASCII requirement
        # is enforced at the TX boundary — `Dhcp4Assembler.__init__`.

    @override
    def __len__(self) -> int:
        """
        Get the DHCPv4 header length.
        """

        return DHCP4__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 header as a memoryview.
        """

        struct.pack_into(
            DHCP4__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.operation),
            int(self.hrtype),
            self.hrlen,
            self.hops,
            self.xid,
            self.secs,
            self.flag_b << 15,
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
            bytes(self.chaddr) + b"\0" * (DHCP4__HEADER__CHADDR__MAX_LEN - DHCP4__HARDWARE_LEN__ETHERNET),
            bytes(self.sname, encoding="ascii") + b"\0" * (DHCP4__HEADER__SNAME__MAX_LEN - len(self.sname)),
            bytes(self.file, encoding="ascii") + b"\0" * (DHCP4__HEADER__FILE__MAX_LEN - len(self.file)),
            self.magic_cookie,
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 header from buffer.
        """

        (
            operation,
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
        ) = struct.unpack(DHCP4__HEADER__STRUCT, buffer[:DHCP4__HEADER__LEN])

        if (value := Dhcp4HardwareType.from_int(hrtype)) != Dhcp4HardwareType.ETHERNET:
            raise Dhcp4IntegrityError(
                f"Invalid DHCPv4 hardware type. Expected: {Dhcp4HardwareType.ETHERNET!r}. Got: {value!r}"
            )

        if hrlen != DHCP4__HARDWARE_LEN__ETHERNET:
            raise Dhcp4IntegrityError(
                f"Invalid DHCPv4 hardware length. Expected: {DHCP4__HARDWARE_LEN__ETHERNET!r}. Got: {hrlen!r}"
            )

        if magic_cookie != DHCP4__HEADER__MAGIC_COOKIE:
            raise Dhcp4IntegrityError(
                f"Invalid DHCPv4 magic cookie. Expected: {DHCP4__HEADER__MAGIC_COOKIE!r}. Got: {magic_cookie!r}"
            )

        return cls(
            # Use the tolerant 'from_int' so an unknown wire 'op' value is
            # materialised as UNKNOWN_n rather than raising ValueError out
            # of '_parse'; the parser's '_validate_sanity' rejects unknowns
            # under RFC 951 §8 / RFC 2131 §2 (only 1=REQUEST, 2=REPLY).
            operation=Dhcp4Operation.from_int(operation),
            hops=hops,
            xid=xid,
            secs=secs,
            flag_b=bool(flags >> 15),
            ciaddr=Ip4Address(ciaddr),
            yiaddr=Ip4Address(yiaddr),
            siaddr=Ip4Address(siaddr),
            giaddr=Ip4Address(giaddr),
            chaddr=MacAddress(chaddr[:6]),
            # Use 'errors="replace"' so an inbound packet whose sname /
            # file carry non-ASCII bytes (e.g. an RFC 2132 §9.3 Option
            # Overload payload) still parses; the parser layer
            # re-extracts the raw bytes from the frame when overload is
            # signalled.
            sname=sname.rstrip(b"\x00").decode("ascii", errors="replace"),
            file=file.rstrip(b"\x00").decode("ascii", errors="replace"),
        )


class Dhcp4HeaderProperties(ABC):
    """
    Properties used to access the DHCPv4 header fields.
    """

    _header: Dhcp4Header

    @property
    def operation(self) -> Dhcp4Operation:
        """
        Get the DHCPv4 header 'operation' field.
        """

        return self._header.operation

    @property
    def hrtype(self) -> Dhcp4HardwareType:
        """
        Get the DHCPv4 header 'hrtype' field.
        """

        return self._header.hrtype

    @property
    def hrlen(self) -> int:
        """
        Get the DHCPv4 header 'hrlen' field.
        """

        return self._header.hrlen

    @property
    def hops(self) -> int:
        """
        Get the DHCPv4 header 'hops' field.
        """

        return self._header.hops

    @property
    def xid(self) -> int:
        """
        Get the DHCPv4 header 'xid' field.
        """

        return self._header.xid

    @property
    def secs(self) -> int:
        """
        Get the DHCPv4 header 'secs' field.
        """

        return self._header.secs

    @property
    def flag_b(self) -> bool:
        """
        Get the DHCPv4 header 'flag_b' field.
        """

        return self._header.flag_b

    @property
    def ciaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 header 'ciaddr' field.
        """

        return self._header.ciaddr

    @property
    def yiaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 header 'yiaddr' field.
        """

        return self._header.yiaddr

    @property
    def siaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 header 'siaddr' field.
        """

        return self._header.siaddr

    @property
    def giaddr(self) -> Ip4Address:
        """
        Get the DHCPv4 header 'giaddr' field.
        """

        return self._header.giaddr

    @property
    def chaddr(self) -> MacAddress:
        """
        Get the DHCPv4 header 'chaddr' field.
        """

        return self._header.chaddr

    @property
    def sname(self) -> str:
        """
        Get the DHCPv4 header 'sname' field.
        """

        return self._header.sname

    @property
    def file(self) -> str:
        """
        Get the DHCPv4 header 'file' field.
        """

        return self._header.file

    @property
    def magic_cookie(self) -> bytes:
        """
        Get the DHCPv4 header 'magic_cookie' field.
        """

        return self._header.magic_cookie
