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
This module contains the DNS header class.

net_proto/protocols/dns/dns__header.py

ver 3.0.8
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.lib.proto_struct import ProtoStruct
from net_proto.protocols.dns.dns__enums import DnsOpcode, DnsResponseCode

# The DNS message header [RFC 1035 §4.1.1].

#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


DNS__HEADER__LEN = 12
DNS__HEADER__STRUCT = "! H H H H H H"

DNS__Z__MAX = 7


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsHeader(ProtoStruct):
    """
    The DNS header.
    """

    id: int
    qr: bool
    opcode: DnsOpcode
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    z: int
    rcode: DnsResponseCode
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DNS header fields.
        """

        assert is_uint16(self.id), f"The 'id' field must be a 16-bit unsigned integer. Got: {self.id!r}"

        assert isinstance(self.qr, bool), f"The 'qr' field must be a boolean. Got: {type(self.qr)!r}"

        assert isinstance(self.opcode, DnsOpcode), f"The 'opcode' field must be a DnsOpcode. Got: {type(self.opcode)!r}"

        assert isinstance(self.aa, bool), f"The 'aa' field must be a boolean. Got: {type(self.aa)!r}"

        assert isinstance(self.tc, bool), f"The 'tc' field must be a boolean. Got: {type(self.tc)!r}"

        assert isinstance(self.rd, bool), f"The 'rd' field must be a boolean. Got: {type(self.rd)!r}"

        assert isinstance(self.ra, bool), f"The 'ra' field must be a boolean. Got: {type(self.ra)!r}"

        assert 0 <= self.z <= DNS__Z__MAX, f"The 'z' field must be a 3-bit unsigned integer. Got: {self.z!r}"

        assert isinstance(
            self.rcode, DnsResponseCode
        ), f"The 'rcode' field must be a DnsResponseCode. Got: {type(self.rcode)!r}"

        assert is_uint16(self.qdcount), f"The 'qdcount' field must be a 16-bit unsigned integer. Got: {self.qdcount!r}"

        assert is_uint16(self.ancount), f"The 'ancount' field must be a 16-bit unsigned integer. Got: {self.ancount!r}"

        assert is_uint16(self.nscount), f"The 'nscount' field must be a 16-bit unsigned integer. Got: {self.nscount!r}"

        assert is_uint16(self.arcount), f"The 'arcount' field must be a 16-bit unsigned integer. Got: {self.arcount!r}"

    @override
    def __len__(self) -> int:
        """
        Get the DNS header length.
        """

        return DNS__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DNS header as a memoryview.
        """

        flags = (
            self.qr << 15
            | int(self.opcode) << 11
            | self.aa << 10
            | self.tc << 9
            | self.rd << 8
            | self.ra << 7
            | self.z << 4
            | int(self.rcode)
        )

        struct.pack_into(
            DNS__HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

        return memoryview(buffer)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DNS header from buffer.
        """

        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(DNS__HEADER__STRUCT, buffer[:DNS__HEADER__LEN])

        return cls(
            id=id,
            qr=bool(flags >> 15 & 0b1),
            # Use the tolerant 'from_int' so an unknown wire 'opcode' /
            # 'rcode' value is materialised as UNKNOWN_n rather than
            # raising ValueError out of '_parse'.
            opcode=DnsOpcode.from_int(flags >> 11 & 0b1111),
            aa=bool(flags >> 10 & 0b1),
            tc=bool(flags >> 9 & 0b1),
            rd=bool(flags >> 8 & 0b1),
            ra=bool(flags >> 7 & 0b1),
            z=flags >> 4 & 0b111,
            rcode=DnsResponseCode.from_int(flags & 0b1111),
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
        )


class DnsHeaderProperties(ABC):
    """
    Properties used to access the DNS header fields.
    """

    _header: DnsHeader

    @property
    def id(self) -> int:
        """
        Get the DNS header 'id' field.
        """

        return self._header.id

    @property
    def qr(self) -> bool:
        """
        Get the DNS header 'qr' field.
        """

        return self._header.qr

    @property
    def opcode(self) -> DnsOpcode:
        """
        Get the DNS header 'opcode' field.
        """

        return self._header.opcode

    @property
    def aa(self) -> bool:
        """
        Get the DNS header 'aa' field.
        """

        return self._header.aa

    @property
    def tc(self) -> bool:
        """
        Get the DNS header 'tc' field.
        """

        return self._header.tc

    @property
    def rd(self) -> bool:
        """
        Get the DNS header 'rd' field.
        """

        return self._header.rd

    @property
    def ra(self) -> bool:
        """
        Get the DNS header 'ra' field.
        """

        return self._header.ra

    @property
    def z(self) -> int:
        """
        Get the DNS header 'z' field.
        """

        return self._header.z

    @property
    def rcode(self) -> DnsResponseCode:
        """
        Get the DNS header 'rcode' field.
        """

        return self._header.rcode

    @property
    def qdcount(self) -> int:
        """
        Get the DNS header 'qdcount' field.
        """

        return self._header.qdcount

    @property
    def ancount(self) -> int:
        """
        Get the DNS header 'ancount' field.
        """

        return self._header.ancount

    @property
    def nscount(self) -> int:
        """
        Get the DNS header 'nscount' field.
        """

        return self._header.nscount

    @property
    def arcount(self) -> int:
        """
        Get the DNS header 'arcount' field.
        """

        return self._header.arcount
