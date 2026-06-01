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
This module contains the DNS question-record class.

net_proto/protocols/dns/dns__question.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass
from typing import Self

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dns.dns__enums import DnsRecordClass, DnsRecordType
from net_proto.protocols.dns.dns__name import decode_name, encode_name

# A DNS question record [RFC 1035 §4.1.2]: a domain name followed by a
# 2-octet QTYPE and a 2-octet QCLASS.

DNS__QUESTION__FIXED_LEN = 4
DNS__QUESTION__STRUCT = "! H H"


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsQuestion:
    """
    The DNS question record.
    """

    qname: str
    qtype: DnsRecordType
    qclass: DnsRecordClass

    def __post_init__(self) -> None:
        """
        Ensure integrity of the DNS question record fields.
        """

        assert isinstance(self.qname, str), f"The 'qname' field must be a string. Got: {type(self.qname)!r}"

        assert isinstance(
            self.qtype, DnsRecordType
        ), f"The 'qtype' field must be a DnsRecordType. Got: {type(self.qtype)!r}"

        assert isinstance(
            self.qclass, DnsRecordClass
        ), f"The 'qclass' field must be a DnsRecordClass. Got: {type(self.qclass)!r}"

    def __len__(self) -> int:
        """
        Get the DNS question record length (uncompressed wire form).
        """

        return len(encode_name(self.qname)) + DNS__QUESTION__FIXED_LEN

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DNS question record as a memoryview (uncompressed).
        """

        buffer = bytearray(encode_name(self.qname))
        buffer += struct.pack(DNS__QUESTION__STRUCT, int(self.qtype), int(self.qclass))

        return memoryview(buffer)

    @classmethod
    def from_frame(cls, frame: Buffer, offset: int, /) -> tuple[Self, int]:
        """
        Parse the DNS question record at 'offset', returning it and the
        offset of the first octet after the record.
        """

        qname, offset = decode_name(frame, offset)
        qtype, qclass = struct.unpack_from(DNS__QUESTION__STRUCT, frame, offset)

        return (
            cls(
                qname=qname,
                qtype=DnsRecordType.from_int(qtype),
                qclass=DnsRecordClass.from_int(qclass),
            ),
            offset + DNS__QUESTION__FIXED_LEN,
        )
