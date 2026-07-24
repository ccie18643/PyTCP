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
This module contains the DNS resource-record class.

net_proto/protocols/dns/dns__resource_record.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self

from net_addr import Buffer, Ip4Address, Ip6Address
from net_proto.lib.int_checks import is_uint16, is_uint32
from net_proto.protocols.dns.dns__enums import DnsRecordClass, DnsRecordType
from net_proto.protocols.dns.dns__errors import DnsIntegrityError
from net_proto.protocols.dns.dns__name import decode_name, encode_name
from net_proto.protocols.dns.dns__rdata import (
    DnsRdata,
    DnsRdataMx,
    DnsRdataName,
    DnsRdataSoa,
    DnsRdataTxt,
    decode_rdata,
)

# A DNS resource record [RFC 1035 §4.1.3]: a domain name, then a 2-octet
# TYPE, 2-octet CLASS, 4-octet TTL, 2-octet RDLENGTH, and RDLENGTH octets
# of RDATA.

DNS__RR__FIXED_LEN = 10
DNS__RR__STRUCT = "! H H L H"

# RFC 1035 §3.4.1 / RFC 3596 §2.2 — A / AAAA RDATA is the raw address.
DNS__RDATA__A__LEN = 4
DNS__RDATA__AAAA__LEN = 16


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsResourceRecord:
    """
    The DNS resource record.
    """

    name: str
    rtype: DnsRecordType
    rclass: DnsRecordClass
    ttl: int
    rdata: bytes
    # The typed RDATA view for name-bearing / structured records, decoded
    # against the full message in 'from_frame' (None for A / AAAA, which
    # use 'address', and for unknown types). Excluded from equality so a
    # parse-built record still compares equal to a hand-built one carrying
    # the same raw 'rdata'.
    rdata_decoded: DnsRdata | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        """
        Ensure integrity of the DNS resource-record fields.
        """

        assert isinstance(self.name, str), f"The 'name' field must be a string. Got: {type(self.name)!r}"

        assert self.rdata_decoded is None or isinstance(
            self.rdata_decoded, (DnsRdataName, DnsRdataMx, DnsRdataSoa, DnsRdataTxt)
        ), f"The 'rdata_decoded' field must be a DnsRdata or None. Got: {type(self.rdata_decoded)!r}"

        assert isinstance(
            self.rtype, DnsRecordType
        ), f"The 'rtype' field must be a DnsRecordType. Got: {type(self.rtype)!r}"

        assert isinstance(
            self.rclass, DnsRecordClass
        ), f"The 'rclass' field must be a DnsRecordClass. Got: {type(self.rclass)!r}"

        assert is_uint32(self.ttl), f"The 'ttl' field must be a 32-bit unsigned integer. Got: {self.ttl!r}"

        assert isinstance(self.rdata, bytes), f"The 'rdata' field must be bytes. Got: {type(self.rdata)!r}"

        assert is_uint16(
            len(self.rdata)
        ), f"The 'rdata' length must be a 16-bit unsigned integer. Got: {len(self.rdata)!r}"

    def __len__(self) -> int:
        """
        Get the DNS resource-record length (uncompressed wire form).
        """

        return len(encode_name(self.name)) + DNS__RR__FIXED_LEN + len(self.rdata)

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DNS resource record as a memoryview (uncompressed).
        """

        buffer = bytearray(encode_name(self.name))
        buffer += struct.pack(DNS__RR__STRUCT, int(self.rtype), int(self.rclass), self.ttl, len(self.rdata))
        buffer += self.rdata

        return memoryview(buffer)

    @property
    def address(self) -> Ip4Address | Ip6Address | None:
        """
        Get the record's IP address for an A / AAAA record, else None.
        """

        if self.rtype == DnsRecordType.A and len(self.rdata) == DNS__RDATA__A__LEN:
            return Ip4Address(self.rdata)
        if self.rtype == DnsRecordType.AAAA and len(self.rdata) == DNS__RDATA__AAAA__LEN:
            return Ip6Address(self.rdata)
        return None

    @classmethod
    def from_frame(cls, frame: Buffer, offset: int, /) -> tuple[Self, int]:
        """
        Parse the DNS resource record at 'offset', returning it and the
        offset of the first octet after the record.
        """

        name, offset = decode_name(frame, offset)
        rtype, rclass, ttl, rdlength = struct.unpack_from(DNS__RR__STRUCT, frame, offset)
        offset += DNS__RR__FIXED_LEN

        if offset + rdlength > len(frame):
            raise DnsIntegrityError(f"The resource-record RDATA at offset {offset} runs past the end of the message.")

        rdata = bytes(memoryview(frame)[offset : offset + rdlength])
        record_type = DnsRecordType.from_int(rtype)

        return (
            cls(
                name=name,
                rtype=record_type,
                rclass=DnsRecordClass.from_int(rclass),
                ttl=ttl,
                rdata=rdata,
                rdata_decoded=decode_rdata(rtype=record_type, frame=frame, rdata_offset=offset, rdlength=rdlength),
            ),
            offset + rdlength,
        )
