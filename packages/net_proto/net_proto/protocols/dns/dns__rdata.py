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
This module contains the DNS RDATA decoders for the name-bearing and
structured record types (PTR / CNAME / NS / MX / SOA / TXT).

A resource record's RDATA frequently embeds domain names that are
compressed against the whole message (RFC 1035 §4.1.4), so it can only
be decoded where the full frame and the RDATA offset are both known —
inside 'DnsResourceRecord.from_frame'. This module turns that RDATA
into typed objects (CLAUDE.md: parse to typed objects, not opaque
blobs) so consumers do not re-walk the wire. A / AAAA records keep
their dedicated 'DnsResourceRecord.address' accessor and decode to
'None' here; unknown record types also decode to 'None' (their raw
'rdata' bytes remain available).

net_proto/protocols/dns/dns__rdata.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8, is_uint16, is_uint32
from net_proto.protocols.dns.dns__enums import DnsRecordType
from net_proto.protocols.dns.dns__errors import DnsIntegrityError
from net_proto.protocols.dns.dns__name import decode_name

# RFC 1035 §3.3.9 — an MX RDATA is a 2-octet PREFERENCE followed by an
# EXCHANGE domain name.
DNS__RDATA__MX__PREFERENCE__STRUCT = "! H"
DNS__RDATA__MX__PREFERENCE__LEN = 2

# RFC 1035 §3.3.13 — an SOA RDATA is MNAME and RNAME domain names
# followed by five 4-octet fields (SERIAL, REFRESH, RETRY, EXPIRE,
# MINIMUM).
DNS__RDATA__SOA__TAIL__STRUCT = "! L L L L L"
DNS__RDATA__SOA__TAIL__LEN = 20


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsRdataName:
    """
    The decoded RDATA of a single-name record (PTR / CNAME / NS).
    """

    name: str

    def __post_init__(self) -> None:
        """
        Ensure integrity of the decoded single-name RDATA fields.
        """

        assert isinstance(self.name, str), f"The 'name' field must be a string. Got: {type(self.name)!r}"


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsRdataMx:
    """
    The decoded RDATA of a mail-exchange (MX) record.
    """

    preference: int
    exchange: str

    def __post_init__(self) -> None:
        """
        Ensure integrity of the decoded MX RDATA fields.
        """

        assert is_uint16(
            self.preference
        ), f"The 'preference' field must be a 16-bit unsigned integer. Got: {self.preference!r}"

        assert isinstance(self.exchange, str), f"The 'exchange' field must be a string. Got: {type(self.exchange)!r}"


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsRdataSoa:
    """
    The decoded RDATA of a start-of-authority (SOA) record.
    """

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int

    def __post_init__(self) -> None:
        """
        Ensure integrity of the decoded SOA RDATA fields.
        """

        assert isinstance(self.mname, str), f"The 'mname' field must be a string. Got: {type(self.mname)!r}"

        assert isinstance(self.rname, str), f"The 'rname' field must be a string. Got: {type(self.rname)!r}"

        for field_name in ("serial", "refresh", "retry", "expire", "minimum"):
            value = getattr(self, field_name)
            assert is_uint32(value), f"The {field_name!r} field must be a 32-bit unsigned integer. Got: {value!r}"


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsRdataTxt:
    """
    The decoded RDATA of a text (TXT) record — one or more raw
    character-strings (RFC 1035 §3.3.14).
    """

    strings: tuple[bytes, ...]

    def __post_init__(self) -> None:
        """
        Ensure integrity of the decoded TXT RDATA fields.
        """

        assert all(
            isinstance(string, bytes) for string in self.strings
        ), "The 'strings' field must be a tuple of bytes."

        assert all(
            is_uint8(len(string)) for string in self.strings
        ), "Each TXT character-string must be at most 255 octets."


type DnsRdata = DnsRdataName | DnsRdataMx | DnsRdataSoa | DnsRdataTxt


def decode_rdata(*, rtype: DnsRecordType, frame: Buffer, rdata_offset: int, rdlength: int) -> DnsRdata | None:
    """
    Decode the RDATA at 'rdata_offset' into a typed object for the
    name-bearing and structured record types, following compression
    pointers against the full 'frame'. Return 'None' for A / AAAA (use
    'DnsResourceRecord.address') and for unknown record types. Raise
    'DnsIntegrityError' when a supported record's RDATA is malformed.
    """

    match rtype:
        case DnsRecordType.PTR | DnsRecordType.CNAME | DnsRecordType.NS:
            name, _ = decode_name(frame, rdata_offset)
            return DnsRdataName(name=name)
        case DnsRecordType.MX:
            if rdlength < DNS__RDATA__MX__PREFERENCE__LEN + 1:
                raise DnsIntegrityError(f"The MX RDATA at offset {rdata_offset} is too short. Got: {rdlength} octets.")
            (preference,) = struct.unpack_from(DNS__RDATA__MX__PREFERENCE__STRUCT, frame, rdata_offset)
            exchange, _ = decode_name(frame, rdata_offset + DNS__RDATA__MX__PREFERENCE__LEN)
            return DnsRdataMx(preference=preference, exchange=exchange)
        case DnsRecordType.SOA:
            mname, offset = decode_name(frame, rdata_offset)
            rname, offset = decode_name(frame, offset)
            if offset + DNS__RDATA__SOA__TAIL__LEN > rdata_offset + rdlength:
                raise DnsIntegrityError(f"The SOA RDATA at offset {rdata_offset} is truncated.")
            serial, refresh, retry, expire, minimum = struct.unpack_from(DNS__RDATA__SOA__TAIL__STRUCT, frame, offset)
            return DnsRdataSoa(
                mname=mname,
                rname=rname,
                serial=serial,
                refresh=refresh,
                retry=retry,
                expire=expire,
                minimum=minimum,
            )
        case DnsRecordType.TXT:
            return _decode_txt(frame=frame, rdata_offset=rdata_offset, rdlength=rdlength)
        case _:
            return None


def _decode_txt(*, frame: Buffer, rdata_offset: int, rdlength: int) -> DnsRdataTxt:
    """
    Decode a TXT RDATA — a sequence of length-prefixed character-strings
    bounded by 'rdlength' (RFC 1035 §3.3.14). Raise 'DnsIntegrityError'
    when a character-string runs past the RDATA boundary.
    """

    frame = memoryview(frame)
    end = rdata_offset + rdlength
    position = rdata_offset
    strings: list[bytes] = []

    while position < end:
        length = frame[position]
        position += 1
        if position + length > end:
            raise DnsIntegrityError(f"The TXT character-string at offset {position - 1} runs past the RDATA boundary.")
        strings.append(bytes(frame[position : position + length]))
        position += length

    return DnsRdataTxt(strings=tuple(strings))
