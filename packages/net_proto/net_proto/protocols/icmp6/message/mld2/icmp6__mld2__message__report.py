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
This module contains the ICMPv6 MLDv2 Report message support class.

net_proto/protocols/icmp6/message/mld2/icmp6__mld2__message__report.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import IP6__ADDRESS_LEN, Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
    Icmp6SanityError,
)
from net_proto.protocols.icmp6.message.icmp6__message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__multicast_address_record import (
    ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN,
    Icmp6Mld2MulticastAddressRecord,
)
from net_proto.protocols.ip6.ip6__header import IP6__PAYLOAD__MAX_LEN

# The ICMPv6 MLDv2 Report message (143/0) [RFC 3810].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |       Number of Records       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [1]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [2]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [M]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__MLD2__REPORT__LEN = 8
ICMP6__MLD2__REPORT__STRUCT = "! BBH HH"


class Icmp6Mld2ReportCode(Icmp6Code):
    """
    The ICMPv6 MLDv2 Report 'code' field values.
    """

    DEFAULT = 0  # RFC 3810 §5.2: only code 0 defined.


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6Mld2MessageReport(Icmp6Message):
    """
    The ICMPv6 MLDv2 Report message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.MLD2__REPORT,
    )
    code: Icmp6Mld2ReportCode = Icmp6Mld2ReportCode.DEFAULT
    cksum: int = 0

    records: list[Icmp6Mld2MulticastAddressRecord]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv2 message fields.
        """

        assert isinstance(
            self.code, Icmp6Mld2ReportCode
        ), f"The 'code' field must be an Icmp6Mld2ReportCode. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert (records_len := sum(len(record) for record in self.records)) <= (
            records_len_max := IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        ), f"The 'records' field length must be less than or equal to {records_len_max}. Got: {records_len}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLDv2 Report message length.
        """

        return ICMP6__MLD2__REPORT__LEN + sum(len(record) for record in self.records)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLDv2 Report message log string.
        """

        records_part = ", records " + ", ".join(str(record) for record in self.records) if self.records else ""

        return f"ICMPv6 MLDv2 Report{records_part}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 MLDv2 Report message as a memoryview.
        """

        buffer = self._pack_header()
        buffer[ICMP6__MLD2__REPORT__LEN:] = self._pack_records()

        return memoryview(buffer)

    @property
    def number_of_records(self) -> int:
        """
        Get the ICMPv6 MLDv2 Report message 'number_of_records' field.
        """

        return len(self.records)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__MLD2__REPORT__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv6 MLDv2 Report message as bytes.
        """

        struct.pack_into(
            ICMP6__MLD2__REPORT__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
            0,
            len(self.records),
        )

        return buffer

    def _pack_records(self) -> bytearray:
        """
        Get the ICMPv6 MLDv2 Report message records as bytes.
        """

        buffer = bytearray()

        for record in self.records:
            buffer += bytearray(record)

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 MLDv2 Report message after parsing it.
        """

        if ip6__hop != 1:
            raise Icmp6SanityError(
                f"MLDv2 Report - [RFC 3810] The 'ip6__hop' field must be 1. Got: {ip6__hop!r}",
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 MLDv2 Report message before parsing it.
        """

        if not (ICMP6__MLD2__REPORT__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen <= len(frame)' is not met. "
                f"Got: {ICMP6__MLD2__REPORT__LEN=}, {ip6__dlen=}, {len(frame)=}"
            )

        record_offset = ICMP6__MLD2__REPORT__LEN
        for _ in range(int.from_bytes(frame[6:8])):
            if not (record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN <= ip6__dlen):
                raise Icmp6IntegrityError(
                    "The condition 'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN <= ip6__dlen' "
                    f"is not met. Got: {record_offset=}, {ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN=}, {ip6__dlen=}"
                )

            record_offset += (
                ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
                + (frame[record_offset + 1] << 2)
                + int.from_bytes(frame[record_offset + 2 : record_offset + 4]) * IP6__ADDRESS_LEN
            )

        if record_offset != ip6__dlen:
            raise Icmp6IntegrityError(
                f"The condition 'record_offset == ip6__dlen' is not met. Got: {record_offset=}, {ip6__dlen=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 MLDv2 Report message from buffer.
        """

        type_, code, cksum, _, number_of_records = struct.unpack(
            ICMP6__MLD2__REPORT__STRUCT, buffer[:ICMP6__MLD2__REPORT__LEN]
        )
        record_bytes = buffer[ICMP6__MLD2__REPORT__LEN:]

        assert (received_type := Icmp6Type.from_int(type_)) == (
            valid_type := Icmp6Type.MLD2__REPORT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        records: list[Icmp6Mld2MulticastAddressRecord] = []
        for _ in range(number_of_records):
            record = Icmp6Mld2MulticastAddressRecord.from_buffer(record_bytes)
            record_bytes = record_bytes[len(record) :]
            records.append(record)

        return cls(
            code=Icmp6Mld2ReportCode.from_int(code),
            cksum=cksum,
            records=records,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 MLDv2 Report message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self._pack_records())
