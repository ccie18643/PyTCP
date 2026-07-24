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
This module contains the IGMPv3 Membership Report message support class.

net_proto/protocols/igmp/message/igmp__message__v3_report.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.igmp.igmp__errors import IgmpIntegrityError
from net_proto.protocols.igmp.message.igmp__message import (
    IgmpMessage,
    IgmpType,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IGMP__V3_GROUP_RECORD__LEN,
    IgmpV3GroupRecord,
)
from net_proto.protocols.ip4.ip4__header import IP4__PAYLOAD__MAX_LEN

# The IGMPv3 Membership Report message [RFC 3376 §4.2].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Type = 0x22  |    Reserved   |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |  Number of Group Records (M)  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                        Group Record [1]                       ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                               .                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                        Group Record [M]                       ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IGMP__V3_REPORT__LEN = 8
IGMP__V3_REPORT__STRUCT = "! BBH HH"


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessageV3Report(IgmpMessage):
    """
    The IGMPv3 Membership Report message.
    """

    type: IgmpType = field(
        repr=False,
        init=False,
        default=IgmpType.V3_MEMBERSHIP_REPORT,
    )
    cksum: int = 0

    records: list[IgmpV3GroupRecord] = field(default_factory=list[IgmpV3GroupRecord])

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IGMPv3 Membership Report message fields.
        """

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert (records_len := sum(len(record) for record in self.records)) <= (
            records_len_max := IP4__PAYLOAD__MAX_LEN - IGMP__V3_REPORT__LEN
        ), f"The 'records' field length must be less than or equal to {records_len_max}. Got: {records_len}"

    @property
    def number_of_records(self) -> int:
        """
        Get the IGMPv3 Membership Report message 'number_of_records' field.
        """

        return len(self.records)

    @override
    def __len__(self) -> int:
        """
        Get the IGMPv3 Membership Report message length.
        """

        return IGMP__V3_REPORT__LEN + sum(len(record) for record in self.records)

    @override
    def __str__(self) -> str:
        """
        Get the IGMPv3 Membership Report message log string.
        """

        records_part = ", records " + ", ".join(str(record) for record in self.records) if self.records else ""

        return f"IGMPv3 Report{records_part}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMPv3 Membership Report message as a memoryview.
        """

        buffer = self._pack_header()
        buffer += self._pack_records()

        return memoryview(buffer)

    def _pack_header(self) -> bytearray:
        """
        Get the IGMPv3 Membership Report message header as bytes.
        """

        struct.pack_into(
            IGMP__V3_REPORT__STRUCT,
            buffer := bytearray(IGMP__V3_REPORT__LEN),
            0,
            int(self.type),
            0,
            0,
            0,
            self.number_of_records,
        )

        return buffer

    def _pack_records(self) -> bytearray:
        """
        Get the IGMPv3 Membership Report message records as bytes.
        """

        buffer = bytearray()

        for record in self.records:
            buffer += bytearray(record)

        return buffer

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMPv3 Membership Report message after
        parsing it. A host ignores Reports it receives from other hosts
        (IGMPv3 does not suppress); the TTL=1 / Router-Alert checks are
        enforced at the RX handler, so the message-class sanity is a
        no-op stub here.
        """

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the IGMPv3 Membership Report message before
        parsing it.
        """

        if not (IGMP__V3_REPORT__LEN <= ip4__payload_len <= len(frame)):
            raise IgmpIntegrityError(
                "The condition 'IGMP__V3_REPORT__LEN <= ip4__payload_len <= len(frame)' is not met. "
                f"Got: {IGMP__V3_REPORT__LEN=}, {ip4__payload_len=}, {len(frame)=}"
            )

        record_offset = IGMP__V3_REPORT__LEN
        for _ in range(int.from_bytes(frame[6:8], "big")):
            if not (record_offset + IGMP__V3_GROUP_RECORD__LEN <= ip4__payload_len):
                raise IgmpIntegrityError(
                    "The condition 'record_offset + IGMP__V3_GROUP_RECORD__LEN <= ip4__payload_len' is not met. "
                    f"Got: {record_offset=}, {IGMP__V3_GROUP_RECORD__LEN=}, {ip4__payload_len=}"
                )

            record_offset += (
                IGMP__V3_GROUP_RECORD__LEN
                + (frame[record_offset + 1] << 2)
                + int.from_bytes(frame[record_offset + 2 : record_offset + 4], "big") * 4
            )

        if record_offset != ip4__payload_len:
            raise IgmpIntegrityError(
                f"The condition 'record_offset == ip4__payload_len' is not met. "
                f"Got: {record_offset=}, {ip4__payload_len=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IGMPv3 Membership Report message from buffer.
        """

        type_, _, cksum, _, number_of_records = struct.unpack(IGMP__V3_REPORT__STRUCT, buffer[:IGMP__V3_REPORT__LEN])

        assert (received_type := IgmpType.from_int(type_)) == (
            valid_type := IgmpType.V3_MEMBERSHIP_REPORT
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        record_bytes = buffer[IGMP__V3_REPORT__LEN:]

        records: list[IgmpV3GroupRecord] = []
        for _ in range(number_of_records):
            record = IgmpV3GroupRecord.from_buffer(record_bytes)
            record_bytes = record_bytes[len(record) :]
            records.append(record)

        return cls(cksum=cksum, records=records)

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMPv3 Membership Report message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self._pack_records())
