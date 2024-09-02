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
Module contains the ICMPv6 MLDv2 Report message support class.

pytcp/protocols/icmp6/message/mld2/icmp6_mld2_message__report.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

from pytcp.lib.int_checks import is_uint16
from pytcp.lib.net_addr import IP6__ADDRESS_LEN
from pytcp.protocols.icmp6.icmp6__errors import (
    Icmp6IntegrityError,
    Icmp6SanityError,
)
from pytcp.protocols.icmp6.message.icmp6_message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN,
    Icmp6Mld2MulticastAddressRecord,
)
from pytcp.protocols.ip6.ip6__header import IP6__PAYLOAD__MAX_LEN

if TYPE_CHECKING:
    from pytcp.lib.net_addr import Ip6Address


# The ICMPv6 MLDv2 Report message (143/0) [RFC3810].

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
    The ICMPv6 MLD2 Report message 'code' values.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp6Mld2ReportMessage(Icmp6Message):
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
        Validate the ICMPv6 MLDv2 message fields.
        """

        assert isinstance(self.code, Icmp6Mld2ReportCode), (
            f"The 'code' field must be an Icmp6Mld2ReportCode. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum}"
        )

        assert (records_len := sum(len(record) for record in self.records)) <= (
            records_len_max := IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        ), (
            f"The 'records' field length must be less than or equal to {records_len_max}. "
            f"Got: {records_len}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLD2 Report message length.
        """

        return ICMP6__MLD2__REPORT__LEN + sum(
            len(record) for record in self.records
        )

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLD2 Report message log string.
        """

        return (
            "ICMPv6 MLDv2 Report"
            f"{', records ' + ', '.join(
                str(record) for record in self.records
            ) if self.records else ''}"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 MLDv2 Report message as bytes.
        """

        return struct.pack(
            ICMP6__MLD2__REPORT__STRUCT,
            int(self.type),
            int(self.code),
            0,
            0,
            len(self.records),
        ) + b"".join([bytes(record) for record in self.records])

    @property
    def number_of_records(self) -> int:
        """
        Get the ICMPv6 MLDv2 Multicast Address Records number.
        """

        return len(self.records)

    @override
    def validate_sanity(
        self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address
    ) -> None:
        """
        Validate the ICMPv6 MLDv2 Report message sanity after parsing it.
        """

        if not (ip6__hop == 1):
            raise Icmp6SanityError(
                "MLDv2 Report - [RFC 3810] The 'ip6__hop' field must be 1. "
                f"Got: {ip6__hop!r}",
            )

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip6__dlen: int) -> None:
        """
        Validate integrity of the ICMPv6 MLDv2 Report message before
        parsing it.
        """

        if not (ICMP6__MLD2__REPORT__LEN <= ip6__dlen <= len(frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen "
                f"<= len(frame)' is not met. Got: {ICMP6__MLD2__REPORT__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

        record_offset = ICMP6__MLD2__REPORT__LEN
        for _ in range(int.from_bytes(frame[6:8])):
            if not (
                record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
                <= ip6__dlen
            ):
                raise Icmp6IntegrityError(
                    "The condition 'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_"
                    f"RECORD__LEN <= ip6__dlen' is not met. Got: {record_offset=}, "
                    f"{ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN=}, {ip6__dlen=}"
                )

            record_offset += (
                ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
                + (frame[record_offset + 1] << 2)
                + int.from_bytes(frame[record_offset + 2 : record_offset + 4])
                * IP6__ADDRESS_LEN
            )

        if not (record_offset == ip6__dlen):
            raise Icmp6IntegrityError(
                "The condition 'record_offset == ip6__dlen' is not met. "
                f"Got: {record_offset=}, {ip6__dlen=}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6Mld2ReportMessage:
        """
        Initialize the ICMPv6 MLDv2 Report message from bytes.
        """

        type, code, cksum, _, number_of_records = struct.unpack(
            ICMP6__MLD2__REPORT__STRUCT, _bytes[:ICMP6__MLD2__REPORT__LEN]
        )
        record_bytes = _bytes[ICMP6__MLD2__REPORT__LEN:]

        assert (received_type := Icmp6Type.from_int(type)) == (
            valid_type := Icmp6Type.MLD2__REPORT
        ), (
            f"The 'type' field must be {valid_type!r}. "
            f"Got: {received_type!r}"
        )

        records: list[Icmp6Mld2MulticastAddressRecord] = []
        for _ in range(number_of_records):
            record = Icmp6Mld2MulticastAddressRecord.from_bytes(record_bytes)
            record_bytes = record_bytes[len(record) :]
            records.append(record)

        return Icmp6Mld2ReportMessage(
            code=Icmp6Mld2ReportCode.from_int(code),
            cksum=cksum,
            records=records,
        )
