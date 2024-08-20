#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This Module contains the ICMPv6 MLDv2 Report message support class.

pytcp/protocols/icmp6/message/mld2/icmp6_mld2_message__report.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp6.message.icmp6_message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
)
from pytcp.protocols.ip6.ip6__header import IP6__PAYLOAD__MAX_LEN

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
        repr=False, init=False, default=Icmp6Type.MLD2__REPORT,
    )
    code: Icmp6Mld2ReportCode = Icmp6Mld2ReportCode.DEFAULT
    cksum: int = 0

    records: list[Icmp6Mld2MulticastAddressRecord]

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 MLDv2 message fields.
        """

        assert isinstance(
            self.code, Icmp6Mld2ReportCode
        ), f"The 'code' field must be an Icmp6Mld2ReportCode. Got: {type(self.code)!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

        assert (records_len := sum(len(record) for record in self.records)) <= (
            records_len_max := IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        ), f"The 'records' field length must be less than or equal to {records_len_max}. Got: {records_len}"

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

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6Mld2ReportMessage:
        """
        Initialize the ICMPv6 MLDv2 Report message from bytes.
        """

        assert (
            Icmp6Type.from_bytes(_bytes[0:1]) == Icmp6Type.MLD2__REPORT
        ), f"The 'type' field must be <Icmp6Type.MLD2_REPORT: 143>. Got: {Icmp6Type.from_bytes(_bytes[0:1])!r}"

        records: list[Icmp6Mld2MulticastAddressRecord] = []
        record_bytes = _bytes[ICMP6__MLD2__REPORT__LEN:]

        for _ in range(int.from_bytes(_bytes[6:8])):
            record = Icmp6Mld2MulticastAddressRecord.from_bytes(record_bytes)
            record_bytes = record_bytes[len(record) :]
            records.append(record)

        return Icmp6Mld2ReportMessage(
            cksum=int.from_bytes(_bytes[2:4]),
            records=records,
        )
