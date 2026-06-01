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
This module contains the IGMPv3 Group Record support class.

net_proto/protocols/igmp/message/igmp__v3_group_record.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import IP4__ADDRESS_LEN, Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_4_byte_alligned
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_struct import ProtoStruct

# The IGMPv3 Group Record [RFC 3376 §4.2.4].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Multicast Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address [1]                      |
# +-                                                             -+
# |                       Source Address [2]                      |
# +-                              .                              -+
# .                               .                               .
# +-                                                             -+
# |                       Source Address [N]                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# .                         Auxiliary Data                        .
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# NOTE: The 'Aux Data Len' field is the length of the 'Auxiliary Data'
# field in 32-bit words (RFC 3376 §4.2.6).

IGMP__V3_GROUP_RECORD__LEN = 8
IGMP__V3_GROUP_RECORD__STRUCT = "! BBH 4s"


class IgmpV3RecordType(ProtoEnumByte):
    """
    The IGMPv3 Group Record 'record_type' field values.
    """

    MODE_IS_INCLUDE = 1  # RFC 3376 §4.2.12: current-state record, INCLUDE filter mode.
    MODE_IS_EXCLUDE = 2  # RFC 3376 §4.2.12: current-state record, EXCLUDE filter mode.
    CHANGE_TO_INCLUDE_MODE = 3  # RFC 3376 §4.2.12: filter-mode change record, transition to INCLUDE.
    CHANGE_TO_EXCLUDE_MODE = 4  # RFC 3376 §4.2.12: filter-mode change record, transition to EXCLUDE.
    ALLOW_NEW_SOURCES = 5  # RFC 3376 §4.2.12: source-list change record, allow listed sources.
    BLOCK_OLD_SOURCES = 6  # RFC 3376 §4.2.12: source-list change record, block listed sources.


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpV3GroupRecord(ProtoStruct):
    """
    The IGMPv3 Group Record.
    """

    type: IgmpV3RecordType
    # The 'aux_data_len' field is available as a property.
    # The 'number_of_sources' field is available as a property.
    multicast_address: Ip4Address
    source_addresses: list[Ip4Address] = field(default_factory=list[Ip4Address])
    aux_data: bytes = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IGMPv3 Group Record fields.
        """

        assert (
            self.multicast_address.is_multicast
        ), f"The 'multicast_address' field must be a multicast address. Got: {self.multicast_address!r}"

        for address in self.source_addresses:
            assert (
                address.is_unicast
            ), f"The 'source_addresses' field must contain only unicast addresses. Got: {address!r}"

        assert is_4_byte_alligned(
            len(self.aux_data)
        ), f"The 'aux_data' field must be 4-byte aligned. Got: {len(self.aux_data)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IGMPv3 Group Record length.
        """

        return IGMP__V3_GROUP_RECORD__LEN + IP4__ADDRESS_LEN * self.number_of_sources + self.aux_data_len

    @override
    def __str__(self) -> str:
        """
        Get the IGMPv3 Group Record log string.
        """

        sources_part = (
            ", sources (" + ", ".join(str(addr) for addr in self.source_addresses) + ")"
            if self.source_addresses
            else ""
        )
        aux_part = f", aux data {self.aux_data!r}" if self.aux_data else ""

        return f"[type '{self.type}', addr {self.multicast_address}{sources_part}{aux_part}]"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMPv3 Group Record as a memoryview.
        """

        struct.pack_into(
            IGMP__V3_GROUP_RECORD__STRUCT,
            buffer := bytearray(IGMP__V3_GROUP_RECORD__LEN),
            0,
            int(self.type),
            self.aux_data_len >> 2,
            self.number_of_sources,
            bytes(self.multicast_address),
        )

        for source_address in self.source_addresses:
            buffer += bytearray(source_address)

        buffer += self.aux_data

        return memoryview(buffer)

    @override
    def __hash__(self) -> int:
        """
        Get the IGMPv3 Group Record hash.
        """

        return hash(
            (
                self.type,
                self.multicast_address,
                tuple(self.source_addresses),
                self.aux_data,
            )
        )

    @property
    def number_of_sources(self) -> int:
        """
        Get the IGMPv3 Group Record 'number_of_sources' field.
        """

        return len(self.source_addresses)

    @property
    def aux_data_len(self) -> int:
        """
        Get the IGMPv3 Group Record 'aux_data_len' field.
        """

        return len(self.aux_data)

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IGMPv3 Group Record from buffer.
        """

        type_, aux_data_len, number_of_sources, multicast_address = struct.unpack(
            IGMP__V3_GROUP_RECORD__STRUCT,
            buffer[0:IGMP__V3_GROUP_RECORD__LEN],
        )

        source_addresses = [
            Ip4Address(
                buffer[
                    IGMP__V3_GROUP_RECORD__LEN
                    + IP4__ADDRESS_LEN * n : IGMP__V3_GROUP_RECORD__LEN
                    + IP4__ADDRESS_LEN * (n + 1)
                ]
            )
            for n in range(number_of_sources)
        ]

        aux_data_offset = IGMP__V3_GROUP_RECORD__LEN + IP4__ADDRESS_LEN * number_of_sources
        aux_data = bytes(buffer[aux_data_offset : aux_data_offset + (aux_data_len << 2)])

        return cls(
            type=IgmpV3RecordType.from_int(type_),
            multicast_address=Ip4Address(multicast_address),
            source_addresses=source_addresses,
            aux_data=aux_data,
        )
