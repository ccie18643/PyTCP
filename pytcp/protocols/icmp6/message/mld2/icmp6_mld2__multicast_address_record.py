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
This module contains the ICMPv6 MLDv2 Multicast Address Record support class.

pytcp/protocols/icmp6/icmp6_mld2__multicast_address_record.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from typing import override

from pytcp.lib.int_checks import is_4_byte_alligned
from pytcp.lib.ip6_address import IP6_ADDRESS_LEN, Ip6Address
from pytcp.lib.proto import Proto
from pytcp.lib.proto_enum import ProtoEnumByte

# The ICMPv6 MLDv2 Multicast Address Record [RFC 3810].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Multicast Address                       +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                         Auxiliary Data                        ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# NOTE: The 'Aux Data Len' field is the length of the 'Auxiliary Data'
# field in 32-bit words.

ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN = 20
ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__STRUCT = "! BBH 16s"


class Icmp6Mld2MulticastAddressRecordType(ProtoEnumByte):
    """
    The ICMPv6 MLDv2 Multicast Address Record 'type' values.
    """

    MODE_IS_INCLUDE = 1
    MODE_IS_EXCLUDE = 2
    CHANGE_TO_INCLUDE = 3
    CHANGE_TO_EXCLUDE = 4
    ALLOW_NEW_SOURCES = 5
    BLOCK_OLD_SOURCES = 6


class Icmp6Mld2MulticastAddressRecord(Proto):
    """
    The ICMPv6 MLDv2 Multicast Address Record support.
    """

    _type: Icmp6Mld2MulticastAddressRecordType
    _aux_data_len: int
    _number_of_sources: int
    _multicast_address: Ip6Address
    _source_addresses: list[Ip6Address]
    _aux_data: bytes

    def __init__(
        self,
        *,
        type: Icmp6Mld2MulticastAddressRecordType,
        multicast_address: Ip6Address,
        source_addresses: list[Ip6Address] = [],
        aux_data: bytes = bytes(),
    ) -> None:
        """
        Initialize the ICMPv6 MLDv2 Multicast Address Record.
        """

        assert multicast_address.is_multicast
        for address in source_addresses or []:
            assert address.is_unicast
        assert is_4_byte_alligned(len(aux_data))

        self._type = type
        self._multicast_address = multicast_address
        self._source_addresses = source_addresses
        self._number_of_sources = len(self._source_addresses)
        self._aux_data = aux_data
        self._aux_data_len = len(self._aux_data)

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record length.
        """

        return (
            ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
            + IP6_ADDRESS_LEN * self._number_of_sources
            + self._aux_data_len
        )

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record log string.
        """

        return (
            f"[type '{self._type}', addr {self._multicast_address}"
            f"{(
                ', sources (' + ', '.join(str(source_address)
                                          for source_address
                                          in self._source_addresses) + ')'
            ) if self._source_addresses else ''}"
            f"{f', aux data {self._aux_data!r}' if self._aux_data else ''}]"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record representation string.
        """

        return (
            f"{self.__class__.__name__}("
            f"type={self._type!r}, "
            f"multicast_address={self._multicast_address!r}, "
            f"source_addresses={self._source_addresses!r}, "
            f"aux_data={self._aux_data!r})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record as bytes.
        """

        return (
            struct.pack(
                ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__STRUCT,
                int(self._type),
                self._aux_data_len >> 2,
                self._number_of_sources,
                bytes(self._multicast_address),
            )
            + b"".join(
                [
                    bytes(source_address)
                    for source_address in self._source_addresses
                ]
            )
            + self._aux_data
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6Mld2MulticastAddressRecord:
        """
        Initialize the ICMPv6 MLDv2 Multicast Address Record from bytes.
        """

        type, aux_data_len, number_of_sources, multicast_address = (
            struct.unpack(
                ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__STRUCT,
                _bytes[0:ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN],
            )
        )

        source_addresses = [
            Ip6Address(
                _bytes[
                    ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
                    + IP6_ADDRESS_LEN
                    * n : ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
                    + IP6_ADDRESS_LEN * (n + 1)
                ]
            )
            for n in range(number_of_sources)
        ]

        aux_data_offset = (
            ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN
            + IP6_ADDRESS_LEN * number_of_sources
        )
        aux_data = _bytes[
            aux_data_offset : aux_data_offset + (aux_data_len << 2)
        ]

        return Icmp6Mld2MulticastAddressRecord(
            type=Icmp6Mld2MulticastAddressRecordType.from_int(type),
            multicast_address=Ip6Address(multicast_address),
            source_addresses=source_addresses,
            aux_data=aux_data,
        )

    @property
    def type(self) -> Icmp6Mld2MulticastAddressRecordType:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'type' field.
        """

        return self._type

    @property
    def aux_data_len(self) -> int:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'aux_data_len' field.
        """

        return self._aux_data_len

    @property
    def number_of_sources(self) -> int:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'number_of_sources' field.
        """

        return self._number_of_sources

    @property
    def multicast_address(self) -> Ip6Address:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'multicast_address' field.
        """

        return self._multicast_address

    @property
    def source_addresses(self) -> list[Ip6Address]:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'source_addresses' field.
        """

        return self._source_addresses

    @property
    def aux_data(self) -> bytes:
        """
        Get the ICMPv6 MLDv2 Multicast Address Record 'aux_data' field.
        """

        return self._aux_data
