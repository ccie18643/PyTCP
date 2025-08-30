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
This module contains tests for the ICMPv6 MLDv2 Multicast Address Record assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__address__record__assembler.py

ver 3.0.4
"""


from typing import Any

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Mode Is Include)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Mode Is Include', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.MODE_I"
                    "S_INCLUDE: 1>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], aux"
                    "_data=b'')"
                ),
                "__bytes__": (
                    b"\x01\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Mode Is Exclude)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Mode Is Exclude', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.MODE_I"
                    "S_EXCLUDE: 2>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], aux"
                    "_data=b'')"
                ),
                "__bytes__": (
                    b"\x02\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Change To Include)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Change To Include', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.CHANGE"
                    "_TO_INCLUDE: 3>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], a"
                    "ux_data=b'')"
                ),
                "__bytes__": (
                    b"\x03\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Change To Exclude)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Change To Exclude', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.CHANGE"
                    "_TO_EXCLUDE: 4>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], a"
                    "ux_data=b'')"
                ),
                "__bytes__": (
                    b"\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Allow New Sources)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Allow New Sources', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.ALLOW_"
                    "NEW_SOURCES: 5>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], a"
                    "ux_data=b'')"
                ),
                "__bytes__": (
                    b"\x05\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record (Block Old Sources)."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Block Old Sources', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.BLOCK_"
                    "OLD_SOURCES: 6>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], a"
                    "ux_data=b'')"
                ),
                "__bytes__": (
                    b"\x06\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record, multiple sources, no aux data."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                    Ip6Address("2001:db8::3"),
                ],
            },
            "_results": {
                "__len__": 68,
                "__str__": (
                    "[type 'Mode Is Include', addr ff02::1, sources (2001:db8::1, 2001:db8::2, 2001:d"
                    "b8::3)]"
                ),
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.MODE_I"
                    "S_INCLUDE: 1>, multicast_address=Ip6Address('ff02::1'), source_addresses=[Ip6Add"
                    "ress('2001:db8::1'), Ip6Address('2001:db8::2'), Ip6Address('2001:db8::3')], aux_"
                    "data=b'')"
                ),
                "__bytes__": (
                    b"\x01\x00\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 3,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                    Ip6Address("2001:db8::3"),
                ],
                "aux_data": b"",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record, no sources, aux data."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
                "aux_data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 36,
                "__str__": (
                    "[type 'Mode Is Include', addr ff02::1, aux data b'0123456789ABCDEF']"
                ),
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.MODE_I"
                    "S_INCLUDE: 1>, multicast_address=Ip6Address('ff02::1'), source_addresses=[], aux"
                    "_data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x01\x04\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "aux_data_len": 16,
                "number_of_sources": 0,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [],
                "aux_data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Multicast Address Record, multiple sources, aux data."
            ),
            "_args": [],
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                    Ip6Address("2001:db8::3"),
                ],
                "aux_data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 84,
                "__str__": (
                    "[type 'Mode Is Include', addr ff02::1, sources (2001:db8::1, 2001:db"
                    "8::2, 2001:db8::3), aux data b'0123456789ABCDEF']"
                ),
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.MODE_I"
                    "S_INCLUDE: 1>, multicast_address=Ip6Address('ff02::1'), source_addresses=[Ip6Add"
                    "ress('2001:db8::1'), Ip6Address('2001:db8::2'), Ip6Address('2001:db8::3')], aux_"
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x01\x04\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "aux_data_len": 16,
                "number_of_sources": 3,
                "multicast_address": Ip6Address("ff02::1"),
                "source_addresses": [
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                    Ip6Address("2001:db8::3"),
                ],
                "aux_data": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestIcmp6Mld2MulticastAddressRecordAssembler(TestCase):
    """
    The ICMPv6 MLDv2 Multicast Address Record assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 MLDv2 Multicast Address Record assembler
        object with testcase arguments.
        """

        self._icmp6__mld2__multicast_address_record = (
            Icmp6Mld2MulticastAddressRecord(*self._args, **self._kwargs)
        )

    def test__icmp6__mld2__multicast_address_record__assembler__len(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record '__len__()' method
        returns a correct value.
        """

        self.assertEqual(
            len(self._icmp6__mld2__multicast_address_record),
            self._results["__len__"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__str(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record '__str__()' method
        returns a correct value.
        """

        self.assertEqual(
            str(self._icmp6__mld2__multicast_address_record),
            self._results["__str__"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__repr(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record '__repr__()' method
        returns a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__mld2__multicast_address_record),
            self._results["__repr__"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record '__bytes__()' method
        returns a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__mld2__multicast_address_record),
            self._results["__bytes__"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__type(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'type' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.type,
            self._results["type"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__aux_data_len(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'aux_data_len' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.aux_data_len,
            self._results["aux_data_len"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__number_of_sources(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'number_of_sources' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.number_of_sources,
            self._results["number_of_sources"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__multicast_address(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'multicast_address' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.multicast_address,
            self._results["multicast_address"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__source_addresses(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'source_addresses' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.source_addresses,
            self._results["source_addresses"],
        )

    def test__icmp6__message__mld2__multicast_address_record__assembler__aux_data(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record 'aux_data' property
        returns a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__multicast_address_record.aux_data,
            self._results["aux_data"],
        )
