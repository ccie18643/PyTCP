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
Module contains tests for the ICMPv6 MLDv2 Multicast Address Record
assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__assembler.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "MLDv2 Multicast Address Record (MODE_IS_INCLUDE, bare 20-byte form).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Mode Is Include', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x01 (MODE_IS_INCLUDE)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (MODE_IS_EXCLUDE).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Mode Is Exclude', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE: 2>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x02 (MODE_IS_EXCLUDE)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (CHANGE_TO_INCLUDE).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Change To Include', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE: 3>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x03 (CHANGE_TO_INCLUDE)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (CHANGE_TO_EXCLUDE).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Change To Exclude', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE: 4>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x04 (CHANGE_TO_EXCLUDE)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (ALLOW_NEW_SOURCES).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Allow New Sources', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES: 5>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x05 (ALLOW_NEW_SOURCES)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (BLOCK_OLD_SOURCES).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                "multicast_address": Ip6Address("ff02::1"),
            },
            "_results": {
                "__len__": 20,
                "__str__": "[type 'Block Old Sources', addr ff02::1]",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES: 6>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x06 (BLOCK_OLD_SOURCES)
                    #   Aux dlen  : 0
                    #   Src count : 0
                    #   Multicast : ff02::1
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
            "_description": "MLDv2 Multicast Address Record (3 sources, no aux data).",
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
                    "[type 'Mode Is Include', addr ff02::1, " "sources (2001:db8::1, 2001:db8::2, 2001:db8::3)]"
                ),
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=["
                    "Ip6Address('2001:db8::1'), "
                    "Ip6Address('2001:db8::2'), "
                    "Ip6Address('2001:db8::3')"
                    "], "
                    "aux_data=b'')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x01 (MODE_IS_INCLUDE)
                    #   Aux dlen  : 0
                    #   Src count : 3
                    #   Multicast : ff02::1
                    #   Sources   : 2001:db8::1, 2001:db8::2, 2001:db8::3
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
            "_description": "MLDv2 Multicast Address Record (no sources, 16-byte aux data).",
            "_kwargs": {
                "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip6Address("ff02::1"),
                "aux_data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 36,
                "__str__": "[type 'Mode Is Include', addr ff02::1, aux data b'0123456789ABCDEF']",
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[], "
                    "aux_data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x01 (MODE_IS_INCLUDE)
                    #   Aux dlen  : 4 (32-bit words → 16 bytes)
                    #   Src count : 0
                    #   Multicast : ff02::1
                    #   Aux data  : "0123456789ABCDEF"
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
            "_description": "MLDv2 Multicast Address Record (3 sources, 16-byte aux data).",
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
                    "[type 'Mode Is Include', addr ff02::1, "
                    "sources (2001:db8::1, 2001:db8::2, 2001:db8::3), "
                    "aux data b'0123456789ABCDEF']"
                ),
                "__repr__": (
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=["
                    "Ip6Address('2001:db8::1'), "
                    "Ip6Address('2001:db8::2'), "
                    "Ip6Address('2001:db8::3')"
                    "], "
                    "aux_data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # MLDv2 Multicast Address Record
                    #   Type      : 0x01 (MODE_IS_INCLUDE)
                    #   Aux dlen  : 4 (32-bit words → 16 bytes)
                    #   Src count : 3
                    #   Multicast : ff02::1
                    #   Sources   : 2001:db8::1, 2001:db8::2, 2001:db8::3
                    #   Aux data  : "0123456789ABCDEF"
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
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the parametrized MLDv2 Multicast Address Record instance.
        """

        self._record = Icmp6Mld2MulticastAddressRecord(**self._kwargs)

    def test__icmp6__mld2__multicast_address_record__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the total on-wire length
        (header + sources + aux_data).

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            len(self._record),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical MLDv2 record log line.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            str(self._record),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' matches the dataclass-generated repr.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            repr(self._record),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the on-wire record encoding.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            bytes(self._record),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__type(self) -> None:
        """
        Ensure the 'type' field is preserved.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__aux_data_len(self) -> None:
        """
        Ensure 'aux_data_len' reports the byte length (not 32-bit words)
        of the 'aux_data' buffer.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.aux_data_len,
            self._results["aux_data_len"],
            msg=f"Unexpected 'aux_data_len' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__number_of_sources(self) -> None:
        """
        Ensure 'number_of_sources' reports the count of entries in
        'source_addresses'.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.number_of_sources,
            self._results["number_of_sources"],
            msg=f"Unexpected 'number_of_sources' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__multicast_address(self) -> None:
        """
        Ensure the 'multicast_address' field is preserved.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.multicast_address,
            self._results["multicast_address"],
            msg=f"Unexpected 'multicast_address' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__source_addresses(self) -> None:
        """
        Ensure the 'source_addresses' list is preserved in order.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.source_addresses,
            self._results["source_addresses"],
            msg=f"Unexpected 'source_addresses' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__aux_data(self) -> None:
        """
        Ensure the 'aux_data' field is preserved verbatim.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self.assertEqual(
            self._record.aux_data,
            self._results["aux_data"],
            msg=f"Unexpected 'aux_data' for case: {self._description}",
        )

    def test__icmp6__mld2__multicast_address_record__assembler__roundtrip(self) -> None:
        """
        Ensure the on-wire bytes round-trip through 'from_buffer()' and
        reproduce a structurally identical record.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        parsed = Icmp6Mld2MulticastAddressRecord.from_buffer(bytes(self._record))

        self.assertEqual(
            parsed,
            self._record,
            msg=f"Round-trip through from_buffer() must preserve the record for case: {self._description}",
        )
