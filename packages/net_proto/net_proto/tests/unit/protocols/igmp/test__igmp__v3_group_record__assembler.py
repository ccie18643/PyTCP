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
This module contains tests for the IGMPv3 Group Record assembler.

net_proto/tests/unit/protocols/igmp/test__igmp__v3_group_record__assembler.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3GroupRecord,
    IgmpV3RecordType,
)


@parameterized_class(
    [
        {
            "_description": "IGMPv3 Group Record (MODE_IS_INCLUDE, bare 8-byte form).",
            "_kwargs": {
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Mode Is Include', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x01\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (MODE_IS_EXCLUDE).",
            "_kwargs": {
                "type": IgmpV3RecordType.MODE_IS_EXCLUDE,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Mode Is Exclude', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.MODE_IS_EXCLUDE: 2>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x02 (MODE_IS_EXCLUDE)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x02\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.MODE_IS_EXCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (CHANGE_TO_INCLUDE_MODE).",
            "_kwargs": {
                "type": IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Change To Include Mode', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE: 3>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x03 (CHANGE_TO_INCLUDE_MODE)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x03\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (CHANGE_TO_EXCLUDE_MODE).",
            "_kwargs": {
                "type": IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Change To Exclude Mode', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE: 4>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x04 (CHANGE_TO_EXCLUDE_MODE)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x04\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (ALLOW_NEW_SOURCES).",
            "_kwargs": {
                "type": IgmpV3RecordType.ALLOW_NEW_SOURCES,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Allow New Sources', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.ALLOW_NEW_SOURCES: 5>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x05 (ALLOW_NEW_SOURCES)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x05\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.ALLOW_NEW_SOURCES,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (BLOCK_OLD_SOURCES).",
            "_kwargs": {
                "type": IgmpV3RecordType.BLOCK_OLD_SOURCES,
                "multicast_address": Ip4Address("239.1.1.1"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "[type 'Block Old Sources', addr 239.1.1.1]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.BLOCK_OLD_SOURCES: 6>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x06 (BLOCK_OLD_SOURCES)
                #   Aux dlen    : 0
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                "__bytes__": b"\x06\x00\x00\x00\xef\x01\x01\x01",
                "type": IgmpV3RecordType.BLOCK_OLD_SOURCES,
                "aux_data_len": 0,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (2 sources, no aux data).",
            "_kwargs": {
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("192.0.2.2"),
                ],
            },
            "_results": {
                "__len__": 16,
                "__str__": "[type 'Mode Is Include', addr 239.1.1.1, sources (192.0.2.1, 192.0.2.2)]",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[Ip4Address('192.0.2.1'), Ip4Address('192.0.2.2')], "
                    "aux_data=b'')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen    : 0
                #   Src count    : 2
                #   Multicast    : 239.1.1.1
                #   Sources      : 192.0.2.1, 192.0.2.2
                "__bytes__": (b"\x01\x00\x00\x02\xef\x01\x01\x01\xc0\x00\x02\x01\xc0\x00\x02\x02"),
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "aux_data_len": 0,
                "number_of_sources": 2,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("192.0.2.2"),
                ],
                "aux_data": b"",
            },
        },
        {
            "_description": "IGMPv3 Group Record (no sources, 4-byte aux data).",
            "_kwargs": {
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "multicast_address": Ip4Address("239.1.1.1"),
                "aux_data": b"\xde\xad\xbe\xef",
            },
            "_results": {
                "__len__": 12,
                "__str__": "[type 'Mode Is Include', addr 239.1.1.1, aux data b'\\xde\\xad\\xbe\\xef']",
                "__repr__": (
                    "IgmpV3GroupRecord("
                    "type=<IgmpV3RecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip4Address('239.1.1.1'), "
                    "source_addresses=[], "
                    "aux_data=b'\\xde\\xad\\xbe\\xef')"
                ),
                # IGMPv3 Group Record
                #   Record type : 0x01 (MODE_IS_INCLUDE)
                #   Aux dlen    : 1 (32-bit words -> 4 bytes)
                #   Src count    : 0
                #   Multicast    : 239.1.1.1
                #   Aux data     : 0xdeadbeef
                "__bytes__": b"\x01\x01\x00\x00\xef\x01\x01\x01\xde\xad\xbe\xef",
                "type": IgmpV3RecordType.MODE_IS_INCLUDE,
                "aux_data_len": 4,
                "number_of_sources": 0,
                "multicast_address": Ip4Address("239.1.1.1"),
                "source_addresses": [],
                "aux_data": b"\xde\xad\xbe\xef",
            },
        },
    ]
)
class TestIgmpV3GroupRecordAssembler(TestCase):
    """
    The IGMPv3 Group Record assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the parametrized IGMPv3 Group Record instance.
        """

        self._record = IgmpV3GroupRecord(**self._kwargs)

    def test__igmp__v3_group_record__len(self) -> None:
        """
        Ensure '__len__()' returns the total on-wire length
        (8-byte header + sources + aux_data).

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        self.assertEqual(
            len(self._record),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__igmp__v3_group_record__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical IGMPv3 record log line.

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        self.assertEqual(
            str(self._record),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__igmp__v3_group_record__repr(self) -> None:
        """
        Ensure '__repr__()' matches the dataclass-generated repr.

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        self.assertEqual(
            repr(self._record),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__igmp__v3_group_record__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the on-wire record encoding, with the
        'aux_data_len' octet expressed in 32-bit words.

        Reference: RFC 3376 §4.2.4 (Group Record).
        Reference: RFC 3376 §4.2.6 (Aux Data Len in 32-bit words).
        """

        self.assertEqual(
            bytes(self._record),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__igmp__v3_group_record__type(self) -> None:
        """
        Ensure the 'type' field is preserved.

        Reference: RFC 3376 §4.2.12 (Record Type values).
        """

        self.assertEqual(
            self._record.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__igmp__v3_group_record__aux_data_len(self) -> None:
        """
        Ensure 'aux_data_len' reports the byte length (not 32-bit words)
        of the 'aux_data' buffer.

        Reference: RFC 3376 §4.2.6 (Aux Data Len).
        """

        self.assertEqual(
            self._record.aux_data_len,
            self._results["aux_data_len"],
            msg=f"Unexpected 'aux_data_len' for case: {self._description}",
        )

    def test__igmp__v3_group_record__number_of_sources(self) -> None:
        """
        Ensure 'number_of_sources' reports the count of entries in
        'source_addresses'.

        Reference: RFC 3376 §4.2.7 (Number of Sources).
        """

        self.assertEqual(
            self._record.number_of_sources,
            self._results["number_of_sources"],
            msg=f"Unexpected 'number_of_sources' for case: {self._description}",
        )

    def test__igmp__v3_group_record__multicast_address(self) -> None:
        """
        Ensure the 'multicast_address' field is preserved.

        Reference: RFC 3376 §4.2.8 (Multicast Address).
        """

        self.assertEqual(
            self._record.multicast_address,
            self._results["multicast_address"],
            msg=f"Unexpected 'multicast_address' for case: {self._description}",
        )

    def test__igmp__v3_group_record__source_addresses(self) -> None:
        """
        Ensure the 'source_addresses' list is preserved in order.

        Reference: RFC 3376 §4.2.9 (Source Address [i]).
        """

        self.assertEqual(
            self._record.source_addresses,
            self._results["source_addresses"],
            msg=f"Unexpected 'source_addresses' for case: {self._description}",
        )

    def test__igmp__v3_group_record__aux_data(self) -> None:
        """
        Ensure the 'aux_data' field is preserved verbatim.

        Reference: RFC 3376 §4.2.10 (Auxiliary Data).
        """

        self.assertEqual(
            self._record.aux_data,
            self._results["aux_data"],
            msg=f"Unexpected 'aux_data' for case: {self._description}",
        )

    def test__igmp__v3_group_record__roundtrip(self) -> None:
        """
        Ensure the on-wire bytes round-trip through 'from_buffer()' and
        reproduce a structurally identical record.

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        parsed = IgmpV3GroupRecord.from_buffer(bytes(self._record))

        self.assertEqual(
            parsed,
            self._record,
            msg=f"Round-trip through from_buffer() must preserve the record for case: {self._description}",
        )
