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
This module contains tests for the IGMPv3 Membership Report assembler.

net_proto/tests/unit/protocols/igmp/test__igmp__message__v3_report__assembler.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3GroupRecord,
    IgmpV3RecordType,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IGMPv3 Report with no group records (empty 8-byte form).",
            "_kwargs": {"records": []},
            "_results": {
                "__len__": 8,
                "__str__": "IGMPv3 Report",
                "number_of_records": 0,
                # IGMPv3 Membership Report (8 bytes):
                #   Byte 0    : 0x22 -> type (V3 Membership Report)
                #   Byte 1    : 0x00 -> Reserved
                #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
                #   Bytes 4-5 : 0x0000 -> Reserved
                #   Bytes 6-7 : 0x0000 -> Number of Group Records = 0
                "__bytes__": b"\x22\x00\x00\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "IGMPv3 Report with one MODE_IS_EXCLUDE record.",
            "_kwargs": {
                "records": [
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip4Address("239.1.1.1"),
                    )
                ]
            },
            "_results": {
                "__len__": 16,
                "__str__": "IGMPv3 Report, records [type 'Mode Is Exclude', addr 239.1.1.1]",
                "number_of_records": 1,
                # IGMPv3 Membership Report (16 bytes):
                #   Bytes 0-7  : header, Number of Group Records = 1
                #   Bytes 8-15 : Group Record (MODE_IS_EXCLUDE, 239.1.1.1)
                "__bytes__": b"\x22\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\xef\x01\x01\x01",
            },
        },
        {
            "_description": "IGMPv3 Report with two records (one carrying a source).",
            "_kwargs": {
                "records": [
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip4Address("239.1.1.1"),
                    ),
                    IgmpV3GroupRecord(
                        type=IgmpV3RecordType.ALLOW_NEW_SOURCES,
                        multicast_address=Ip4Address("239.2.2.2"),
                        source_addresses=[Ip4Address("192.0.2.1")],
                    ),
                ]
            },
            "_results": {
                "__len__": 28,
                "__str__": (
                    "IGMPv3 Report, records [type 'Mode Is Exclude', addr 239.1.1.1], "
                    "[type 'Allow New Sources', addr 239.2.2.2, sources (192.0.2.1)]"
                ),
                "number_of_records": 2,
                # IGMPv3 Membership Report (28 bytes):
                #   Bytes 0-7   : header, Number of Group Records = 2
                #   Bytes 8-15  : Group Record (MODE_IS_EXCLUDE, 239.1.1.1)
                #   Bytes 16-27 : Group Record (ALLOW_NEW_SOURCES, 239.2.2.2, src 192.0.2.1)
                "__bytes__": (
                    b"\x22\x00\x00\x00\x00\x00\x00\x02"
                    b"\x02\x00\x00\x00\xef\x01\x01\x01"
                    b"\x05\x00\x00\x01\xef\x02\x02\x02\xc0\x00\x02\x01"
                ),
            },
        },
    ]
)
class TestIgmpMessageV3ReportAssembler(TestCase):
    """
    The IGMPv3 Membership Report assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the parametrized IGMPv3 Report instance.
        """

        self._report = IgmpMessageV3Report(**self._kwargs)

    def test__igmp__v3_report__len(self) -> None:
        """
        Ensure '__len__()' returns the 8-byte header plus the total
        length of all group records.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        self.assertEqual(
            len(self._report),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__igmp__v3_report__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical IGMPv3 Report log line.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        self.assertEqual(
            str(self._report),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__igmp__v3_report__number_of_records(self) -> None:
        """
        Ensure 'number_of_records' reports the count of group records.

        Reference: RFC 3376 §4.2.3 (Number of Group Records).
        """

        self.assertEqual(
            self._report.number_of_records,
            self._results["number_of_records"],
            msg=f"Unexpected number_of_records for case: {self._description}",
        )

    def test__igmp__v3_report__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the on-wire report encoding (header +
        concatenated group records), with the checksum slot left zero
        for the IGMP base to inject.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        self.assertEqual(
            bytes(self._report),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__igmp__v3_report__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends the header buffer and the records
        buffer (two entries) whose concatenation equals 'bytes()'.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        buffers: list[Any] = []
        self._report.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=f"assemble() must append header + records for case: {self._description}",
        )
        self.assertEqual(
            b"".join(bytes(part) for part in buffers),
            self._results["__bytes__"],
            msg=f"assemble() concatenation must equal bytes() for case: {self._description}",
        )

    def test__igmp__v3_report__roundtrip(self) -> None:
        """
        Ensure the on-wire bytes round-trip through 'from_buffer()' and
        reproduce a structurally identical report.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        parsed = IgmpMessageV3Report.from_buffer(bytes(self._report))

        self.assertEqual(
            parsed.records,
            self._report.records,
            msg=f"Round-trip through from_buffer() must preserve records for case: {self._description}",
        )
