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
This module contains tests for the IGMP Membership Query assembler —
the querier-side emission path (Phase-2 router work).

net_proto/tests/unit/protocols/igmp/test__igmp__message__query__assembler__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, Ip4Address
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.igmp.igmp__assembler import IgmpAssembler
from net_proto.protocols.igmp.message.igmp__message import IgmpVersion
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IGMPv3 General Query (group 0.0.0.0, no sources).",
            "_kwargs": {
                "version": IgmpVersion.V3,
                "max_resp_code": 100,
                "group_address": Ip4Address("0.0.0.0"),
                "s_flag": False,
                "qrv": 2,
                "qqic": 125,
                "source_addresses": (),
            },
            # IGMPv3 Membership Query (12 bytes, cksum slot zero):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Code = 100
            #   Bytes 2-3 : 0x0000 -> checksum (message.assemble leaves zero)
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            #   Byte 8    : 0x02 -> Resv=0, S=0, QRV=2
            #   Byte 9    : 0x7d -> QQIC = 125
            #   Bytes 10-11: 0x0000 -> Number of Sources = 0
            "_frame": b"\x11\x64\x00\x00\x00\x00\x00\x00\x02\x7d\x00\x00",
            "_len": 12,
        },
        {
            "_description": "IGMPv3 Group-Specific Query (group 239.1.1.1, no sources).",
            "_kwargs": {
                "version": IgmpVersion.V3,
                "max_resp_code": 100,
                "group_address": Ip4Address("239.1.1.1"),
                "s_flag": False,
                "qrv": 2,
                "qqic": 0,
                "source_addresses": (),
            },
            # IGMPv3 Membership Query (12 bytes, cksum slot zero):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Code = 100
            #   Bytes 2-3 : 0x0000 -> checksum
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            #   Byte 8    : 0x02 -> Resv=0, S=0, QRV=2
            #   Byte 9    : 0x00 -> QQIC = 0
            #   Bytes 10-11: 0x0000 -> Number of Sources = 0
            "_frame": b"\x11\x64\x00\x00\xef\x01\x01\x01\x02\x00\x00\x00",
            "_len": 12,
        },
        {
            "_description": "IGMPv3 Group-and-Source-Specific Query (2 sources, S flag set).",
            "_kwargs": {
                "version": IgmpVersion.V3,
                "max_resp_code": 0xFF,
                "group_address": Ip4Address("239.1.1.1"),
                "s_flag": True,
                "qrv": 2,
                "qqic": 0,
                "source_addresses": (Ip4Address("192.0.2.1"), Ip4Address("192.0.2.2")),
            },
            # IGMPv3 Membership Query (20 bytes, cksum slot zero):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0xff -> Max Resp Code = 0xff
            #   Bytes 2-3 : 0x0000 -> checksum
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            #   Byte 8    : 0x0a -> Resv=0, S=1, QRV=2
            #   Byte 9    : 0x00 -> QQIC = 0
            #   Bytes 10-11: 0x0002 -> Number of Sources = 2
            #   Bytes 12-15: 0xc0000201 -> Source 192.0.2.1
            #   Bytes 16-19: 0xc0000202 -> Source 192.0.2.2
            "_frame": (b"\x11\xff\x00\x00\xef\x01\x01\x01\x0a\x00\x00\x02\xc0\x00\x02\x01\xc0\x00\x02\x02"),
            "_len": 20,
        },
        {
            "_description": "IGMPv2 General Query (8-byte form, Max Resp Time non-zero).",
            "_kwargs": {
                "version": IgmpVersion.V2,
                "max_resp_code": 100,
                "group_address": Ip4Address("0.0.0.0"),
            },
            # IGMPv2 Membership Query (8 bytes, cksum slot zero):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x64 -> Max Resp Time = 100
            #   Bytes 2-3 : 0x0000 -> checksum
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            "_frame": b"\x11\x64\x00\x00\x00\x00\x00\x00",
            "_len": 8,
        },
        {
            "_description": "IGMPv1 General Query (8-byte form, Max Resp Time zero).",
            "_kwargs": {
                "version": IgmpVersion.V1,
                "max_resp_code": 0,
                "group_address": Ip4Address("0.0.0.0"),
            },
            # IGMPv1 Membership Query (8 bytes, cksum slot zero):
            #   Byte 0    : 0x11 -> type (Membership Query)
            #   Byte 1    : 0x00 -> Max Resp Time = 0 (IGMPv1 discriminator)
            #   Bytes 2-3 : 0x0000 -> checksum
            #   Bytes 4-7 : 0x00000000 -> Group Address 0.0.0.0 (General Query)
            "_frame": b"\x11\x00\x00\x00\x00\x00\x00\x00",
            "_len": 8,
        },
    ]
)
class TestIgmpMessageQueryAssembler(TestCase):
    """
    The IGMP Membership Query assembler ('assemble' / '__buffer__') tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _frame: bytes
    _len: int

    @override
    def setUp(self) -> None:
        """
        Build the parametrized IGMP Query message.
        """

        self._query = IgmpMessageQuery(**self._kwargs)

    def test__igmp__query__assembler__bytes(self) -> None:
        """
        Ensure the assembled Query message serialises to the exact wire
        frame with the checksum slot left zero for the IGMP base to
        inject.

        Reference: RFC 3376 §4.1 (Membership Query wire format).
        Reference: RFC 2236 §2 (IGMPv1/v2 Query wire format).
        """

        self.assertEqual(
            bytes(self._query),
            self._frame,
            msg=f"Unexpected assembled Query bytes for case: {self._description}",
        )

    def test__igmp__query__assembler__len(self) -> None:
        """
        Ensure the assembled Query reports the on-wire length (8 octets
        for v1/v2, 12 + 4N for v3).

        Reference: RFC 3376 §4.1 (Query message layout).
        """

        self.assertEqual(
            len(self._query),
            self._len,
            msg=f"Unexpected assembled Query length for case: {self._description}",
        )

    def test__igmp__query__assembler__assemble(self) -> None:
        """
        Ensure 'assemble' appends the Query to the buffer list so the
        concatenated buffers equal the message bytes.

        Reference: RFC 3376 §4.1 (Membership Query wire format).
        """

        buffers: list[Buffer] = []
        self._query.assemble(buffers)

        self.assertEqual(
            b"".join(bytes(buffer) for buffer in buffers),
            self._frame,
            msg=f"Unexpected assembled buffer contents for case: {self._description}",
        )

    def test__igmp__query__assembler__roundtrip(self) -> None:
        """
        Ensure a Query survives an assemble then parse round-trip with
        every field preserved.

        Reference: RFC 3376 §4.1 (Membership Query wire format).
        Reference: RFC 3376 §7.1 (Query version discrimination on parse).
        """

        parsed = IgmpMessageQuery.from_buffer(bytes(self._query))

        for field_name in (
            "version",
            "max_resp_code",
            "group_address",
            "s_flag",
            "qrv",
            "qqic",
            "source_addresses",
        ):
            with self.subTest(field=field_name):
                self.assertEqual(
                    getattr(parsed, field_name),
                    getattr(self._query, field_name),
                    msg=f"Unexpected round-tripped {field_name!r} for case: {self._description}",
                )

    def test__igmp__query__assembler__checksum(self) -> None:
        """
        Ensure the IGMP assembler injects a checksum over the whole Query
        message such that the emitted frame checksums to zero.

        Reference: RFC 3376 §4.1.2 (Checksum over the whole IGMP message).
        """

        buffers: list[Buffer] = []
        IgmpAssembler(igmp__message=self._query).assemble(buffers)
        frame = b"".join(bytes(buffer) for buffer in buffers)

        self.assertEqual(
            inet_cksum(frame),
            0,
            msg=f"Assembled Query must checksum to zero for case: {self._description}",
        )
