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
Module contains tests for the ICMPv6 MLDv2 Query message assembler —
the querier-side emission path (Phase-2 router work).

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__query__assembler.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, Ip6Address
from net_proto import Icmp6Assembler, Icmp6Type
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__query import (
    Icmp6Mld2MessageQuery,
    Icmp6Mld2QueryCode,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "MLDv2 General Query (multicast ::, no sources).",
            "_kwargs": {
                "maximum_response_code": 10000,
                "multicast_address": Ip6Address("::"),
                "qrv": 2,
                "qqic": 125,
            },
            # ICMPv6 MLDv2 Query (28 bytes):
            #   Bytes 0-1   : 0x8200 -> type=130 (Listener Query), code=0
            #   Bytes 2-3   : 0x5472 -> checksum (computed, pshdr_sum=0)
            #   Bytes 4-5   : 0x2710 -> Maximum Response Code = 10000
            #   Bytes 6-7   : 0x0000 -> Reserved
            #   Bytes 8-23  : ::     -> Multicast Address (General Query)
            #   Byte 24     : 0x02   -> Resv=0, S=0, QRV=2
            #   Byte 25     : 0x7d   -> QQIC = 125
            #   Bytes 26-27 : 0x0000 -> Number of Sources = 0
            "_frame": bytes.fromhex("820054722710000000000000000000000000000000000000027d0000"),
            "_len": 28,
            "_buffers": 2,
        },
        {
            "_description": "MLDv2 Multicast-Address-Specific Query (ff38::1234, no sources).",
            "_kwargs": {
                "maximum_response_code": 10000,
                "multicast_address": Ip6Address("ff38::1234"),
                "qrv": 2,
                "qqic": 125,
            },
            # ICMPv6 MLDv2 Query (28 bytes):
            #   Bytes 0-1   : 0x8200 -> type=130, code=0
            #   Bytes 2-3   : 0x4305 -> checksum
            #   Bytes 4-5   : 0x2710 -> Maximum Response Code = 10000
            #   Bytes 6-7   : 0x0000 -> Reserved
            #   Bytes 8-23  : ff38::1234 -> Multicast Address
            #   Byte 24     : 0x02   -> Resv=0, S=0, QRV=2
            #   Byte 25     : 0x7d   -> QQIC = 125
            #   Bytes 26-27 : 0x0000 -> Number of Sources = 0
            "_frame": bytes.fromhex("8200430527100000ff380000000000000000000000001234027d0000"),
            "_len": 28,
            "_buffers": 2,
        },
        {
            "_description": "MLDv2 Multicast-Address-and-Source-Specific Query (2 sources, S flag set).",
            "_kwargs": {
                "maximum_response_code": 10000,
                "multicast_address": Ip6Address("ff38::1234"),
                "s_flag": True,
                "qrv": 2,
                "qqic": 125,
                "source_addresses": (Ip6Address("2001:db8::1"), Ip6Address("2001:db8::2")),
            },
            # ICMPv6 MLDv2 Query (60 bytes = 28-byte header + 2 × 16-byte sources):
            #   Bytes 0-1   : 0x8200 -> type=130, code=0
            #   Bytes 2-3   : 0xdf8d -> checksum
            #   Bytes 4-5   : 0x2710 -> Maximum Response Code = 10000
            #   Bytes 6-7   : 0x0000 -> Reserved
            #   Bytes 8-23  : ff38::1234 -> Multicast Address
            #   Byte 24     : 0x0a   -> Resv=0, S=1, QRV=2
            #   Byte 25     : 0x7d   -> QQIC = 125
            #   Bytes 26-27 : 0x0002 -> Number of Sources = 2
            #   Bytes 28-43 : 2001:db8::1 -> Source Address [1]
            #   Bytes 44-59 : 2001:db8::2 -> Source Address [2]
            "_frame": bytes.fromhex(
                "8200df8d27100000ff3800000000000000000000000012340a7d0002"
                "20010db800000000000000000000000120010db8000000000000000000000002"
            ),
            "_len": 60,
            "_buffers": 2,
        },
    ]
)
class TestIcmp6Mld2MessageQueryAssembler(TestCase):
    """
    The ICMPv6 MLDv2 Query message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _frame: bytes
    _len: int
    _buffers: int

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized MLDv2 Query message.
        """

        self._message = Icmp6Mld2MessageQuery(**self._kwargs)
        self._assembler = Icmp6Assembler(icmp6__message=self._message)

    def test__icmp6__mld2__query__assembler__len(self) -> None:
        """
        Ensure the assembler length equals the 28-byte fixed header plus
        16 bytes per source address.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        self.assertEqual(
            len(self._assembler),
            self._len,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__mld2__query__assembler__bytes(self) -> None:
        """
        Ensure the assembled MLDv2 Query serialises to the full wire form
        including the recomputed Internet checksum at bytes 2-3.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        self.assertEqual(
            bytes(self._assembler),
            self._frame,
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__mld2__query__assembler__assemble(self) -> None:
        """
        Ensure 'assemble' appends the packed buffers so the concatenation
        equals the full wire form.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        buffers: list[Buffer] = []
        self._assembler.assemble(buffers)

        self.assertEqual(
            b"".join(bytes(buffer) for buffer in buffers),
            self._frame,
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__mld2__query__assembler__buffer_layout(self) -> None:
        """
        Ensure 'assemble' appends exactly two buffers — the 28-byte header
        followed by the concatenated source list — so the ICMPv6 checksum
        back-patch targets the header buffer.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        buffers: list[Buffer] = []
        self._assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            self._buffers,
            msg=f"assemble() must append exactly {self._buffers} buffers for case: {self._description}",
        )
        self.assertEqual(
            len(buffers[0]),
            28,
            msg=f"First buffer must be the 28-byte MLDv2 Query header for case: {self._description}",
        )

    def test__icmp6__mld2__query__assembler__roundtrip(self) -> None:
        """
        Ensure a MLDv2 Query survives an assemble then parse round-trip
        with every field preserved.

        Reference: RFC 3810 §5.1 (MLDv2 Query wire format).
        """

        parsed = Icmp6Mld2MessageQuery.from_buffer(self._frame)

        self.assertEqual(
            parsed.type,
            Icmp6Type.MULTICAST_LISTENER_QUERY,
            msg=f"Unexpected round-tripped type for case: {self._description}",
        )
        self.assertEqual(
            parsed.code,
            Icmp6Mld2QueryCode.DEFAULT,
            msg=f"Unexpected round-tripped code for case: {self._description}",
        )
        for field_name in (
            "maximum_response_code",
            "multicast_address",
            "s_flag",
            "qrv",
            "qqic",
            "source_addresses",
        ):
            with self.subTest(field=field_name):
                self.assertEqual(
                    getattr(parsed, field_name),
                    getattr(self._message, field_name),
                    msg=f"Unexpected round-tripped {field_name!r} for case: {self._description}",
                )
