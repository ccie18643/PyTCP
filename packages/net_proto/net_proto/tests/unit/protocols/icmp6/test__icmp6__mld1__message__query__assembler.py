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
Module contains tests for the ICMPv6 MLDv1 Query message assembler —
the querier-side emission path under MLDv1-compat interop (Phase-2
router work).

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld1__message__query__assembler.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, Ip6Address
from net_proto import Icmp6Assembler, Icmp6Type
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__query import (
    Icmp6Mld1MessageQuery,
    Icmp6Mld1QueryCode,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "MLDv1 General Query (multicast ::).",
            "_kwargs": {
                "maximum_response_delay": 10000,
                "multicast_address": Ip6Address("::"),
            },
            # ICMPv6 MLDv1 Query (24 bytes):
            #   Bytes 0-1   : 0x8200 -> type=130 (Listener Query), code=0
            #   Bytes 2-3   : 0x56ef -> checksum (computed, pshdr_sum=0)
            #   Bytes 4-5   : 0x2710 -> Maximum Response Delay = 10000
            #   Bytes 6-7   : 0x0000 -> Reserved
            #   Bytes 8-23  : ::     -> Multicast Address (General Query)
            "_frame": bytes.fromhex("820056ef2710000000000000000000000000000000000000"),
        },
        {
            "_description": "MLDv1 Multicast-Address-Specific Query (ff02::1).",
            "_kwargs": {
                "maximum_response_delay": 1000,
                "multicast_address": Ip6Address("ff02::1"),
            },
            # ICMPv6 MLDv1 Query (24 bytes):
            #   Bytes 0-1   : 0x8200 -> type=130, code=0
            #   Bytes 2-3   : 0x7b13 -> checksum
            #   Bytes 4-5   : 0x03e8 -> Maximum Response Delay = 1000
            #   Bytes 6-7   : 0x0000 -> Reserved
            #   Bytes 8-23  : ff02::1 -> Multicast Address
            "_frame": bytes.fromhex("82007b1303e80000ff020000000000000000000000000001"),
        },
    ]
)
class TestIcmp6Mld1MessageQueryAssembler(TestCase):
    """
    The ICMPv6 MLDv1 Query message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _frame: bytes

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized MLDv1 Query message.
        """

        self._message = Icmp6Mld1MessageQuery(**self._kwargs)
        self._assembler = Icmp6Assembler(icmp6__message=self._message)

    def test__icmp6__mld1__query__assembler__len(self) -> None:
        """
        Ensure the assembler length is the fixed 24-octet MLDv1 message
        form.

        Reference: RFC 2710 §3.1 (MLDv1 Query wire format).
        Reference: RFC 3810 §8.1 (MLDv1 Query is the 24-octet form).
        """

        self.assertEqual(
            len(self._assembler),
            24,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__mld1__query__assembler__bytes(self) -> None:
        """
        Ensure the assembled MLDv1 Query serialises to the full wire form
        including the recomputed Internet checksum at bytes 2-3.

        Reference: RFC 2710 §3.1 (MLDv1 Query wire format).
        """

        self.assertEqual(
            bytes(self._assembler),
            self._frame,
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__mld1__query__assembler__assemble(self) -> None:
        """
        Ensure 'assemble' appends the packed buffers so the concatenation
        equals the full wire form.

        Reference: RFC 2710 §3.1 (MLDv1 Query wire format).
        """

        buffers: list[Buffer] = []
        self._assembler.assemble(buffers)

        self.assertEqual(
            b"".join(bytes(buffer) for buffer in buffers),
            self._frame,
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__mld1__query__assembler__roundtrip(self) -> None:
        """
        Ensure a MLDv1 Query survives an assemble then parse round-trip
        with every field preserved.

        Reference: RFC 2710 §3.1 (MLDv1 Query wire format).
        """

        parsed = Icmp6Mld1MessageQuery.from_buffer(self._frame)

        self.assertEqual(
            parsed.type,
            Icmp6Type.MULTICAST_LISTENER_QUERY,
            msg=f"Unexpected round-tripped type for case: {self._description}",
        )
        self.assertEqual(
            parsed.code,
            Icmp6Mld1QueryCode.DEFAULT,
            msg=f"Unexpected round-tripped code for case: {self._description}",
        )
        for field_name in ("maximum_response_delay", "multicast_address"):
            with self.subTest(field=field_name):
                self.assertEqual(
                    getattr(parsed, field_name),
                    getattr(self._message, field_name),
                    msg=f"Unexpected round-tripped {field_name!r} for case: {self._description}",
                )
