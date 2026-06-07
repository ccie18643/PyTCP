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
Module contains tests for the ICMPv6 Time Exceeded message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__time_exceeded__assembler.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    Icmp6Assembler,
    Icmp6MessageTimeExceeded,
    Icmp6TimeExceededCode,
    Icmp6Type,
)
from net_proto.lib.buffer import Buffer
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Time Exceeded, code 0 (Hop Limit Exceeded In Transit), no data.",
            "_kwargs": {
                "code": Icmp6TimeExceededCode.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "type": Icmp6Type.TIME_EXCEEDED,
                "code": Icmp6TimeExceededCode.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
            },
        },
        {
            "_description": "ICMPv6 Time Exceeded, code 1 (Fragment Reassembly Time Exceeded), no data.",
            "_kwargs": {
                "code": Icmp6TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "type": Icmp6Type.TIME_EXCEEDED,
                "code": Icmp6TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
            },
        },
    ]
)
class TestIcmp6MessageTimeExceededAssembler(TestCase):
    """
    The ICMPv6 Time Exceeded message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Time Exceeded
        message.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageTimeExceeded(**self._kwargs),
        )

    def test__icmp6__message__time_exceeded__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals
        ICMP6__TIME_EXCEEDED__LEN plus len(data).

        Reference: RFC 4443 §3.3 (Time Exceeded wire-format length =
        8 + data).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp6__message__time_exceeded__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp6Type.TIME_EXCEEDED).

        Reference: RFC 4443 §3.3 (Time Exceeded type field is 3).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__time_exceeded__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 4443 §3.3 (Time Exceeded codes 0/1).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__message__time_exceeded__assembler__assemble_round_trip(self) -> None:
        """
        Ensure 'assemble()' yields wire bytes that round-trip cleanly:
        the first byte is type=3 (TIME_EXCEEDED) and the second is the
        code value.

        Reference: RFC 4443 §3.3 (Time Exceeded type byte is 3).
        """

        buffers: list[Buffer] = []
        self._icmp6__assembler.assemble(buffers)
        wire = b"".join(bytes(b) for b in buffers)

        self.assertEqual(wire[0], 3, msg="First wire byte must be type=3 (TIME_EXCEEDED).")
        self.assertEqual(wire[1], int(self._results["code"]), msg="Second wire byte must be the code value.")
