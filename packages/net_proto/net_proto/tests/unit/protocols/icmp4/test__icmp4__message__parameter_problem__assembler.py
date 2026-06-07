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
Module contains tests for the ICMPv4 Parameter Problem message
assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__parameter_problem__assembler.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest import TestCase

from net_proto import (
    Icmp4Assembler,
    Icmp4MessageParameterProblem,
    Icmp4ParameterProblemCode,
    Icmp4Type,
)
from net_proto.lib.buffer import Buffer
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Parameter Problem, code 0 (Pointer), pointer=0, no data.",
            "_kwargs": {
                "code": Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                "pointer": 0,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type/Code : 12/0, Cksum 0xf3ff (computed), Pointer 0, Unused 0x000000
                    b"\x0c\x00\xf3\xff\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.PARAMETER_PROBLEM,
                "code": Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                "pointer": 0,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Parameter Problem, code 0 (Pointer), pointer=20, no data.",
            "_kwargs": {
                "code": Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                "pointer": 20,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type/Code : 12/0, Cksum 0xdfff (computed), Pointer 20=0x14, Unused 0x000000
                    b"\x0c\x00\xdf\xff\x14\x00\x00\x00"
                ),
                "type": Icmp4Type.PARAMETER_PROBLEM,
                "code": Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                "pointer": 20,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Parameter Problem, code 1 (Required Option Missing), no data.",
            "_kwargs": {
                "code": Icmp4ParameterProblemCode.REQUIRED_OPTION_MISSING,
                "pointer": 0,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type/Code : 12/1, Cksum 0xf3fe (computed), Pointer 0, Unused 0x000000
                    b"\x0c\x01\xf3\xfe\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.PARAMETER_PROBLEM,
                "code": Icmp4ParameterProblemCode.REQUIRED_OPTION_MISSING,
                "pointer": 0,
                "cksum": 0,
                "data": b"",
            },
        },
    ]
)
class TestIcmp4MessageParameterProblemAssembler(TestCase):
    """
    The ICMPv4 Parameter Problem message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Parameter Problem
        message.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageParameterProblem(**self._kwargs),
        )

    def test__icmp4__message__parameter_problem__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals
        ICMP4__PARAMETER_PROBLEM__LEN plus len(data).

        Reference: RFC 792 (Parameter Problem wire-format length = 8 + data).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3 and the pointer
        at byte 4.

        Reference: RFC 792 (Parameter Problem wire format with pointer
        as 5th byte).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp4Type.PARAMETER_PROBLEM).

        Reference: RFC 792 (Parameter Problem type field is 12).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (Parameter Problem code 0/1/2).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__assembler__pointer(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'pointer'
        field — the byte offset into the original datagram identifying
        the offending field.

        Reference: RFC 792 (Parameter Problem pointer field).
        """

        self.assertEqual(
            cast(Icmp4MessageParameterProblem, self._icmp4__assembler.message).pointer,
            self._results["pointer"],
            msg=f"Unexpected 'pointer' for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' yields the same wire bytes as 'bytes()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )
