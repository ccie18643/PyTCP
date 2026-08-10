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
Module contains tests for the ICMPv6 Parameter Problem message
assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__parameter_problem__assembler.py

ver 3.0.9
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
    Icmp6Type,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Parameter Problem, code 0 (Erroneous Header Field), pointer=40.",
            "_kwargs": {
                "code": Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                "pointer": 40,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "type": Icmp6Type.PARAMETER_PROBLEM,
                "code": Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                "pointer": 40,
            },
        },
        {
            "_description": "ICMPv6 Parameter Problem, code 1 (Unrecognized Next Header), pointer=6.",
            "_kwargs": {
                "code": Icmp6ParameterProblemCode.UNRECOGNIZED_NEXT_HEADER,
                "pointer": 6,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "type": Icmp6Type.PARAMETER_PROBLEM,
                "code": Icmp6ParameterProblemCode.UNRECOGNIZED_NEXT_HEADER,
                "pointer": 6,
            },
        },
        {
            "_description": "ICMPv6 Parameter Problem, code 2 (Unrecognized IPv6 Option), pointer=44.",
            "_kwargs": {
                "code": Icmp6ParameterProblemCode.UNRECOGNIZED_IPV6_OPTION,
                "pointer": 44,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "type": Icmp6Type.PARAMETER_PROBLEM,
                "code": Icmp6ParameterProblemCode.UNRECOGNIZED_IPV6_OPTION,
                "pointer": 44,
            },
        },
    ]
)
class TestIcmp6MessageParameterProblemAssembler(TestCase):
    """
    The ICMPv6 Parameter Problem message assembler tests.
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

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageParameterProblem(**self._kwargs),
        )

    def test__icmp6__message__parameter_problem__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals
        ICMP6__PARAMETER_PROBLEM__LEN plus len(data).

        Reference: RFC 4443 §3.4 (Parameter Problem wire-format length =
        8 + data).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp6__message__parameter_problem__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp6Type.PARAMETER_PROBLEM).

        Reference: RFC 4443 §3.4 (Parameter Problem type field is 4).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__parameter_problem__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 4443 §3.4 (Parameter Problem codes 0/1/2).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__message__parameter_problem__assembler__pointer(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'pointer'
        field — the 32-bit byte offset into the original packet
        identifying the offending field.

        Reference: RFC 4443 §3.4 (Parameter Problem pointer field is
        32 bits).
        """

        self.assertEqual(
            cast(Icmp6MessageParameterProblem, self._icmp6__assembler.message).pointer,
            self._results["pointer"],
            msg=f"Unexpected 'pointer' for case: {self._description}",
        )

    def test__icmp6__message__parameter_problem__assembler__assemble_round_trip(self) -> None:
        """
        Ensure 'assemble()' yields wire bytes that round-trip cleanly:
        first byte type=4, second byte code, bytes 4-7 the 32-bit
        pointer in big-endian.

        Reference: RFC 4443 §3.4 (Parameter Problem wire format).
        """

        buffers: list[Buffer] = []
        self._icmp6__assembler.assemble(buffers)
        wire = b"".join(bytes(b) for b in buffers)

        self.assertEqual(wire[0], 4, msg="First wire byte must be type=4 (PARAMETER_PROBLEM).")
        self.assertEqual(wire[1], int(self._results["code"]), msg="Second wire byte must be the code value.")
        self.assertEqual(
            int.from_bytes(wire[4:8], "big"),
            self._results["pointer"],
            msg="Bytes 4-7 must encode the 32-bit pointer in big-endian.",
        )


class TestIcmp6MessageParameterProblemWithData(TestCase):
    """
    The ICMPv6 Parameter Problem with-embedded-data length tests.
    """

    def test__icmp6__message__parameter_problem__len_with_data(self) -> None:
        """
        Ensure 'len()' on a Parameter Problem message carrying embedded data
        equals the 8-byte message header plus the data length, pinning
        the 'LEN + len(data)' computation against a '-' corruption that
        the existing empty-data fixtures cannot catch.

        Reference: RFC 4443 (Parameter Problem message length is 8 octets plus embedded data).
        """

        data = bytes(range(28))
        message = Icmp6MessageParameterProblem(
            code=Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD, pointer=4, data=data
        )

        self.assertEqual(
            len(message),
            8 + len(data),
            msg="Parameter Problem length must be the 8-byte header plus the embedded data length.",
        )
        self.assertEqual(
            len(bytes(Icmp6Assembler(icmp6__message=message))),
            8 + len(data),
            msg="Parameter Problem assembled wire length must be 8 + the embedded data length.",
        )
