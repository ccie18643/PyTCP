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
parser operation.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__parameter_problem__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            hop=64,
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
            pshdr_sum=0,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Parameter Problem, code 0 (Erroneous Header Field), pointer=40.",
            "_code": Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
            "_pointer": 40,
        },
        {
            "_description": "ICMPv6 Parameter Problem, code 1 (Unrecognized Next Header), pointer=6.",
            "_code": Icmp6ParameterProblemCode.UNRECOGNIZED_NEXT_HEADER,
            "_pointer": 6,
        },
        {
            "_description": "ICMPv6 Parameter Problem, code 2 (Unrecognized IPv6 Option), pointer=44.",
            "_code": Icmp6ParameterProblemCode.UNRECOGNIZED_IPV6_OPTION,
            "_pointer": 44,
        },
    ]
)
class TestIcmp6MessageParameterProblemParser(TestCase):
    """
    The ICMPv6 Parameter Problem message parser-operation tests.
    """

    _description: str
    _code: Icmp6ParameterProblemCode
    _pointer: int

    def test__icmp6__message__parameter_problem__parser__dispatches_to_parameter_problem(
        self,
    ) -> None:
        """
        Ensure that an inbound frame whose ICMPv6 type byte is 4 routes
        through Icmp6Parser to an Icmp6MessageParameterProblem instance
        — not to Icmp6MessageUnknown. Closes the silent-drop gap on
        ICMPv6 Parameter Problem.

        Reference: RFC 4443 §3.4 (Parameter Problem type 4).
        Reference: RFC 1122 §3.2.2.5 (incoming Parameter Problem MUST
        be passed to transport — applies symmetrically to v6).
        """

        asm = Icmp6Assembler(
            icmp6__message=Icmp6MessageParameterProblem(
                code=self._code,
                pointer=self._pointer,
                data=b"",
            )
        )
        frame = bytes(asm)

        packet_rx = _packet_rx_with_ip6(frame)

        Icmp6Parser(packet_rx)

        self.assertIsInstance(
            packet_rx.icmp6.message,
            Icmp6MessageParameterProblem,
            msg=f"Type-4 frame must route to Icmp6MessageParameterProblem for case: {self._description}",
        )
        self.assertEqual(
            cast(Any, packet_rx.icmp6.message).code,
            self._code,
            msg=f"Decoded code must round-trip for case: {self._description}",
        )
        self.assertEqual(
            cast(Any, packet_rx.icmp6.message).pointer,
            self._pointer,
            msg=f"Decoded pointer must round-trip for case: {self._description}",
        )
