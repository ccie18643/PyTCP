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
parser operation.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__parameter_problem__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_proto import (
    Icmp4MessageParameterProblem,
    Icmp4ParameterProblemCode,
    Icmp4Parser,
    Ip4Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip4(frame: bytes, *, ip4__payload_len: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len'
    defaults to the full frame length, or is overridden to model a frame
    followed by lower-layer padding.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(
        Ip4Parser,
        SimpleNamespace(payload_len=len(frame) if ip4__payload_len is None else ip4__payload_len),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Parameter Problem, code 0, pointer=20, no data.",
            "_frame_rx": (
                # Type/Code : 12/0, Cksum 0xdfff, Pointer 20=0x14, Unused 0x000000
                b"\x0c\x00\xdf\xff\x14\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageParameterProblem(
                    code=Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                    pointer=20,
                    cksum=0xDFFF,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Parameter Problem, code 1 (Required Option Missing), no data.",
            "_frame_rx": (
                # Type/Code : 12/1, Cksum 0xf3fe, Pointer 0, Unused 0x000000
                b"\x0c\x01\xf3\xfe\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageParameterProblem(
                    code=Icmp4ParameterProblemCode.REQUIRED_OPTION_MISSING,
                    pointer=0,
                    cksum=0xF3FE,
                    data=b"",
                ),
            },
        },
    ]
)
class TestIcmp4MessageParameterProblemParser(TestCase):
    """
    The ICMPv4 Parameter Problem message parser-operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__icmp4__message__parameter_problem__parser__dispatches_to_parameter_problem(
        self,
    ) -> None:
        """
        Ensure that an inbound frame whose ICMPv4 type byte is 12
        routes through Icmp4Parser to an Icmp4MessageParameterProblem
        instance — not to Icmp4MessageUnknown. Closes the silent-drop
        gap on Parameter Problem.

        Reference: RFC 792 (Parameter Problem type 12).
        Reference: RFC 1122 §3.2.2.5 (incoming Parameter Problem MUST
        be passed to the transport layer).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertIsInstance(
            packet_rx.icmp4.message,
            Icmp4MessageParameterProblem,
            msg=f"Type-12 frame must route to Icmp4MessageParameterProblem for case: {self._description}",
        )

    def test__icmp4__message__parameter_problem__parser__decoded_message_matches(
        self,
    ) -> None:
        """
        Ensure the decoded Parameter Problem message equals the
        expected dataclass (code, pointer, cksum round-trip cleanly).

        Reference: RFC 792 (Parameter Problem wire format).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertEqual(
            packet_rx.icmp4.message,
            self._results["message"],
            msg=f"Unexpected decoded Parameter Problem message for case: {self._description}",
        )


class TestIcmp4MessageParameterProblemParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv4 Parameter Problem integrity validator.
    """

    def test__icmp4__message__parameter_problem__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure the shortest valid Parameter Problem frame (exactly
        8 bytes — type, code, checksum, pointer + unused) parses without
        raising an integrity error.

        Reference: RFC 792 (ICMPv4 Parameter Problem type 12 integrity).
        """

        # ICMPv4 Parameter Problem at minimum length (8 bytes, valid cksum)
        #   Type     : 12 (Parameter Problem)
        #   Code     : 0 (Default)
        #   Checksum : 0xf3ff
        #   Pointer  : 0 / unused 0x000000
        frame = b"\x0c\x00\xf3\xff\x00\x00\x00\x00"

        Icmp4Parser(_packet_rx_with_ip4(frame))

    def test__icmp4__message__parameter_problem__parser__integrity__trailing_bytes_accepted(self) -> None:
        """
        Ensure a frame whose raw length exceeds 'ip4__payload_len' (the
        ICMPv4 message is followed by lower-layer padding) still parses:
        the integrity bound is 'ip4__payload_len <= len(frame)', so
        trailing bytes beyond the declared payload are tolerated, not
        rejected.

        Reference: RFC 792 (ICMPv4 Parameter Problem type 12 integrity).
        """

        # Minimum 8-byte Parameter Problem (valid checksum over the 8
        # octets) followed by 4 octets of lower-layer padding.
        # ip4__payload_len=8 is strictly less than len(frame)=12.
        frame = b"\x0c\x00\xf3\xff\x00\x00\x00\x00" + b"\x00\x00\x00\x00"

        Icmp4Parser(_packet_rx_with_ip4(frame, ip4__payload_len=8))
