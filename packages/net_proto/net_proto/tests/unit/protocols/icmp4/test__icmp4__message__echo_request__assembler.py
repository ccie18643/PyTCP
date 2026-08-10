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
Module contains tests for the ICMPv4 Echo Request message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__echo_request__assembler.py

ver 3.0.10
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import (
    Icmp4Assembler,
    Icmp4EchoRequestCode,
    Icmp4MessageEchoRequest,
    Icmp4Type,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Echo Request, empty data.",
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Echo Request, id 12345, seq 54321, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageEchoRequest(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Echo Request
                    #   Type     : 8 (Echo Request)
                    #   Code     : 0 (Default)
                    #   Checksum : 0xf394 (computed by assemble())
                    #   Id/Seq   : 12345 / 54321
                    #   Data     : none
                    b"\x08\x00\xf3\x94\x30\x39\xd4\x31"
                ),
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Echo Request, 16-byte data.",
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv4 Echo Request, id 12345, seq 54321, len 24 (8+16)",
                "__repr__": (
                    "Icmp4MessageEchoRequest(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv4 Echo Request
                    #   Type     : 8 (Echo Request)
                    #   Code     : 0 (Default)
                    #   Checksum : 0x24be (computed by assemble())
                    #   Id/Seq   : 12345 / 54321
                    #   Data     : b"0123456789ABCDEF" (16 bytes)
                    b"\x08\x00\x24\xbe\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv4 Echo Request at maximum data length (65507 bytes).",
            "_kwargs": {
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
            "_results": {
                "__len__": 65515,
                "__str__": "ICMPv4 Echo Request, id 11111, seq 22222, len 65515 (8+65507)",
                "__repr__": (
                    "Icmp4MessageEchoRequest(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    f"cksum=0, id=11111, seq=22222, data=b'{'X' * 65507}')"
                ),
                "__bytes__": (
                    # ICMPv4 Echo Request (at IPv4 payload maximum)
                    #   Type     : 8 (Echo Request)
                    #   Code     : 0 (Default)
                    #   Checksum : 0x1ecb (computed by assemble())
                    #   Id/Seq   : 11111 / 22222
                    #   Data     : b"X" * 65507 (IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN)
                    b"\x08\x00\x1e\xcb\x2b\x67\x56\xce"
                    + b"X" * 65507
                ),
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
        },
    ]
)
class TestIcmp4MessageEchoRequestAssembler(TestCase):
    """
    The ICMPv4 Echo Request message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Echo Request message.
        """

        self._icmp4__assembler = Icmp4Assembler(icmp4__message=Icmp4MessageEchoRequest(**self._kwargs))

    def test__icmp4__message__echo_request__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP4__ECHO_REQUEST__LEN +
        len(data).

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical Echo Request log line.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp4Type.ECHO_REQUEST via the non-init dataclass field).

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__id(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'id' field.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            cast(Icmp4MessageEchoRequest, self._icmp4__assembler.message).id,
            self._results["id"],
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__seq(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'seq' field.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            cast(Icmp4MessageEchoRequest, self._icmp4__assembler.message).seq,
            self._results["seq"],
            msg=f"Unexpected 'seq' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        self.assertEqual(
            cast(Icmp4MessageEchoRequest, self._icmp4__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp4__message__echo_request__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' yields the same wire bytes as 'bytes()'.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 wire format).
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )


class TestIcmp4MessageEchoRequestWithData(TestCase):
    """
    The ICMPv4 Echo Request with-embedded-data length tests.
    """

    def test__icmp4__message__echo_request__len_with_data(self) -> None:
        """
        Ensure 'len()' on a Echo Request message carrying embedded data
        equals the 8-byte message header plus the data length, pinning
        the 'LEN + len(data)' computation against a '-' corruption that
        the existing empty-data fixtures cannot catch.

        Reference: RFC 792 (Echo Request message length is 8 octets plus embedded data).
        """

        data = bytes(range(28))
        message = Icmp4MessageEchoRequest(id=0x1234, seq=0x5678, data=data)

        self.assertEqual(
            len(message),
            8 + len(data),
            msg="Echo Request length must be the 8-byte header plus the embedded data length.",
        )
        self.assertEqual(
            len(bytes(Icmp4Assembler(icmp4__message=message))),
            8 + len(data),
            msg="Echo Request assembled wire length must be 8 + the embedded data length.",
        )
