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
Module contains tests for the ICMPv6 Echo Reply message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__echo_reply__assembler.py

ver 3.0.8
"""

from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp6Assembler,
    Icmp6EchoReplyCode,
    Icmp6MessageEchoReply,
    Icmp6Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Reply message, empty data (bare 8-byte header).",
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Echo Reply, id 12345, seq 54321, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageEchoReply(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Echo Reply
                    #   Type     : 129 (Echo Reply)
                    #   Code     : 0 (Default)
                    #   Checksum : 0x7a94 (computed by assemble(), pshdr_sum=0)
                    #   Id/Seq   : 12345 / 54321
                    #   Data     : none
                    b"\x81\x00\x7a\x94\x30\x39\xd4\x31"
                ),
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Echo Reply message, 16-byte data.",
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv6 Echo Reply, id 12345, seq 54321, len 24 (8+16)",
                "__repr__": (
                    "Icmp6MessageEchoReply(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv6 Echo Reply
                    #   Type     : 129 (Echo Reply)
                    #   Code     : 0 (Default)
                    #   Checksum : 0xabbd (computed by assemble(), pshdr_sum=0)
                    #   Id/Seq   : 12345 / 54321
                    #   Data     : b"0123456789ABCDEF" (16 bytes)
                    b"\x81\x00\xab\xbd\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv6 Echo Reply message, 65527-byte data (IPv6 payload maximum).",
            "_kwargs": {
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65527,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "ICMPv6 Echo Reply, id 11111, seq 22222, len 65535 (8+65527)",
                "__repr__": (
                    "Icmp6MessageEchoReply(code=<Icmp6EchoReplyCode.DEFAULT: 0>, cksum=0, "
                    f"id=11111, seq=22222, data=b'{'X' * 65527}')"
                ),
                "__bytes__": (
                    # ICMPv6 Echo Reply at maximum payload size
                    #   Type     : 129 (Echo Reply)
                    #   Code     : 0 (Default)
                    #   Checksum : 0x3257 (computed by assemble(), pshdr_sum=0)
                    #   Id/Seq   : 11111 / 22222
                    #   Data     : b"X" * 65527 (IP6__PAYLOAD__MAX_LEN - ICMP6__ECHO_REPLY__LEN)
                    b"\x81\x00\x32\x57\x2b\x67\x56\xce"
                    + b"X" * 65527
                ),
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65527,
            },
        },
        {
            "_description": "ICMPv6 Echo Reply message, constructor cksum ignored on wire.",
            "_kwargs": {
                # The constructor 'cksum' is retained as a field value but the
                # assembler overwrites bytes 2-4 on the wire with the computed
                # Internet checksum, so this 0xAAAA never reaches the wire.
                "cksum": 0xAAAA,
                "id": 1,
                "seq": 2,
                "data": b"payload!",
            },
            "_results": {
                "__len__": 16,
                "__str__": "ICMPv6 Echo Reply, id 1, seq 2, len 16 (8+8)",
                "__repr__": (
                    "Icmp6MessageEchoReply(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=43690, id=1, seq=2, data=b'payload!')"
                ),
                "__bytes__": (
                    # ICMPv6 Echo Reply
                    #   Type     : 129 (Echo Reply)
                    #   Code     : 0 (Default)
                    #   Checksum : 0xc1ab (computed by assemble(), NOT 0xAAAA)
                    #   Id/Seq   : 1 / 2
                    #   Data     : b"payload!" (8 bytes)
                    b"\x81\x00\xc1\xab\x00\x01\x00\x02\x70\x61\x79\x6c\x6f\x61\x64\x21"
                ),
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0xAAAA,
                "id": 1,
                "seq": 2,
                "data": b"payload!",
            },
        },
    ]
)
class TestIcmp6MessageEchoReplyAssembler(TestCase):
    """
    The ICMPv6 Echo Reply message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Echo Reply message.
        """

        self._icmp6__assembler = Icmp6Assembler(icmp6__message=Icmp6MessageEchoReply(**self._kwargs))

    def test__icmp6__message__echo_reply__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP6__ECHO_REPLY__LEN + len(data).

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical ICMPv6 Echo Reply log line.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field as
        passed to the constructor (the on-wire checksum is written during
        assemble() and does not mutate this attribute).

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__id(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'id' field.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            cast(Icmp6MessageEchoReply, self._icmp6__assembler.message).id,
            self._results["id"],
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__seq(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'seq' field.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            cast(Icmp6MessageEchoReply, self._icmp6__assembler.message).seq,
            self._results["seq"],
            msg=f"Unexpected 'seq' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        self.assertEqual(
            cast(Icmp6MessageEchoReply, self._icmp6__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the header + data, back-patches the
        checksum into the header buffer, and yields the same wire bytes
        as 'bytes()'.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__message__echo_reply__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' produces exactly two buffers — the packed
        8-byte header followed by the data buffer — so the ICMPv6 checksum
        back-patch in Icmp6Assembler.assemble() targets the header buffer.

        Reference: RFC 4443 §4.2 (Echo Reply type 129).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=f"assemble() must append exactly 2 buffers (header + data) for case: {self._description}",
        )
        self.assertEqual(
            len(buffers[0]),
            8,
            msg=f"First buffer must be the 8-byte Echo Reply header for case: {self._description}",
        )
