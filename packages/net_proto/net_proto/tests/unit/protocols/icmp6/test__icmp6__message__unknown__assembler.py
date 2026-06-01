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
Module contains tests for the ICMPv6 unknown message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__unknown__assembler.py

ver 3.0.8
"""

from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp6Assembler,
    Icmp6Code,
    Icmp6MessageUnknown,
    Icmp6Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv6 unknown message (type 255, code 255), 16-byte data.",
            "_kwargs": {
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 20,
                "__str__": "ICMPv6 Unknown Message, type 255, code 255, cksum 0, len 20 (4+16)",
                "__repr__": (
                    "Icmp6MessageUnknown(type=<Icmp6Type.UNKNOWN_255: 255>, "
                    "code=<Icmp6Code.UNKNOWN_255: 255>, cksum=0, "
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv6 Unknown Message
                    #   Type     : 255 (Unknown)
                    #   Code     : 255 (Unknown)
                    #   Checksum : 0x3129 (computed by assemble(), pshdr_sum=0)
                    #   Data     : b"0123456789ABCDEF" (16 bytes)
                    b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "cksum": 0,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv6 unknown message (type 5, code 2), empty data (bare header).",
            "_kwargs": {
                "type": Icmp6Type.from_int(5),
                "code": Icmp6Code.from_int(2),
                "data": b"",
            },
            "_results": {
                "__len__": 4,
                "__str__": "ICMPv6 Unknown Message, type 5, code 2, cksum 0, len 4 (4+0)",
                "__repr__": (
                    "Icmp6MessageUnknown(type=<Icmp6Type.UNKNOWN_5: 5>, "
                    "code=<Icmp6Code.UNKNOWN_2: 2>, cksum=0, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Unknown Message
                    #   Type     : 5 (Unknown)
                    #   Code     : 2 (Unknown)
                    #   Checksum : 0xfafd (computed by assemble(), pshdr_sum=0)
                    #   Data     : none
                    b"\x05\x02\xfa\xfd"
                ),
                "type": Icmp6Type.from_int(5),
                "code": Icmp6Code.from_int(2),
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 unknown message (type 100, code 200), constructor cksum ignored on wire.",
            "_kwargs": {
                "type": Icmp6Type.from_int(100),
                "code": Icmp6Code.from_int(200),
                # The constructor 'cksum' is retained as a field value but the
                # assembler overwrites bytes 2-4 on the wire with the computed
                # Internet checksum, so this 0xAAAA never reaches the wire.
                "cksum": 0xAAAA,
                "data": b"payload!",
            },
            "_results": {
                "__len__": 12,
                "__str__": "ICMPv6 Unknown Message, type 100, code 200, cksum 43690, len 12 (4+8)",
                "__repr__": (
                    "Icmp6MessageUnknown(type=<Icmp6Type.UNKNOWN_100: 100>, "
                    "code=<Icmp6Code.UNKNOWN_200: 200>, cksum=43690, data=b'payload!')"
                ),
                "__bytes__": (
                    # ICMPv6 Unknown Message
                    #   Type     : 100 (Unknown)
                    #   Code     : 200 (Unknown)
                    #   Checksum : 0xdde6 (computed by assemble(), NOT 0xAAAA)
                    #   Data     : b"payload!" (8 bytes)
                    b"\x64\xc8\xdd\xe6\x70\x61\x79\x6c\x6f\x61\x64\x21"
                ),
                "type": Icmp6Type.from_int(100),
                "code": Icmp6Code.from_int(200),
                "cksum": 0xAAAA,
                "data": b"payload!",
            },
        },
    ]
)
class TestIcmp6MessageUnknownAssembler(TestCase):
    """
    The ICMPv6 unknown message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized unknown message.
        """

        self._icmp6__assembler = Icmp6Assembler(icmp6__message=Icmp6MessageUnknown(**self._kwargs))

    def test__icmp6__message__unknown__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP6__HEADER__LEN + len(data).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical ICMPv6 unknown-message log line.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field as
        passed to the constructor (the on-wire checksum is written during
        assemble() and does not mutate this attribute).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        self.assertEqual(
            cast(Icmp6MessageUnknown, self._icmp6__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the header + data, back-patches the
        checksum into the header buffer, and yields the same wire bytes
        as 'bytes()'.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__message__unknown__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' produces exactly two buffers — the packed header
        (4 bytes) followed by the data buffer — so the ICMPv6 checksum
        back-patch in Icmp6Assembler.assemble() targets the header buffer.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
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
            4,
            msg=f"First buffer must be the 4-byte ICMPv6 header for case: {self._description}",
        )
