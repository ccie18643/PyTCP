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
Module contains tests for the ICMPv4 unknown message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__assembler.py

ver 3.0.10
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import Icmp4Assembler, Icmp4Code, Icmp4MessageUnknown, Icmp4Type
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message (type 255, code 255), 16-byte data.",
            "_kwargs": {
                "type": Icmp4Type.from_int(255),
                "code": Icmp4Code.from_int(255),
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 20,
                "__str__": "ICMPv4 Unknown Message, type 255, code 255, cksum 0, len 20 (4+16)",
                "__repr__": (
                    "Icmp4MessageUnknown(type=<Icmp4Type.UNKNOWN_255: 255>, "
                    "code=<Icmp4Code.UNKNOWN_255: 255>, cksum=0, "
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv4 Unknown Message
                    #   Type     : 255 (Unknown)
                    #   Code     : 255 (Unknown)
                    #   Checksum : 0x3129 (computed by assemble())
                    #   Data     : b"0123456789ABCDEF" (16 bytes)
                    b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.from_int(255),
                "code": Icmp4Code.from_int(255),
                "cksum": 0,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 1, code 2), empty data (bare header).",
            "_kwargs": {
                "type": Icmp4Type.from_int(1),
                "code": Icmp4Code.from_int(2),
                "data": b"",
            },
            "_results": {
                "__len__": 4,
                "__str__": "ICMPv4 Unknown Message, type 1, code 2, cksum 0, len 4 (4+0)",
                "__repr__": (
                    "Icmp4MessageUnknown(type=<Icmp4Type.UNKNOWN_1: 1>, "
                    "code=<Icmp4Code.UNKNOWN_2: 2>, cksum=0, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Unknown Message
                    #   Type     : 1 (Unknown)
                    #   Code     : 2 (Unknown)
                    #   Checksum : 0xfefd (computed by assemble())
                    #   Data     : none
                    b"\x01\x02\xfe\xfd"
                ),
                "type": Icmp4Type.from_int(1),
                "code": Icmp4Code.from_int(2),
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 100, code 200), constructor cksum ignored on wire.",
            "_kwargs": {
                "type": Icmp4Type.from_int(100),
                "code": Icmp4Code.from_int(200),
                # The constructor 'cksum' is retained as a field value but the
                # assembler overwrites bytes 2-4 on the wire with the computed
                # Internet checksum, so this 0xAAAA never reaches the wire.
                "cksum": 0xAAAA,
                "data": b"payload!",
            },
            "_results": {
                "__len__": 12,
                "__str__": "ICMPv4 Unknown Message, type 100, code 200, cksum 43690, len 12 (4+8)",
                "__repr__": (
                    "Icmp4MessageUnknown(type=<Icmp4Type.UNKNOWN_100: 100>, "
                    "code=<Icmp4Code.UNKNOWN_200: 200>, cksum=43690, data=b'payload!')"
                ),
                "__bytes__": (
                    # ICMPv4 Unknown Message
                    #   Type     : 100 (Unknown)
                    #   Code     : 200 (Unknown)
                    #   Checksum : 0xdde6 (computed by assemble(), NOT 0xAAAA)
                    #   Data     : b"payload!" (8 bytes)
                    b"\x64\xc8\xdd\xe6\x70\x61\x79\x6c\x6f\x61\x64\x21"
                ),
                "type": Icmp4Type.from_int(100),
                "code": Icmp4Code.from_int(200),
                "cksum": 0xAAAA,
                "data": b"payload!",
            },
        },
    ]
)
class TestIcmp4MessageUnknownAssembler(TestCase):
    """
    The ICMPv4 unknown message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized unknown message.
        """

        self._icmp4__assembler = Icmp4Assembler(icmp4__message=Icmp4MessageUnknown(**self._kwargs))

    def test__icmp4__message__unknown__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP4__HEADER__LEN + len(data).

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical ICMPv4 unknown-message log line.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field as
        passed to the constructor (the on-wire checksum is written during
        assemble() and does not mutate this attribute).

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        self.assertEqual(
            cast(Icmp4MessageUnknown, self._icmp4__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the header + data, back-patches the
        checksum into the header buffer, and yields the same wire bytes
        as 'bytes()'.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp4__message__unknown__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' produces exactly two buffers — the packed header
        (4 bytes) followed by the data buffer — so the ICMPv4 checksum
        back-patch in Icmp4Assembler.assemble() targets the header buffer.

        Reference: RFC 792 (ICMPv4 unknown-type message wire format).
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=f"assemble() must append exactly 2 buffers (header + data) for case: {self._description}",
        )
        self.assertEqual(
            len(buffers[0]),
            4,
            msg=f"First buffer must be the 4-byte ICMPv4 header for case: {self._description}",
        )
