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
Module contains tests for the ICMPv4 Time Exceeded message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__time_exceeded__assembler.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageTimeExceeded,
    Icmp4TimeExceededCode,
    Icmp4Type,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Time Exceeded, code 0 (TTL Exceeded in Transit), no data.",
            "_kwargs": {
                "code": Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Time Exceeded - TTL Exceeded in Transit, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageTimeExceeded(code=<Icmp4TimeExceededCode"
                    ".TTL_EXCEEDED_IN_TRANSIT: 0>, cksum=0, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 11/0, Cksum 0xf4ff (computed by assemble()), Rest 0x00000000
                    b"\x0b\x00\xf4\xff\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.TIME_EXCEEDED,
                "code": Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Time Exceeded, code 1 (Fragment Reassembly Time Exceeded), no data.",
            "_kwargs": {
                "code": Icmp4TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Time Exceeded - Fragment Reassembly Time Exceeded, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageTimeExceeded(code=<Icmp4TimeExceededCode"
                    ".FRAGMENT_REASSEMBLY_TIME_EXCEEDED: 1>, cksum=0, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 11/1, Cksum 0xf4fe, Rest 0x00000000
                    b"\x0b\x01\xf4\xfe\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.TIME_EXCEEDED,
                "code": Icmp4TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Time Exceeded, code 0 with embedded IP header + 8 bytes UDP.",
            "_kwargs": {
                "code": Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                # Embedded payload — original IPv4 header (20 bytes) + first 8
                # bytes of triggering UDP datagram. The byte values are
                # arbitrary but verbatim from the inbound packet per RFC 792.
                "data": (
                    b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
                    b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
                    b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
                ),
            },
            "_results": {
                "__len__": 36,
                "__str__": "ICMPv4 Time Exceeded - TTL Exceeded in Transit, len 36 (8+28)",
                "__repr__": (
                    "Icmp4MessageTimeExceeded(code=<Icmp4TimeExceededCode"
                    ".TTL_EXCEEDED_IN_TRANSIT: 0>, cksum=0, "
                    "data=b'E\\x00\\x00!\\x00\\x01\\x00\\x00@\\x11\\xa8l"
                    "\\n\\x00\\x01\\x07\\n\\x00\\x01[\\x03\\xe8\\x07\\xd0"
                    "\\x00\\r\\x124')"
                ),
                "__bytes__": (
                    # Type/Code : 11/0, Cksum 0x9304 (computed by assemble()), Rest 0x00000000
                    # then 20-byte IPv4 header + 8 bytes UDP header.
                    b"\x0b\x00\x93\x04\x00\x00\x00\x00"
                    b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
                    b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
                    b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
                ),
                "type": Icmp4Type.TIME_EXCEEDED,
                "code": Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                "cksum": 0,
                "data": (
                    b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
                    b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
                    b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
                ),
            },
        },
    ]
)
class TestIcmp4MessageTimeExceededAssembler(TestCase):
    """
    The ICMPv4 Time Exceeded message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Time Exceeded message.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageTimeExceeded(**self._kwargs),
        )

    def test__icmp4__message__time_exceeded__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP4__TIME_EXCEEDED__LEN
        plus len(data) (after the __post_init__ truncation).

        Reference: RFC 792 (Time Exceeded wire-format length = 8 + data).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical Time Exceeded log line
        (including the human-readable code name).

        Reference: RFC 792 (Time Exceeded codes 0/1 with descriptive
        names).
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 792 (ICMP message checksum covers entire ICMP
        message starting with type field).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp4Type.TIME_EXCEEDED via the non-init dataclass field).

        Reference: RFC 792 (Time Exceeded type field is 11).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (Time Exceeded code 0/1).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field
        (post-truncation by __post_init__).

        Reference: RFC 792 (Time Exceeded data carries Internet header +
        first 8 octets of original datagram).
        """

        self.assertEqual(
            cast(Icmp4MessageTimeExceeded, self._icmp4__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__assembler__assemble(self) -> None:
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
