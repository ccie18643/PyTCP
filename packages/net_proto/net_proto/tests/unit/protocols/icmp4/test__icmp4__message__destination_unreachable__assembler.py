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
Module contains tests for the ICMPv4 Destination Unreachable message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__destination_unreachable__assembler.py

ver 3.0.8
"""

from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Destination Unreachable, code 0 (Network), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK: 0>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/0, Cksum 0xfcff (computed by assemble()), Rest 0x00000000
                    b"\x03\x00\xfc\xff\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 1 (Host), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST: 1>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/1, Cksum 0xfcfe, Rest 0x00000000
                    b"\x03\x01\xfc\xfe\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 2 (Protocol), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PROTOCOL,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Protocol, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PROTOCOL: 2>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/2, Cksum 0xfcfd, Rest 0x00000000
                    b"\x03\x02\xfc\xfd\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PROTOCOL,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 3 (Port), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PORT: 3>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/3, Cksum 0xfcfc, Rest 0x00000000
                    b"\x03\x03\xfc\xfc\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 4 (Fragmentation Needed), MTU 1200.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                "mtu": 1200,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Fragmentation Needed, mtu 1200, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".FRAGMENTATION_NEEDED: 4>, cksum=0, mtu=1200, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/4, Cksum 0xf84b, Reserved 0x0000, MTU 0x04b0 (1200)
                    b"\x03\x04\xf8\x4b\x00\x00\x04\xb0"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                "cksum": 0,
                "mtu": 1200,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 5 (Source Route Failed), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Source Route Failed, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".SOURCE_ROUTE_FAILED: 5>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/5, Cksum 0xfcfa, Rest 0x00000000
                    b"\x03\x05\xfc\xfa\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 6 (Network Unknown), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network Unknown, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_UNKNOWN: 6>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/6, Cksum 0xfcf9, Rest 0x00000000
                    b"\x03\x06\xfc\xf9\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 7 (Host Unknown), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Unknown, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_UNKNOWN: 7>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/7, Cksum 0xfcf8, Rest 0x00000000
                    b"\x03\x07\xfc\xf8\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 8 (Source Host Isolated), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Source Host Isolated, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".SOURCE_HOST_ISOLATED: 8>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/8, Cksum 0xfcf7, Rest 0x00000000
                    b"\x03\x08\xfc\xf7\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 9 (Network Prohibited), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_PROHIBITED: 9>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/9, Cksum 0xfcf6, Rest 0x00000000
                    b"\x03\x09\xfc\xf6\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 10 (Host Prohibited), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_PROHIBITED: 10>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/10, Cksum 0xfcf5, Rest 0x00000000
                    b"\x03\x0a\xfc\xf5\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 11 (Network TOS), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_TOS,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network TOS, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_TOS: 11>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/11, Cksum 0xfcf4, Rest 0x00000000
                    b"\x03\x0b\xfc\xf4\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_TOS,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 12 (Host TOS), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_TOS,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host TOS, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_TOS: 12>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/12, Cksum 0xfcf3, Rest 0x00000000
                    b"\x03\x0c\xfc\xf3\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_TOS,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 13 (Communication Prohibited), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Communication Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".COMMUNICATION_PROHIBITED: 13>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/13, Cksum 0xfcf2, Rest 0x00000000
                    b"\x03\x0d\xfc\xf2\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 14 (Host Precedence), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Precedence, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_PRECEDENCE: 14>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/14, Cksum 0xfcf1, Rest 0x00000000
                    b"\x03\x0e\xfc\xf1\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 15 (Precedence Cutoff), no data.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Precedence Cutoff, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PRECEDENCE_CUTOFF: 15>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # Type/Code : 3/15, Cksum 0xfcf0, Rest 0x00000000
                    b"\x03\x0f\xfc\xf0\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, non-empty 16-byte data (code=Port).",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 24 (8+16)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PORT: 3>, cksum=0, mtu=None, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # Type/Code : 3/3, Cksum 0x2e26, Rest 0x00000000
                    # Data      : b"0123456789ABCDEF"
                    b"\x03\x03\x2e\x26\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": (
                "ICMPv4 Destination Unreachable, oversized data silently truncated to 548 bytes "
                "(IP4__MIN_MTU minus IP4__HEADER__LEN minus DU__LEN)."
            ),
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"X" * 65507,
            },
            "_results": {
                "__len__": 556,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 556 (8+548)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    f".PORT: 3>, cksum=0, mtu=None, data=b'{'X' * 548}')"
                ),
                "__bytes__": (
                    # Type/Code : 3/3, Cksum 0x6e6e, Rest 0x00000000
                    # Data      : b"X" * 548 (input was 65507; __post_init__ truncated it)
                    b"\x03\x03\x6e\x6e\x00\x00\x00\x00"
                    + b"X" * 548
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"X" * 548,
            },
        },
    ]
)
class TestIcmp4MessageDestinationUnreachableAssembler(TestCase):
    """
    The ICMPv4 Destination Unreachable message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Destination Unreachable
        message.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageDestinationUnreachable(**self._kwargs),
        )

    def test__icmp4__message__destination_unreachable__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP4__DESTINATION_UNREACHABLE__LEN
        plus len(data) (after the __post_init__ truncation).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical Destination Unreachable log line
        (including the 'mtu' segment for FRAGMENTATION_NEEDED).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field
        (always Icmp4Type.DESTINATION_UNREACHABLE via the non-init
        dataclass field).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field
        (post-truncation by __post_init__).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        self.assertEqual(
            cast(Icmp4MessageDestinationUnreachable, self._icmp4__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' yields the same wire bytes as 'bytes()'.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )


class TestIcmp4MessageDestinationUnreachableAssembler__FragmentationNeededMtu(TestCase):
    """
    Standalone test for the 'mtu' field on a FRAGMENTATION_NEEDED message.
    The 'mtu' field is meaningful only for code 4; the parameterized
    assembler tests above intentionally omit 'mtu' from the per-fixture
    '_results' for non-FRAGMENTATION_NEEDED codes (where the field is
    None by construction and already covered by repr/bytes assertions).
    """

    def test__icmp4__message__destination_unreachable__fragmentation_needed__mtu_field(self) -> None:
        """
        Ensure a FRAGMENTATION_NEEDED message constructed with mtu=1200
        round-trips that value through the assembler's wrapped message.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 wire format).
        """

        assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                mtu=1200,
                data=b"",
            ),
        )

        self.assertEqual(
            cast(Icmp4MessageDestinationUnreachable, assembler.message).mtu,
            1200,
            msg=(
                "FRAGMENTATION_NEEDED message MUST round-trip 'mtu' through "
                "the assembler. Got "
                f"{cast(Icmp4MessageDestinationUnreachable, assembler.message).mtu!r}."
            ),
        )
