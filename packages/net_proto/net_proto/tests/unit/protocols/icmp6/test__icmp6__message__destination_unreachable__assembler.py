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
Module contains tests for the ICMPv6 Destination Unreachable message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__destination_unreachable__assembler.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Destination Unreachable (No Route), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.NO_ROUTE,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - No Route, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.NO_ROUTE: 0>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 0 (No Route)
                    #   Checksum : 0xfeff (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x00\xfe\xff\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.NO_ROUTE,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Prohibited), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.PROHIBITED: 1>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 1 (Administratively Prohibited)
                    #   Checksum : 0xfefe (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x01\xfe\xfe\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Beyond Scope), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.SCOPE,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Scope, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.SCOPE: 2>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 2 (Beyond Scope)
                    #   Checksum : 0xfefd (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x02\xfe\xfd\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.SCOPE,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Address Unreachable), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.ADDRESS,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Address, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.ADDRESS: 3>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 3 (Address Unreachable)
                    #   Checksum : 0xfefc (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x03\xfe\xfc\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.ADDRESS,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port Unreachable), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.PORT,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Port, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.PORT: 4>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 4 (Port Unreachable)
                    #   Checksum : 0xfefb (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x04\xfe\xfb\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Source Failed Policy), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.FAILED_POLICY,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Failed Policy, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.FAILED_POLICY: 5>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 5 (Source Failed Policy)
                    #   Checksum : 0xfefa (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x05\xfe\xfa\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.FAILED_POLICY,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Reject Route), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Reject Route, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.REJECT_ROUTE: 6>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 6 (Reject Route)
                    #   Checksum : 0xfef9 (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x06\xfe\xf9\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Error in Source Routing Header), empty data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Source Routing Header, len 8 (8+0)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER: 7>, cksum=0, "
                    "data=b'')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 7 (Error in Source Routing Header)
                    #   Checksum : 0xfef8 (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : none
                    b"\x01\x07\xfe\xf8\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port Unreachable), 16-byte data.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.PORT,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv6 Destination Unreachable - Port, len 24 (8+16)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.PORT: 4>, cksum=0, "
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 4 (Port Unreachable)
                    #   Checksum : 0x3025 (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : b"0123456789ABCDEF" (16 bytes)
                    b"\x01\x04\x30\x25\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": (
                "ICMPv6 Destination Unreachable (Port Unreachable), data truncated to "
                "1232 bytes (IP6_MIN_MTU - IP6_HEADER_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN)."
            ),
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.PORT,
                # Supply more than the per-RFC4443 cap; the dataclass __post_init__
                # truncates to 1232 bytes so the total message length stays within
                # the IPv6 minimum MTU.
                "data": b"X" * 65527,
            },
            "_results": {
                "__len__": 1240,
                "__str__": "ICMPv6 Destination Unreachable - Port, len 1240 (8+1232)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.PORT: 4>, cksum=0, "
                    f"data=b'{'X' * 1232}')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 4 (Port Unreachable)
                    #   Checksum : 0x6a67 (computed by assemble(), pshdr_sum=0)
                    #   Reserved : 0x00000000
                    #   Data     : b"X" * 1232 (truncated from 65527 to fit min-MTU reply)
                    b"\x01\x04\x6a\x67\x00\x00\x00\x00"
                    + b"X" * 1232
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"X" * 1232,
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable, constructor cksum ignored on wire.",
            "_kwargs": {
                "code": Icmp6DestinationUnreachableCode.NO_ROUTE,
                # The constructor 'cksum' is retained as a field value but the
                # assembler overwrites bytes 2-4 on the wire with the computed
                # Internet checksum, so this 0xAAAA never reaches the wire.
                "cksum": 0xAAAA,
                "data": b"X!",
            },
            "_results": {
                "__len__": 10,
                "__str__": "ICMPv6 Destination Unreachable - No Route, len 10 (8+2)",
                "__repr__": (
                    "Icmp6MessageDestinationUnreachable("
                    "code=<Icmp6DestinationUnreachableCode.NO_ROUTE: 0>, cksum=43690, "
                    "data=b'X!')"
                ),
                "__bytes__": (
                    # ICMPv6 Destination Unreachable
                    #   Type     : 1 (Destination Unreachable)
                    #   Code     : 0 (No Route)
                    #   Checksum : 0xa6de (computed by assemble(), NOT 0xAAAA)
                    #   Reserved : 0x00000000
                    #   Data     : b"X!" (2 bytes)
                    b"\x01\x00\xa6\xde\x00\x00\x00\x00\x58\x21"
                ),
                "type": Icmp6Type.DESTINATION_UNREACHABLE,
                "code": Icmp6DestinationUnreachableCode.NO_ROUTE,
                "cksum": 0xAAAA,
                "data": b"X!",
            },
        },
    ]
)
class TestIcmp6MessageDestinationUnreachableAssembler(TestCase):
    """
    The ICMPv6 Destination Unreachable message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized Destination Unreachable
        message.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageDestinationUnreachable(**self._kwargs),
        )

    def test__icmp6__message__destination_unreachable__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals
        ICMP6__DESTINATION_UNREACHABLE__LEN + len(data) (data already
        truncated by __post_init__ if the caller supplied more than the
        RFC4443 min-MTU cap).

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected length for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical ICMPv6 Destination Unreachable
        log line.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected str() for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected repr() for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes() for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field as
        passed to the constructor (the on-wire checksum is written during
        assemble() and does not mutate this attribute).

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__data(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'data' field
        (post-truncation if applicable).

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        self.assertEqual(
            cast(Icmp6MessageDestinationUnreachable, self._icmp6__assembler.message).data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the header + data, back-patches the
        checksum into the header buffer, and yields the same wire bytes
        as 'bytes()'.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' produces exactly two buffers — the packed
        8-byte header followed by the data buffer — so the ICMPv6 checksum
        back-patch in Icmp6Assembler.assemble() targets the header buffer.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=("assemble() must append exactly 2 buffers (header + data) " f"for case: {self._description}"),
        )
        self.assertEqual(
            len(buffers[0]),
            8,
            msg=("First buffer must be the 8-byte Destination Unreachable header " f"for case: {self._description}"),
        )
