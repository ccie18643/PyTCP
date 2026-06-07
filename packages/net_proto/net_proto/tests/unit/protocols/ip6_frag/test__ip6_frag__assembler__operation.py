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
This module contains tests for the IPv6 Frag packet assembler operation.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Ip6FragAssembler, Ip6FragHeader, IpProto
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "IPv6 Frag header only (no payload, offset=0, flag_mf=False, id=0).",
            "_kwargs": {
                "ip6_frag__next": IpProto.RAW,
                "ip6_frag__offset": 0,
                "ip6_frag__flag_mf": False,
                "ip6_frag__id": 0,
                "ip6_frag__payload": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "IPv6_FRAG id 0, offset 0, next Raw, len 8 (8+0)",
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<IpProto.RAW: 255>, offset=0, "
                    "flag_mf=False, id=0), payload=b'')"
                ),
                # IPv6 Frag wire frame (8 bytes, header only):
                #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
                #   Byte  1     : 0x00       -> reserved (must be zero)
                #   Bytes 2-3   : 0x0000     -> offset=0, res=0, flag_mf=0
                #   Bytes 4-7   : 0x00000000 -> id=0
                "__bytes__": b"\xff\x00\x00\x00\x00\x00\x00\x00",
                "next": IpProto.RAW,
                "offset": 0,
                "flag_mf": False,
                "id": 0,
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=0,
                    flag_mf=False,
                    id=0,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "IPv6 Frag with 16-byte ASCII payload, mid-range offset, MF set, max id.",
            "_kwargs": {
                "ip6_frag__next": IpProto.RAW,
                "ip6_frag__offset": 3208,
                "ip6_frag__flag_mf": True,
                "ip6_frag__id": 4294967295,
                "ip6_frag__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "IPv6_FRAG id 4294967295, MF, offset 3208, next Raw, len 24 (8+16)",
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<IpProto.RAW: 255>, offset=3208, "
                    "flag_mf=True, id=4294967295), payload=b'0123456789ABCDEF')"
                ),
                # IPv6 Frag wire frame (24 bytes = 8-byte header + 16-byte payload):
                #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
                #   Byte  1     : 0x00       -> reserved
                #   Bytes 2-3   : 0x0c89     -> offset=0x0c88=3208, res=0, flag_mf=1
                #                 (3208 | 1 = 0x0c89)
                #   Bytes 4-7   : 0xffffffff -> id=4294967295 (UINT_32__MAX)
                #   Bytes 8-23  : b"0123456789ABCDEF" (ASCII payload)
                "__bytes__": (
                    b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                    + b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "next": IpProto.RAW,
                "offset": 3208,
                "flag_mf": True,
                "id": 4294967295,
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=3208,
                    flag_mf=True,
                    id=4294967295,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "IPv6 Frag with 1422-byte payload at maximum offset (UINT_13__MAX).",
            "_kwargs": {
                "ip6_frag__next": IpProto.RAW,
                "ip6_frag__offset": 65528,
                "ip6_frag__flag_mf": False,
                "ip6_frag__id": 7777777,
                "ip6_frag__payload": b"X" * 1422,
            },
            "_results": {
                "__len__": 1430,
                "__str__": "IPv6_FRAG id 7777777, offset 65528, next Raw, len 1430 (8+1422)",
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<IpProto.RAW: 255>, offset=65528, "
                    f"flag_mf=False, id=7777777), payload=b'{'X' * 1422}')"
                ),
                # IPv6 Frag wire frame (1430 bytes = 8-byte header + 1422-byte payload):
                #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
                #   Byte  1     : 0x00       -> reserved
                #   Bytes 2-3   : 0xfff8     -> offset=0xfff8=65528 (UINT_13__MAX),
                #                 res=0, flag_mf=0
                #   Bytes 4-7   : 0x0076adf1 -> id=7777777
                #   Bytes 8+    : 1422 bytes of 'X'
                "__bytes__": b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422,
                "next": IpProto.RAW,
                "offset": 65528,
                "flag_mf": False,
                "id": 7777777,
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=65528,
                    flag_mf=False,
                    id=7777777,
                ),
                "payload": b"X" * 1422,
            },
        },
        {
            "_description": "IPv6 Frag with TCP next-header, flag_mf=True at offset=0 (first fragment).",
            "_kwargs": {
                "ip6_frag__next": IpProto.TCP,
                "ip6_frag__offset": 0,
                "ip6_frag__flag_mf": True,
                "ip6_frag__id": 3735928559,
                "ip6_frag__payload": b"\x00" * 8,
            },
            "_results": {
                "__len__": 16,
                "__str__": "IPv6_FRAG id 3735928559, MF, offset 0, next TCP, len 16 (8+8)",
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<IpProto.TCP: 6>, offset=0, "
                    "flag_mf=True, id=3735928559), payload=b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')"
                ),
                # IPv6 Frag wire frame (16 bytes = 8-byte header + 8-byte payload):
                #   Byte  0     : 0x06       -> next=IpProto.TCP (6)
                #   Byte  1     : 0x00       -> reserved
                #   Bytes 2-3   : 0x0001     -> offset=0, res=0, flag_mf=1
                #   Bytes 4-7   : 0xdeadbeef -> id=3735928559
                #   Bytes 8-15  : 8 bytes of 0x00 (placeholder TCP header)
                "__bytes__": b"\x06\x00\x00\x01\xde\xad\xbe\xef" + b"\x00" * 8,
                "next": IpProto.TCP,
                "offset": 0,
                "flag_mf": True,
                "id": 3735928559,
                "header": Ip6FragHeader(
                    next=IpProto.TCP,
                    offset=0,
                    flag_mf=True,
                    id=3735928559,
                ),
                "payload": b"\x00" * 8,
            },
        },
    ]
)
class TestIp6FragAssemblerOperation(TestCase):
    """
    The IPv6 Frag packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the IPv6 Frag assembler from the parametrized kwargs.
        """

        self._ip6_frag__assembler = Ip6FragAssembler(**self._kwargs)

    def test__ip6_frag__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total packet length
        (header + payload).

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            len(self._ip6_frag__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip6_frag__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            str(self._ip6_frag__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip6_frag__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            repr(self._ip6_frag__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip6_frag__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            bytes(self._ip6_frag__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip6_frag__assembler__next(self) -> None:
        """
        Ensure the 'next' property returns the provided next-header
        IpProto.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.next,
            self._results["next"],
            msg=f"Unexpected 'next' for case: {self._description}",
        )

    def test__ip6_frag__assembler__offset(self) -> None:
        """
        Ensure the 'offset' property returns the provided offset.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.offset,
            self._results["offset"],
            msg=f"Unexpected 'offset' for case: {self._description}",
        )

    def test__ip6_frag__assembler__flag_mf(self) -> None:
        """
        Ensure the 'flag_mf' property returns the provided MF flag.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.flag_mf,
            self._results["flag_mf"],
            msg=f"Unexpected 'flag_mf' for case: {self._description}",
        )

    def test__ip6_frag__assembler__id(self) -> None:
        """
        Ensure the 'id' property returns the provided datagram id.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.id,
            self._results["id"],
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__ip6_frag__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed Ip6FragHeader.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__ip6_frag__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload bytes.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        self.assertEqual(
            self._ip6_frag__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ip6_frag__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header and payload in order and the
        concatenation matches '__bytes__'.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        buffers: list[Buffer] = []

        self._ip6_frag__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__ip6_frag__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers — the fixed
        8-byte header followed by the payload — so downstream code can
        locate them by index.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        buffers: list[Buffer] = []

        self._ip6_frag__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg="Ip6FragAssembler.assemble must append header + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            8,
            msg="Ip6FragAssembler.assemble must append the 8-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["payload"]),
            msg="Ip6FragAssembler.assemble must append the payload buffer second.",
        )


class TestIp6FragAssemblerDefaults(TestCase):
    """
    Tests for the IPv6 Frag assembler default-argument contract. The
    assembler accepts every header field as a keyword-only optional
    argument so callers can build a 'zero' fragment and override only
    what they need; this suite pins those defaults.
    """

    def test__ip6_frag__assembler__defaults(self) -> None:
        """
        Ensure the assembler with no arguments produces a valid 8-byte
        zeroed-out fragment header with empty payload.

        Reference: RFC 8200 §4.5 (Fragment header wire format).
        """

        assembler = Ip6FragAssembler()

        self.assertEqual(
            assembler.next,
            IpProto.RAW,
            msg="Default 'next' must be IpProto.RAW.",
        )
        self.assertEqual(
            assembler.offset,
            0,
            msg="Default 'offset' must be 0.",
        )
        self.assertFalse(
            assembler.flag_mf,
            msg="Default 'flag_mf' must be False.",
        )
        self.assertEqual(
            assembler.id,
            0,
            msg="Default 'id' must be 0.",
        )
        self.assertEqual(
            bytes(assembler.payload),
            b"",
            msg="Default 'payload' must be empty.",
        )
        self.assertEqual(
            len(assembler),
            8,
            msg="Default-constructed assembler must serialize to the 8-byte header.",
        )
