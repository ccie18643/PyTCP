#!/usr/bin/env python3

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

tests/pytcp/unit/protocols/ip6_frag/test__ip6_frag__assembler__packet.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.ip6.ip6__enums import Ip6Next
from pytcp.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler
from pytcp.protocols.ip6_frag.ip6_frag__header import Ip6FragHeader


@parameterized_class(
    [
        {
            "_description": "IPv6 Frag packet (I).",
            "_args": [],
            "_kwargs": {
                "ip6_frag__next": Ip6Next.RAW,
                "ip6_frag__offset": 0,
                "ip6_frag__flag_mf": False,
                "ip6_frag__id": 0,
                "ip6_frag__payload": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": (
                    "IPv6_FRAG id 0, offset 0, next 255 (Raw), len 8 (8+0)"
                ),
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<Ip6Next.RAW: 255>, offset=0, "
                    "flag_mf=False, id=0), payload=b'')"
                ),
                "__bytes__": (b"\xff\x00\x00\x00\x00\x00\x00\x00"),
                "next": Ip6Next.RAW,
                "offset": 0,
                "flag_mf": False,
                "id": 0,
                "header": Ip6FragHeader(
                    next=Ip6Next.RAW,
                    offset=0,
                    flag_mf=False,
                    id=0,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "IPv6 Frag packet (II).",
            "_args": [],
            "_kwargs": {
                "ip6_frag__next": Ip6Next.RAW,
                "ip6_frag__offset": 3208,
                "ip6_frag__flag_mf": True,
                "ip6_frag__id": 4294967295,
                "ip6_frag__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": (
                    "IPv6_FRAG id 4294967295, MF, offset 3208, next 255 (Raw), len 24 (8+16)"
                ),
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<Ip6Next.RAW: 255>, offset=3208, "
                    "flag_mf=True, id=4294967295), payload=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "next": Ip6Next.RAW,
                "offset": 3208,
                "flag_mf": True,
                "id": 4294967295,
                "header": Ip6FragHeader(
                    next=Ip6Next.RAW,
                    offset=3208,
                    flag_mf=True,
                    id=4294967295,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "IPv6 Frag packet (III).",
            "_args": [],
            "_kwargs": {
                "ip6_frag__next": Ip6Next.RAW,
                "ip6_frag__offset": 65528,
                "ip6_frag__flag_mf": False,
                "ip6_frag__id": 7777777,
                "ip6_frag__payload": b"X" * 1422,
            },
            "_results": {
                "__len__": 1430,
                "__str__": (
                    "IPv6_FRAG id 7777777, offset 65528, next 255 (Raw), len 1430 (8+1422)"
                ),
                "__repr__": (
                    "Ip6FragAssembler(header=Ip6FragHeader(next=<Ip6Next.RAW: 255>, offset=65528, "
                    f"flag_mf=False, id=7777777), payload=b'{"X" * 1422}')"
                ),
                "__bytes__": b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422,
                "next": Ip6Next.RAW,
                "offset": 65528,
                "flag_mf": False,
                "id": 7777777,
                "header": Ip6FragHeader(
                    next=Ip6Next.RAW,
                    offset=65528,
                    flag_mf=False,
                    id=7777777,
                ),
                "payload": b"X" * 1422,
            },
        },
    ]
)
class TestIp6FragAssemblerOperation(TestCase):
    """
    The IPv6 Frag packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 Frag packet assembler object with testcase
        arguments.
        """

        self._ip6_frag__assembler = Ip6FragAssembler(
            *self._args, **self._kwargs
        )

    def test__ip6_frag__assembler__len(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._ip6_frag__assembler),
            self._results["__len__"],
        )

    def test__ip6__ext_frag__assembler__str(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._ip6_frag__assembler),
            self._results["__str__"],
        )

    def test__ip6_frag__assembler__repr(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._ip6_frag__assembler),
            self._results["__repr__"],
        )

    def test__ip6_frag__assembler__bytes(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._ip6_frag__assembler),
            self._results["__bytes__"],
        )

    def test__ip6_frag__assembler__next(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'next' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.next,
            self._results["next"],
        )

    def test__ip6_ip6_frag__assembler__offset(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'offset' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.offset,
            self._results["offset"],
        )

    def test__ip6_frag__assembler__flag_mf(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'flag_mf' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.flag_mf,
            self._results["flag_mf"],
        )

    def test__ip6_frag__assembler__id(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'id' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.id,
            self._results["id"],
        )

    def test__ip6_frag__assembler__header(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'header' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.header,
            self._results["header"],
        )

    def test__ip6__assembler__payload(self) -> None:
        """
        Ensure the IPv6 Frag packet assembler 'payload' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_frag__assembler.payload,
            self._results["payload"],
        )
