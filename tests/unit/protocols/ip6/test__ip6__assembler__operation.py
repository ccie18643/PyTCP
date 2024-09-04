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
This module contains tests for the IPv6 packet assembler operation.

tests/unit/protocols/ip6/test__ip6__assembler__operation.py

ver 3.0.2
"""

from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import Ip6Address
from pytcp.protocols.ip6.ip6__assembler import Ip6Assembler
from pytcp.protocols.ip6.ip6__enums import Ip6Next
from pytcp.protocols.ip6.ip6__header import Ip6Header
from pytcp.protocols.raw.raw__assembler import RawAssembler


@parameterized_class(
    [
        {
            "_description": "IPv6 packet (I).",
            "_args": [],
            "_kwargs": {
                "ip6__src": Ip6Address(
                    "1001:2002:3003:4004:5005:6006:7007:8008"
                ),
                "ip6__dst": Ip6Address(
                    "a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"
                ),
                "ip6__hop": 1,
                "ip6__dscp": 0,
                "ip6__ecn": 0,
                "ip6__flow": 0,
                "ip6__payload": RawAssembler(),
            },
            "_results": {
                "__len__": 40,
                "__str__": (
                    "IPv6 1001:2002:3003:4004:5005:6006:7007:8008 > a00a:b00b:c00c:d00d:e00e:f00f:a0a:b0b, "
                    "next 255 (Raw), flow 0, hop 1, len 40 (40+0)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=0, ecn=0, flow=0, dlen=0, "
                    "next=<Ip6Next.RAW: 255>, hop=1, "
                    "src=Ip6Address('1001:2002:3003:4004:5005:6006:7007:8008'), "
                    "dst=Ip6Address('a00a:b00b:c00c:d00d:e00e:f00f:a0a:b0b')), "
                    "payload=RawAssembler(raw__payload=b''))"
                ),
                "__bytes__": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
                "ver": 6,
                "dscp": 0,
                "ecn": 0,
                "flow": 0,
                "dlen": 0,
                "next": Ip6Next.RAW,
                "hop": 1,
                "src": Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                "dst": Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                "header": Ip6Header(
                    dscp=0,
                    ecn=0,
                    flow=0,
                    dlen=0,
                    next=Ip6Next.RAW,
                    hop=1,
                    src=Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                    dst=Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                ),
                "payload": RawAssembler(),
            },
        },
        {
            "_description": "IPv6 packet (II).",
            "_args": [],
            "_kwargs": {
                "ip6__src": Ip6Address(
                    "1111:2222:3333:4444:5555:6666:7777:8888"
                ),
                "ip6__dst": Ip6Address(
                    "8888:7777:6666:5555:4444:3333:2222:1111"
                ),
                "ip6__hop": 255,
                "ip6__dscp": 38,
                "ip6__ecn": 2,
                "ip6__flow": 1048575,
                "ip6__payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
            "_results": {
                "__len__": 56,
                "__str__": (
                    "IPv6 1111:2222:3333:4444:5555:6666:7777:8888 > 8888:7777:6666:5555:4444:3333:2222:1111, "
                    "next 255 (Raw), flow 1048575, hop 255, len 56 (40+16)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=38, ecn=2, flow=1048575, dlen=16, "
                    "next=<Ip6Next.RAW: 255>, hop=255, "
                    "src=Ip6Address('1111:2222:3333:4444:5555:6666:7777:8888'), "
                    "dst=Ip6Address('8888:7777:6666:5555:4444:3333:2222:1111')), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "ver": 6,
                "dscp": 38,
                "ecn": 2,
                "flow": 1048575,
                "dlen": 16,
                "next": Ip6Next.RAW,
                "hop": 255,
                "src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "header": Ip6Header(
                    dscp=38,
                    ecn=2,
                    flow=1048575,
                    dlen=16,
                    next=Ip6Next.RAW,
                    hop=255,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "IPv6 packet (III).",
            "_args": [],
            "_kwargs": {
                "ip6__src": Ip6Address(
                    "1111:2222:3333:4444:5555:6666:7777:8888"
                ),
                "ip6__dst": Ip6Address(
                    "8888:7777:6666:5555:4444:3333:2222:1111"
                ),
                "ip6__hop": 128,
                "ip6__dscp": 63,
                "ip6__ecn": 3,
                "ip6__flow": 0,
                "ip6__payload": RawAssembler(raw__payload=b"X" * 65495),
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "IPv6 1111:2222:3333:4444:5555:6666:7777:8888 > 8888:7777:6666:5555:4444:3333:2222:1111, "
                    "next 255 (Raw), flow 0, hop 128, len 65535 (40+65495)"
                ),
                "__repr__": (
                    "Ip6Assembler(header=Ip6Header(dscp=63, ecn=3, flow=0, dlen=65495, "
                    "next=<Ip6Next.RAW: 255>, hop=128, "
                    "src=Ip6Address('1111:2222:3333:4444:5555:6666:7777:8888'), "
                    "dst=Ip6Address('8888:7777:6666:5555:4444:3333:2222:1111')), "
                    f"payload=RawAssembler(raw__payload=b'{"X" * 65495}'))"
                ),
                "__bytes__": (
                    b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11" + b"X" * 65495
                ),
                "ver": 6,
                "dscp": 63,
                "ecn": 3,
                "flow": 0,
                "dlen": 65495,
                "next": Ip6Next.RAW,
                "hop": 128,
                "src": Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                "dst": Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                "header": Ip6Header(
                    dscp=63,
                    ecn=3,
                    flow=0,
                    dlen=65495,
                    next=Ip6Next.RAW,
                    hop=128,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": RawAssembler(raw__payload=b"X" * 65495),
            },
        },
    ]
)
class TestIp6AssemblerOperation(TestCase):
    """
    The IPv6 packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 packet assembler object with testcase arguments.
        """

        self._ip6__assembler = Ip6Assembler(*self._args, **self._kwargs)

    def test__ip6__assembler__len(self) -> None:
        """
        Ensure the IPv6 packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._ip6__assembler),
            self._results["__len__"],
        )

    def test__ip6__assembler__str(self) -> None:
        """
        Ensure the IPv6 packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._ip6__assembler),
            self._results["__str__"],
        )

    def test__ip6__assembler__repr(self) -> None:
        """
        Ensure the IPv6 packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._ip6__assembler),
            self._results["__repr__"],
        )

    def test__ip6__assembler__bytes(self) -> None:
        """
        Ensure the IPv6 packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._ip6__assembler),
            self._results["__bytes__"],
        )

    def test__ip6__assembler__ver(self) -> None:
        """
        Ensure the IPv6 packet assembler 'ver' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.ver,
            self._results["ver"],
        )

    def test__ip6__assembler__dscp(self) -> None:
        """
        Ensure the IPv6 packet assembler 'dscp' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.dscp,
            self._results["dscp"],
        )

    def test__ip6__assembler__ecn(self) -> None:
        """
        Ensure the IPv6 packet assembler 'ecn' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.ecn,
            self._results["ecn"],
        )

    def test__ip6__assembler__flow(self) -> None:
        """
        Ensure the IPv6 packet assembler 'flow' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.flow,
            self._results["flow"],
        )

    def test__ip6__assembler__dlen(self) -> None:
        """
        Ensure the IPv6 packet assembler 'dlen' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.dlen,
            self._results["dlen"],
        )

    def test__ip6__assembler__next(self) -> None:
        """
        Ensure the IPv6 packet assembler 'next' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.next,
            self._results["next"],
        )

    def test__ip6__assembler__hop(self) -> None:
        """
        Ensure the IPv6 packet assembler 'hop' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.hop,
            self._results["hop"],
        )

    def test__ip6__assembler__src(self) -> None:
        """
        Ensure the IPv6 packet assembler 'src' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.src,
            self._results["src"],
        )

    def test__ip6__assembler__dst(self) -> None:
        """
        Ensure the IPv6 packet assembler 'dst' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.dst,
            self._results["dst"],
        )

    def test__ip6__assembler__header(self) -> None:
        """
        Ensure the IPv6 packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.header,
            self._results["header"],
        )

    def test__ip6__assembler__payload(self) -> None:
        """
        Ensure the IPv6 packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6__assembler.payload,
            self._results["payload"],
        )
