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
This module contains tests for the UDP packet assembler operation.

tests/pytcp/unit/protocols/udp/test__udp__assembler__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.udp.udp__assembler import UdpAssembler
from pytcp.protocols.udp.udp__header import UdpHeader


@parameterized_class(
    [
        {
            "_description": "UDP packet with the empty payload.",
            "_args": [],
            "_kwargs": {
                "udp__sport": 65535,
                "udp__dport": 65535,
                "udp__payload": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "UDP 65535 > 65535, len 8 (8+0)",
                "__repr__": (
                    "UdpAssembler(header=UdpHeader(sport=65535, dport=65535, "
                    "plen=8, cksum=0), payload=b'')"
                ),
                "__bytes__": b"\xff\xff\xff\xff\x00\x08\xff\xf7",
                "sport": 65535,
                "dport": 65535,
                "plen": 8,
                "cksum": 0,
                "header": UdpHeader(
                    sport=65535,
                    dport=65535,
                    plen=8,
                    cksum=0,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "UDP packet with the non-empty payload.",
            "_args": [],
            "_kwargs": {
                "udp__sport": 12345,
                "udp__dport": 54321,
                "udp__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "UDP 12345 > 54321, len 24 (8+16)",
                "__repr__": (
                    "UdpAssembler(header=UdpHeader(sport=12345, dport=54321, "
                    "plen=24, cksum=0), payload=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x30\x39\xd4\x31\x00\x18\x2c\xa6\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "sport": 12345,
                "dport": 54321,
                "plen": 24,
                "cksum": 0,
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=24,
                    cksum=0,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "UDP packet with the maximum length payload.",
            "_args": [],
            "_kwargs": {
                "udp__sport": 11111,
                "udp__dport": 22222,
                "udp__payload": b"X" * 65527,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "UDP 11111 > 22222, len 65535 (8+65527)",
                "__repr__": (
                    "UdpAssembler(header=UdpHeader(sport=11111, dport=22222, "
                    f"plen=65535, cksum=0), payload=b'{"X" * 65527}')"
                ),
                "__bytes__": b"\x2b\x67\x56\xce\xff\xff\xb3\x57" + b"X" * 65527,
                "sport": 11111,
                "dport": 22222,
                "plen": 65535,
                "cksum": 0,
                "header": UdpHeader(
                    sport=11111,
                    dport=22222,
                    plen=65535,
                    cksum=0,
                ),
                "payload": b"X" * 65527,
            },
        },
    ]
)
class TestUdpAssemblerOperation(TestCase):
    """
    The UDP packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the UDP packet assembler object with testcase arguments.
        """

        self._udp__assembler = UdpAssembler(*self._args, **self._kwargs)

    def test__udp__assembler__len(self) -> None:
        """
        Ensure the UDP packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._udp__assembler),
            self._results["__len__"],
        )

    def test__udp__assembler__str(self) -> None:
        """
        Ensure the UDP packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._udp__assembler),
            self._results["__str__"],
        )

    def test__udp__assembler__repr(self) -> None:
        """
        Ensure the UDP packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._udp__assembler),
            self._results["__repr__"],
        )

    def test__udp__assembler__bytes(self) -> None:
        """
        Ensure the UDP packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._udp__assembler),
            self._results["__bytes__"],
        )

    def test__udp__assembler__sport(self) -> None:
        """
        Ensure the UDP packet assembler 'sport' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.sport,
            self._results["sport"],
        )

    def test__udp__assembler__dport(self) -> None:
        """
        Ensure the UDP packet assembler 'dport' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.dport,
            self._results["dport"],
        )

    def test__udp__assembler__plen(self) -> None:
        """
        Ensure the UDP packet assembler 'plen' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.plen,
            self._results["plen"],
        )

    def test__udp__assembler__cksum(self) -> None:
        """
        Ensure the UDP packet assembler 'cksum' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.cksum,
            self._results["cksum"],
        )

    def test__udp__assembler__header(self) -> None:
        """
        Ensure the UDP packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.header,
            self._results["header"],
        )

    def test__udp__assembler__payload(self) -> None:
        """
        Ensure the UDP packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._udp__assembler.payload,
            self._results["payload"],
        )


class TestUdpAssemblerMisc(TestCase):
    """
    The UDP packet assembler miscellaneous functions tests.
    """

    def test__udp__assembler__echo_tracker(self) -> None:
        """
        Ensure the UDP packet assembler 'tracker' property returns
        a correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        udp__assembler = UdpAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            udp__assembler.tracker.echo_tracker,
            echo_tracker,
        )
