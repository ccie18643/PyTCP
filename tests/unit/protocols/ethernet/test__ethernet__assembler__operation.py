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
This module contains tests for the Ethernet II protocol packet assembling functionality.

tests/unit/protocols/ethernet/test__ethernet__assembler__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp.protocols.ethernet.ethernet__enums import EthernetType
from pytcp.protocols.ethernet.ethernet__header import EthernetHeader
from pytcp.protocols.raw.raw__assembler import RawAssembler


@parameterized_class(
    [
        {
            "_description": "Ethernet packet with Raw payload (I).",
            "_args": {
                "ethernet__src": MacAddress("77:88:99:aa:bb:cc"),
                "ethernet__dst": MacAddress("11:22:33:44:55:66"),
                "ethernet__payload": RawAssembler(
                    raw__payload=b"0123456789ABCDEF"
                ),
            },
            "_results": {
                "__len__": 30,
                "__str__": (
                    "ETHER 77:88:99:aa:bb:cc > 11:22:33:44:55:66, type 0xffff (Raw), len 30 (14+16)"
                ),
                "__repr__": (
                    "EthernetAssembler(header=EthernetHeader(dst=MacAddress('11:22:33:44:55:66'), "
                    "src=MacAddress('77:88:99:aa:bb:cc'), type=<EthernetType.RAW: 65535>), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xff\xff\x30\x31"
                    b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("77:88:99:aa:bb:cc"),
                "type": EthernetType.RAW,
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("77:88:99:aa:bb:cc"),
                    type=EthernetType.RAW,
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "Ethernet packet with Raw payload (II).",
            "_args": {
                "ethernet__dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "ethernet__src": MacAddress("11:12:13:14:15:16"),
                "ethernet__payload": RawAssembler(raw__payload=b"X" * 1500),
            },
            "_results": {
                "__len__": 1514,
                "__str__": (
                    "ETHER 11:12:13:14:15:16 > a1:b2:c3:d4:e5:f6, type 0xffff (Raw), len 1514 (14+1500)"
                ),
                "__repr__": (
                    "EthernetAssembler(header=EthernetHeader(dst=MacAddress('a1:b2:c3:d4:e5:f6'), "
                    "src=MacAddress('11:12:13:14:15:16'), type=<EthernetType.RAW: 65535>), "
                    f"payload=RawAssembler(raw__payload=b'{"X" * 1500}'))"
                ),
                "__bytes__": (
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\xff\xff"
                    + b"X" * 1500
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("11:12:13:14:15:16"),
                "type": EthernetType.RAW,
                "header": EthernetHeader(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("11:12:13:14:15:16"),
                    type=EthernetType.RAW,
                ),
                "payload": RawAssembler(raw__payload=b"X" * 1500),
            },
        },
    ]
)
class TestEthernetAssemblerOperation(TestCase):
    """
    The Ethernet packet assembler operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the Ethernet packet assembler object with testcase arguments.
        """

        self._ethernet__assembler = EthernetAssembler(**self._args)

    def test__ehternet__assembler__len(self) -> None:
        """
        Ensure the Ethernet packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._ethernet__assembler),
            self._results["__len__"],
        )

    def test__ethernet__assembler__str(self) -> None:
        """
        Ensure the Ethernet packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._ethernet__assembler),
            self._results["__str__"],
        )

    def test__ethernet__assembler__repr(self) -> None:
        """
        Ensure the Ethernet packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._ethernet__assembler),
            self._results["__repr__"],
        )

    def test__ethernet__assembler__bytes(self) -> None:
        """
        Ensure the Ethernet packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._ethernet__assembler),
            self._results["__bytes__"],
        )

    def test__ethernet__assembler__dst(self) -> None:
        """
        Ensure the Ethernet packet assembler 'dst' property returns a correct
        value.
        """

        self.assertEqual(
            self._ethernet__assembler.dst,
            self._results["dst"],
        )

    def test__ethernet__assembler__src(self) -> None:
        """
        Ensure the Ethernet packet assembler 'src' property returns a correct
        value.
        """

        self.assertEqual(
            self._ethernet__assembler.src,
            self._results["src"],
        )

    def test__ethernet__assembler__type(self) -> None:
        """
        Ensure the Ethernet packet assembler 'type' property returns a correct
        value.
        """

        self.assertEqual(
            self._ethernet__assembler.type,
            self._results["type"],
        )

    def test__ethernet__assembler__header(self) -> None:
        """
        Ensure the Ethernet packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._ethernet__assembler.header,
            self._results["header"],
        )

    def test__ethernet__assembler__payload(self) -> None:
        """
        Ensure the Ethernet packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._ethernet__assembler.payload,
            self._results["payload"],
        )
