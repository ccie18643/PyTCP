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
This module contains tests for the Ethernet 802.3 protocol packet assembling functionality.

net_proto/tests/unit/protocols/test__ethernet_802_3__assembler__operation.py

ver 3.0.4
"""


from typing import Any

from net_addr import MacAddress
from net_proto import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PACKET__MAX_LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Assembler,
    Ethernet8023Header,
    RawAssembler,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 packet (I).",
            "_args": [],
            "_kwargs": {
                "ethernet_802_3__src": MacAddress("77:88:99:aa:bb:cc"),
                "ethernet_802_3__dst": MacAddress("11:22:33:44:55:66"),
                "ethernet_802_3__payload": RawAssembler(
                    raw__payload=b"0123456789ABCDEF"
                ),
            },
            "_results": {
                "__len__": 30,
                "__str__": (
                    "ETHER_802.3 77:88:99:aa:bb:cc > 11:22:33:44:55:66, dlen 16, len 30 (14+16)"
                ),
                "__repr__": (
                    "Ethernet8023Assembler(header=Ethernet8023Header(dst=MacAddress('11:22:33:44:55:66'), "
                    "src=MacAddress('77:88:99:aa:bb:cc'), dlen=16), "
                    "payload=RawAssembler(raw__payload=b'0123456789ABCDEF'))"
                ),
                "__bytes__": (
                    b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00\x10"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("77:88:99:aa:bb:cc"),
                "dlen": 16,
                "header": Ethernet8023Header(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("77:88:99:aa:bb:cc"),
                    dlen=16,
                ),
                "payload": RawAssembler(raw__payload=b"0123456789ABCDEF"),
            },
        },
        {
            "_description": "Ethernet 802.3 packet (II).",
            "_args": [],
            "_kwargs": {
                "ethernet_802_3__dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "ethernet_802_3__src": MacAddress("11:12:13:14:15:16"),
                "ethernet_802_3__payload": RawAssembler(
                    raw__payload=b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
                ),
            },
            "_results": {
                "__len__": ETHERNET_802_3__PACKET__MAX_LEN,
                "__str__": (
                    f"ETHER_802.3 11:12:13:14:15:16 > a1:b2:c3:d4:e5:f6, "
                    f"dlen {ETHERNET_802_3__PAYLOAD__MAX_LEN}, "
                    f"len {ETHERNET_802_3__PACKET__MAX_LEN} "
                    f"({ETHERNET_802_3__HEADER__LEN}+{ETHERNET_802_3__PAYLOAD__MAX_LEN})"
                ),
                "__repr__": (
                    "Ethernet8023Assembler(header=Ethernet8023Header(dst=MacAddress('a1:b2:c3:d4:e5:f6'), "
                    f"src=MacAddress('11:12:13:14:15:16'), dlen={ETHERNET_802_3__PAYLOAD__MAX_LEN}), "
                    f"payload=RawAssembler(raw__payload=b'{"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN}'))"
                ),
                "__bytes__": (
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xdc"
                    + b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("11:12:13:14:15:16"),
                "dlen": ETHERNET_802_3__PAYLOAD__MAX_LEN,
                "header": Ethernet8023Header(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("11:12:13:14:15:16"),
                    dlen=ETHERNET_802_3__PAYLOAD__MAX_LEN,
                ),
                "payload": RawAssembler(
                    raw__payload=b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
                ),
            },
        },
    ]
)
class TestEthernet8023AssemblerOperation(TestCase):
    """
    The Ethernet 802.3 packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        self._ethernet_802_3__assembler = Ethernet8023Assembler(
            *self._args, **self._kwargs
        )

    def test__ehternet_802_3__assembler__len(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._ethernet_802_3__assembler),
            self._results["__len__"],
        )

    def test__ethernet_802_3__assembler__str(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._ethernet_802_3__assembler),
            self._results["__str__"],
        )

    def test__ethernet_802_3__assembler__repr(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._ethernet_802_3__assembler),
            self._results["__repr__"],
        )

    def test__ethernet_802_3__assembler__bytes(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._ethernet_802_3__assembler),
            self._results["__bytes__"],
        )

    def test__ethernet_802_3__assembler__dst(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'dst' property returns
        a correct value.
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.dst,
            self._results["dst"],
        )

    def test__ethernet_802_3__assembler__src(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'src' property returns
        a correct value.
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.src,
            self._results["src"],
        )

    def test__ethernet_802_3__assembler__dlen(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'dlen' property returns
        a correct value.
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.dlen,
            self._results["dlen"],
        )

    def test__ethernet_802_3__assembler__header(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'header' property returns
        a correct value.
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.header,
            self._results["header"],
        )

    def test__ethernet_802_3__assembler__payload(self) -> None:
        """
        Ensure the Ethernet 802.3 packet assembler 'payload' property returns
        a correct value.
        """

        self.assertEqual(
            self._ethernet_802_3__assembler.payload,
            self._results["payload"],
        )
