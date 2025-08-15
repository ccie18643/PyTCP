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
This module contains tests for the Ethernet 802.3 packet parser operation.

tests/pytcp/unit/protocols/test__ethernet_802_3__parser__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr import MacAddress
from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__parser import (
    Ethernet8023Parser,
)
from tests.pytcp.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 packet (I).",
            "_args": [
                b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00\x10\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_kwargs": {},
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("77:88:99:aa:bb:cc"),
                    dlen=16,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "Ethernet 802.3 packet (II).",
            "_args": [
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xdc"
                + b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
            ],
            "_kwargs": {},
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("11:12:13:14:15:16"),
                    dlen=ETHERNET_802_3__PAYLOAD__MAX_LEN,
                ),
                "payload": b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN,
            },
        },
    ]
)
class TestEthernet8023ParserOperation(TestCasePacketRx):
    """
    Ethernet 802.3 packet parser packet tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ethernet__parser__from_bytes(self) -> None:
        """
        Ensure the Ethernet 802.3 packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        ethernet_802_3_parser = Ethernet8023Parser(self._packet_rx)

        self.assertEqual(
            ethernet_802_3_parser.header,
            self._results["header"],
        )

        self.assertIs(
            self._packet_rx.ethernet_802_3,
            ethernet_802_3_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )
