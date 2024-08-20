#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the Ethernet II packet parser operation.

tests/unit/protocols/ethernet/test__ethernet__parser__operation.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ethernet.ethernet__enums import EthernetType
from pytcp.protocols.ethernet.ethernet__header import EthernetHeader
from pytcp.protocols.ethernet.ethernet__parser import EthernetParser


@parameterized_class(
    [
        {
            "_description": "Ethernet packet (I).",
            "_args": {
                "bytes": (
                    b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xff\xff\x30\x31"
                    b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("77:88:99:aa:bb:cc"),
                    type=EthernetType.RAW,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "Ethernet header (II).",
            "_args": {
                "bytes": (
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\xff\xff"
                    + b"X" * 1500
                ),
            },
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("11:12:13:14:15:16"),
                    type=EthernetType.RAW,
                ),
                "payload": b"X" * 1500,
            },
        },
    ]
)
class TestEthernetHeaderParserOperation(TestCase):
    """
    Ethernet header parseer packet tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ethernet__parser__from_bytes(self) -> None:
        """
        Ensure the Ethernet packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        packet_rx = PacketRx(self._args["bytes"])

        ethernet_parser = EthernetParser(packet_rx=packet_rx)

        self.assertEqual(
            ethernet_parser.header,
            self._results["header"],
        )

        self.assertIs(
            packet_rx.ethernet,
            ethernet_parser,
        )

        self.assertEqual(
            bytes(packet_rx.frame),
            self._results["payload"],
        )
