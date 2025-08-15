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
This module contains tests for the ARP packet parser operation.

tests/pytcp/unit/protocols/arp/test__arp__parser__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr import Ip4Address, MacAddress
from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.arp.arp__enums import ArpOperation
from pytcp.protocols.arp.arp__header import ArpHeader
from pytcp.protocols.arp.arp__parser import ArpParser
from tests.pytcp.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": "ARP Request.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ],
            "_kwargs": {},
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("01:02:03:04:05:06"),
                    spa=Ip4Address("11.22.33.44"),
                    tha=MacAddress("0a:0b:0c:0d:0e:0f"),
                    tpa=Ip4Address("101.102.103.104"),
                ),
            },
        },
        {
            "_description": "ARP Reply.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x02\xa1\xb2\xc3\xd4\xe5\xf6\x05\x05"
                b"\x05\x05\x7a\x7b\x7c\x7d\x7e\x7f\x07\x07\x07\x07"
            ],
            "_kwargs": {},
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REPLY,
                    sha=MacAddress("a1:b2:c3:d4:e5:f6"),
                    spa=Ip4Address("5.5.5.5"),
                    tha=MacAddress("7a:7b:7c:7d:7e:7f"),
                    tpa=Ip4Address("7.7.7.7"),
                ),
            },
        },
    ]
)
class TestArpHeaderParserOperation(TestCasePacketRx):
    """
    The ARP packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__arp_parser__from_bytes(self) -> None:
        """
        Ensure the ARP packet parser creates the proper header, options
        and payload objects and also updates the appropriate 'tx_packet'
        object fields.
        """

        arp_parser = ArpParser(self._packet_rx)

        self.assertEqual(
            arp_parser.header,
            self._results["header"],
        )

        self.assertIs(
            self._packet_rx.arp,
            arp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            b"",
        )
