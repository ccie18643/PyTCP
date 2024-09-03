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
This module contains tests for the IPv4 packet parser operation.

tests/unit/protocols/ip4/test__ip4__parser__packet.py

ver 3.0.2
"""

from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import Ip4Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__enums import Ip4Proto
from pytcp.protocols.ip4.ip4__header import Ip4Header
from pytcp.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.protocols.ip4.options.ip4_option__nop import Ip4OptionNop
from pytcp.protocols.ip4.options.ip4_options import Ip4Options


@parameterized_class(
    [
        {
            "_description": "IPv4 packet (I)",
            "_args": {
                "bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                )
            },
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=63,
                    ecn=3,
                    plen=20,
                    id=65535,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=55587,
                    src=Ip4Address("10.20.30.40"),
                    dst=Ip4Address("50.60.70.80"),
                ),
                "options": Ip4Options(),
                "payload": b"",
                "header_bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
                "payload_bytes": b"",
                "packet_bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
        },
        {
            "_description": "IPv4 packet (II)",
            "_args": {
                "bytes": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                )
            },
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=36,
                    id=12345,
                    flag_df=True,
                    flag_mf=False,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=14920,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": b"0123456789ABCDEF",
                "header_bytes": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08"
                ),
                "payload_bytes": (
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "packet_bytes": (
                    b"\x45\x46\x00\x24\x30\x39\x40\x00\xff\xff\x3a\x48\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv4 packet (III)",
            "_args": {
                "bytes": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea\x01\x01\x01\x01"
                    b"\x02\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    + b"X" * 65475
                )
            },
            "_results": {
                "header": Ip4Header(
                    hlen=60,
                    dscp=8,
                    ecn=0,
                    plen=65535,
                    id=21212,
                    flag_df=False,
                    flag_mf=False,
                    offset=0,
                    ttl=64,
                    proto=Ip4Proto.RAW,
                    cksum=746,
                    src=Ip4Address("1.1.1.1"),
                    dst=Ip4Address("2.2.2.2"),
                ),
                "options": Ip4Options(
                    *([Ip4OptionNop()] * 40),
                ),
                "payload": b"X" * 65475,
                "header_bytes": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea\x01\x01\x01\x01"
                    b"\x02\x02\x02\x02"
                ),
                "payload_bytes": b"X" * 65475,
                "packet_bytes": (
                    b"\x4f\x20\xff\xff\x52\xdc\x00\x00\x40\xff\x02\xea\x01\x01\x01\x01"
                    b"\x02\x02\x02\x02\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    + b"X" * 65475
                ),
            },
        },
        {
            "_description": "IPv4 packet (IV)",
            "_args": {
                "bytes": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0\x04\x03\x02\x01"
                    b"\x08\x07\x06\x05\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                )
            },
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=10,
                    ecn=1,
                    plen=36,
                    id=54321,
                    flag_df=False,
                    flag_mf=False,
                    offset=32008,
                    ttl=128,
                    proto=Ip4Proto.RAW,
                    cksum=16848,
                    src=Ip4Address("4.3.2.1"),
                    dst=Ip4Address("8.7.6.5"),
                ),
                "options": Ip4Options(),
                "payload": b"0123456789ABCDEF",
                "header_bytes": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0\x04\x03\x02\x01"
                    b"\x08\x07\x06\x05"
                ),
                "payload_bytes": (
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "packet_bytes": (
                    b"\x45\x29\x00\x24\xd4\x31\x0f\xa1\x80\xff\x41\xd0\x04\x03\x02\x01"
                    b"\x08\x07\x06\x05\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv4 packet (V)",
            "_args": {
                "bytes": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08" + b"X" * 1466
                )
            },
            "_results": {
                "header": Ip4Header(
                    hlen=20,
                    dscp=17,
                    ecn=2,
                    plen=1486,
                    id=12345,
                    flag_df=False,
                    flag_mf=True,
                    offset=0,
                    ttl=255,
                    proto=Ip4Proto.RAW,
                    cksum=21662,
                    src=Ip4Address("1.2.3.4"),
                    dst=Ip4Address("5.6.7.8"),
                ),
                "options": Ip4Options(),
                "payload": b"X" * 1466,
                "header_bytes": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08"
                ),
                "payload_bytes": b"X" * 1466,
                "packet_bytes": (
                    b"\x45\x46\x05\xce\x30\x39\x20\x00\xff\xff\x54\x9e\x01\x02\x03\x04"
                    b"\x05\x06\x07\x08" + b"X" * 1466
                ),
            },
        },
    ]
)
class TestIp4PacketParserOperation(TestCase):
    """
    The IPv4 packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4__header_parser__from_bytes(self) -> None:
        """
        Ensure the IPv4 packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        packet_rx = PacketRx(self._args["bytes"])

        ip4_parser = Ip4Parser(packet_rx)

        self.assertEqual(
            ip4_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            ip4_parser.options,
            self._results["options"],
        )

        self.assertEqual(
            ip4_parser.header_bytes,
            self._results["header_bytes"],
        )

        self.assertEqual(
            ip4_parser.payload_bytes,
            self._results["payload_bytes"],
        )

        self.assertEqual(
            ip4_parser.packet_bytes,
            self._results["packet_bytes"],
        )

        self.assertIs(
            packet_rx.ip4,
            ip4_parser,
        )

        self.assertEqual(
            bytes(packet_rx.frame),
            self._results["payload"],
        )
