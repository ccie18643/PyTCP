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
This module contains tests for the UDP packet parser operation.

tests/unit/protocols/udp/test__udp__parser__operation.py

ver 3.0.0
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.protocols.udp.udp__header import UdpHeader
from pytcp.protocols.udp.udp__parser import UdpParser


@parameterized_class(
    [
        {
            "_description": "UDP packet with the empty payload.",
            "_args": {
                "bytes": b"\xff\xff\xff\xff\x00\x08\xff\xf7",
            },
            "_results": {
                "header": UdpHeader(
                    sport=65535,
                    dport=65535,
                    plen=8,
                    cksum=65527,
                ),
                "payload": b"",
            },
        },
        {
            "_description": "UDP packet with the non-empty payload.",
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x18\x2c\xa6\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=24,
                    cksum=11430,
                ),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "UDP packet with the maximum length payload.",
            "_args": {
                "bytes": b"\x2b\x67\x56\xce\xff\xff\xb3\x57" + b"X" * 65527,
            },
            "_results": {
                "header": UdpHeader(
                    sport=11111,
                    dport=22222,
                    plen=65535,
                    cksum=45911,
                ),
                "payload": b"X" * 65527,
            },
        },
        {
            "_description": "UDP packet with the 'cksum' field set to '0' (valid state).",
            "_args": {
                "bytes": b"\x30\x39\xd4\x31\x00\x08\x00\x00",
            },
            "_results": {
                "header": UdpHeader(
                    sport=12345,
                    dport=54321,
                    plen=8,
                    cksum=0,
                ),
                "payload": b"",
            },
        },
    ]
)
class TestUdpParserOperation(TestCase):
    """
    The UDP packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser creates the proper header and payload objects
        and also updates the appropriate 'tx_packet' object fields.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip = cast(Ip4Parser, StrictMock(template=Ip4Parser))
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="payload_len",
            new_value=len(self._args["bytes"]),
        )
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="pshdr_sum",
            new_value=0,
        )

        udp_parser = UdpParser(packet_rx=packet_rx)

        self.assertEqual(
            udp_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            udp_parser.payload,
            self._results["payload"],
        )

        self.assertIs(
            packet_rx.udp,
            udp_parser,
        )

        self.assertEqual(
            bytes(packet_rx.frame),
            self._results["payload"],
        )
