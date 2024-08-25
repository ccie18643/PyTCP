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
Module contains tests for the ICMPv4 packet parser operation.

tests/unit/protocols/icmp4/test__icmp4__parser__operation.py

ver 3.0.1
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp4.icmp4__parser import Icmp4Parser
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    Icmp4EchoReplyCode,
    Icmp4EchoReplyMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestCode,
    Icmp4EchoRequestMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)
from pytcp.protocols.ip4.ip4__parser import Ip4Parser


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Echo Reply message.",
            "_args": {
                "bytes": b"\x00\x00\xff\xff\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4EchoReplyMessage(
                    code=Icmp4EchoReplyCode.DEFAULT,
                    cksum=65535,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message.",
            "_args": {
                "bytes": b"\x03\x03\xfc\xfc\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=64764,
                    mtu=None,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Echo Request message.",
            "_args": {
                "bytes": b"\x08\x00\xf7\xff\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4EchoRequestMessage(
                    code=Icmp4EchoRequestCode.DEFAULT,
                    cksum=63487,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 unknown message.",
            "_args": {
                "bytes": b"\xff\xff\x00\x00",
            },
            "_results": {
                "message": Icmp4UnknownMessage(
                    type=Icmp4Type.from_int(255),
                    code=Icmp4Code.from_int(255),
                    cksum=0,
                    raw=b"",
                ),
            },
        },
    ]
)
class TestIcmp4ParserOperation(TestCase):
    """
    The ICMPv4 packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp4__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv4 packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip4 = cast(Ip4Parser, StrictMock(template=Ip4Parser))
        self.patch_attribute(
            target=packet_rx.ip4,
            attribute="payload_len",
            new_value=len(self._args["bytes"]),
        )

        icmp4_parser = Icmp4Parser(packet_rx=packet_rx)

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )

        self.assertIs(
            packet_rx.icmp4,
            icmp4_parser,
        )

        self.assertEqual(
            bytes(packet_rx.frame),
            b"",
        )
