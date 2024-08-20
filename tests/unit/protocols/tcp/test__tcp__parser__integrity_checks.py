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
This module contains tests for the TCP packet integrity checks.

tests/unit/protocols/tcp/test__tcp__parser__integrity_checks.py

ver 3.0.0
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError
from pytcp.protocols.tcp.tcp__header import TCP__HEADER__LEN
from pytcp.protocols.tcp.tcp__parser import TcpParser


@parameterized_class(
    [
        {
            "_description": (
                "The value of the 'ip__payload_len' variable is lower than the "
                "value of the 'TCP_HEADER_LEN' constant."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                    b"\xcb\x5b\x00\x00\x01\x01\x01\x01"
                ),
            },
            "_conditions": {
                "ip__payload_len": TCP__HEADER__LEN - 1,
            },
            "_results": {
                "error_message": "The wrong packet length (I).",
            },
        },
        {
            "_description": (
                "The value of the 'ip__payload_len' variable is higher than the frame length."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                    b"\xcb\x5b\x00\x00\x01\x01\x01\x01"
                ),
            },
            "_conditions": {
                "ip__payload_len": TCP__HEADER__LEN + 4 + 1,
            },
            "_results": {
                "error_message": "The wrong packet length (I).",
            },
        },
        {
            "_description": (
                "The value of the header 'hlen' field (19) is lower than the 'TCP_HEADER_LEN'."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x4c\x10\x2b\x67"
                    b"\xdf\x5b\x00\x00\x01\x01\x01\x01"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
        {
            "_description": (
                "The value of the header 'hlen' field (28) is higher than the value "
                "of the 'ip__payload_len' variable."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x70\x10\x2b\x67"
                    b"\xbb\x5b\x00\x00\x01\x01\x01\x01"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
        {
            "_description": "Packet has incorrect checksum.",
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                    b"\xbe\x86\x00\x00\x03\x03\x0a\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The wrong packet checksum.",
            },
        },
        {
            "_description": (
                "The value of the option 'len' field (1) is lower than the minimum "
                "acceptable value (2)."
                "of the 'ip__payload_len' variable."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                    b"\xce\x5b\x00\x00\xff\x01\x00\x00"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The wrong option length (I).",
            },
        },
        {
            "_description": (
                "The value of the option 'len' field (5 vs 3) is extends past the value "
                "of the 'hlen' header field."
            ),
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                    b"\xce\x57\x00\x00\xff\x05\x00\x00"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The wrong option length (II).",
            },
        },
    ],
)
class TestTcpParserIntegrityChecks(TestCase):
    """
    The TCP packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _conditions: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser raises integrity error on malformed packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip = cast(Ip4Parser, StrictMock(template=Ip4Parser))
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="payload_len",
            new_value=self._conditions.get(
                "ip__payload_len", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="pshdr_sum",
            new_value=0,
        )

        with self.assertRaises(TcpIntegrityError) as error:
            TcpParser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][TCP] {self._results["error_message"]}",
        )
