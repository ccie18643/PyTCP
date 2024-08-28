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
This module contains tests for the IPv4 packet integrity checks.

tests/unit/protocols/tcp/test__ip4_parser__integrity_checks.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__errors import Ip4IntegrityError
from pytcp.protocols.ip4.ip4__parser import Ip4Parser


@parameterized_class(
    [
        {
            "_description": (
                "The length of the frame is lower than the value of the "
                "'IP4_HEADER_LEN' constant."
            ),
            "_args": {
                "bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x73\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46"
                ),
            },
            "_results": {
                "error_message": "The wrong packet length (I).",
            },
        },
        {
            "_description": ("The value of the 'ver' field is incorrect."),
            "_args": {
                "bytes": (
                    b"\x55\xff\x00\x14\xff\xff\x40\x00\xff\xff\xc9\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
            "_results": {
                "error_message": "Value of the 'ver' field must be set to 4.",
            },
        },
        {
            "_description": (
                "The value of the 'hlen' field is lower than the value of the "
                "'IP4_HEADER_LEN' constant."
            ),
            "_args": {
                "bytes": (
                    b"\x44\xff\x00\x14\xff\xff\x40\x00\xff\xff\xda\x23\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
        {
            "_description": (
                "The value of the 'plen' field is lower than the value of the 'hlen' field."
            ),
            "_args": {
                "bytes": (
                    b"\x45\xff\x00\x13\xff\xff\x40\x00\xff\xff\xd9\x24\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
        {
            "_description": (
                "The value of the 'hlen' & 'plen' fields ar higher than the length of the frame."
            ),
            "_args": {
                "bytes": (
                    b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd8\x1f\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
        {
            "_description": "The value of the 'cksum' field is invalid.",
            "_args": {
                "bytes": (
                    b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xd9\x24\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50"
                ),
            },
            "_results": {
                "error_message": "The wrong packet checksum.",
            },
        },
        {
            "_description": (
                "The value of the option 'len' field (1) is lower than the minimum "
                "acceptable value (2)."
            ),
            "_args": {
                "bytes": (
                    b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd9\x1d\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50\xff\x01\x00\x00"
                ),
            },
            "_results": {
                "error_message": (
                    "The IPv4 option length must be greater than 1. Got: 1."
                ),
            },
        },
        {
            "_description": (
                "The value of the option 'len' field (5 vs 3) is extends past the value "
                "of the 'hlen' header field."
            ),
            "_args": {
                "bytes": (
                    b"\x46\xff\x00\x18\xff\xff\x40\x00\xff\xff\xd9\x19\x0a\x14\x1e\x28"
                    b"\x32\x3c\x46\x50\xff\x05\x00\x00"
                ),
            },
            "_results": {
                "error_message": (
                    "The IPv4 option length must not extend past the header "
                    "length. Got: offset=25, hlen=24"
                ),
            },
        },
    ],
)
class TestIp4ParserIntegrityChecks(TestCase):
    """
    The IPv4 packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4__parser__from_bytes(self) -> None:
        """
        Ensure the IPv4 packet parser raises integrity error on malformed packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Parser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv4] {self._results["error_message"]}",
        )
