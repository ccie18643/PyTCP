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
This module contains tests for the IPv6 packet integrity checks.

tests/pytcp/unit/protocols/tcp/test__ip6__parser__integrity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6.ip6__errors import Ip6IntegrityError
from pytcp.protocols.ip6.ip6__parser import Ip6Parser
from tests.pytcp.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": (
                "The length of the frame is lower than the value of the "
                "'IP6__HEADER__LEN' constant."
            ),
            "_kwargs": {},
            "_args": [
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b"
            ],
            "_results": {
                "error_message": "The wrong packet length (I).",
            },
        },
        {
            "_description": ("The value of the 'ver' field is incorrect"),
            "_args": [
                b"\x50\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'ver' must be 6.",
            },
        },
        {
            "_description": (
                "The value of the 'dlen' field is different the length of the frame less "
                "the value of the 'IP6_HEADER_LEN' constant."
            ),
            "_args": [
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b\x00"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The wrong packet length (II).",
            },
        },
    ],
)
class TestIp6ParserIntegrityChecks(TestCasePacketRx):
    """
    The IPv6 packet parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ip6__parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 packet parser raises integrity error on malformed packets.
        """

        with self.assertRaises(Ip6IntegrityError) as error:
            Ip6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv6] {self._results["error_message"]}",
        )
