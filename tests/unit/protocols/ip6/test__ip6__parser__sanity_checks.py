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
This module contains tests for the IPv6 packet sanity checks.

tests/unit/protocols/tcp/test__ip6__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6.ip6__errors import Ip6SanityError
from pytcp.protocols.ip6.ip6__parser import Ip6Parser


@parameterized_class(
    [
        {
            "_description": "The 'hop' field value is 0.",
            "_args": {
                "bytes": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x00\x10\x01\x20\x02\x30\x03\x40\x04"
                    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
            },
            "_results": {
                "error_message": "The 'hop' must not be 0.",
            },
        },
        {
            "_description": "The 'src' address is multicast.",
            "_args": {
                "bytes": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x01\xff\xff\xff\xff\xff\xff\xff\xff"
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
            },
            "_results": {
                "error_message": "The 'src' must not be multicast.",
            },
        },
    ],
)
class TestIp6ParserSanityChecks(TestCase):
    """
    The IPv6 packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6__parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 packet parser raises sanity error on crazy packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(Ip6SanityError) as error:
            Ip6Parser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv6] {self._results["error_message"]}",
        )
