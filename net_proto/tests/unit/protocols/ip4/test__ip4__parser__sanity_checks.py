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
This module contains tests for the IPv4 packet sanity checks.

net_proto/tests/unit/protocols/tcp/test__ip4__parser__sanity_checks.py

ver 3.0.4
"""


from typing import Any

from net_proto import Ip4Parser, Ip4SanityError, PacketRx
from net_proto.tests.lib.testcase__packet_rx import TestCasePacketRx
from parameterized import parameterized_class  # type: ignore


@parameterized_class(
    [
        {
            "_description": "The value of the 'ttl' field is 0.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x40\x00\x00\xff\xd8\x24\x0a\x14\x1e\x28"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Value of the 'ttl' field must be greater than 0.",
            },
        },
        {
            "_description": "The source IP address is a multicast address.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x21\x5e\xe0\x00\x00\x01"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Value of the 'src' field must not be a multicast address.",
            },
        },
        {
            "_description": "The source IP address is a reserved address.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x11\x5e\xf0\x00\x00\x01"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Value of the 'src' field must not be a reserved address.",
            },
        },
        {
            "_description": "The source IP address is a limited broadcast.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x01\x60\xff\xff\xff\xff"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Value of the 'src' field must not be a limited broadcast address.",
            },
        },
        {
            "_description": "The fields 'flag_df' and 'flag_mf' are both set.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x60\x00\xff\xff\xb9\x23\x0a\x14\x1e\x28"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Flags 'DF' and 'MF' must not be set simultaneously.",
            },
        },
        {
            "_description": "The field 'flag_df' is set and value of the 'offset' field is non-zero.",
            "_args": [
                b"\x45\xff\x00\x14\xff\xff\x41\x00\xff\xff\xd8\x23\x0a\x14\x1e\x28"
                b"\x32\x3c\x46\x50"
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "Value of the 'offset' field must be 0 when 'DF' flag is set.",
            },
        },
    ],
)
class TestIp4ParserSanityChecks(TestCasePacketRx):
    """
    The IPv4 packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ip4__parser__from_bytes(self) -> None:
        """
        Ensure the IPv4 packet parser raises sanity error on crazy packets.
        """

        with self.assertRaises(Ip4SanityError) as error:
            Ip4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv4] {self._results["error_message"]}",
        )
