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
This module contains tests for the ARP packet sanity checks.

tests/unit/protocols/arp/test__arp__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.arp.arp__errors import ArpSanityError
from pytcp.protocols.arp.arp__parser import ArpParser


@parameterized_class(
    [
        {
            "_description": "The value of the 'prlen' field is incorrect.",
            "_args": {
                "bytes": (
                    b"\x00\x01\x08\x00\x06\x04\x00\x00\x01\x02\x03\x04\x05\x06\x0b\x16"
                    b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
                ),
            },
            "_results": {
                "error_message": "The 'oper' field value must be one of [1, 2], got 0.",
            },
        },
    ]
)
class TestArpParserSanityChecks(TestCase):
    """
    The ARP packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__arp__parser__from_bytes(self) -> None:
        """
        Ensure the ARP packet parser raises sanity errors on crazy packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ARP] {self._results["error_message"]}",
        )
