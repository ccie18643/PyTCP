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
This module contains tests for the Ethernet II packet sanity checks.

tests/unit/protocols/ethernet/test__parser__sanity_checks.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ethernet.ethernet__errors import EthernetSanityError
from pytcp.protocols.ethernet.ethernet__parser import EthernetParser


@parameterized_class(
    [
        {
            "_description": (
                "The 'type' field value is lowere than the minimum allowed value."
            ),
            "_args": {
                "bytes": b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xff"
            },
            "_results": {
                "error_message": (
                    "The minimum 'type' field value must be 0x0600, got 0x05ff."
                ),
            },
        },
    ]
)
class TestEthernetParserSanityChecks(TestCase):
    """
    The Ethernet packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ethernet__parser__from_bytes(self) -> None:
        """
        Ensure the Ethernet packet parser raises sanity errors on crazy packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(EthernetSanityError) as error:
            EthernetParser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][Ethernet] {self._results["error_message"]}",
        )
