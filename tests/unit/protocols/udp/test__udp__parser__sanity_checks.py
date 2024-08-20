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
This module contains tests for the UDP packet sanity checks.

tests/unit/protocols/udp/test__udp__parser__sanity_checks.py

ver 3.0.0
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.protocols.udp.udp__errors import UdpSanityError
from pytcp.protocols.udp.udp__parser import UdpParser


@parameterized_class(
    [
        {
            "_description": "The value of the 'sport' field equals '0'.",
            "_args": {
                "bytes": b"\x00\x00\xd4\x31\x00\x08\x2b\xc6",
            },
            "_results": {
                "error_message": "The 'sport' value must be greater than 0.",
            },
        },
        {
            "_description": "The value of the 'dport' field equals '0'.",
            "_args": {
                "bytes": b"\x30\x39\x00\x00\x00\x08\xcf\xbe",
            },
            "_results": {
                "error_message": "The 'dport' value must be greater than 0.",
            },
        },
    ]
)
class TestUdpParserSanityChecks(TestCase):
    """
    The UDP packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser raises sanity errors on crazy packets.
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

        with self.assertRaises(UdpSanityError) as error:
            UdpParser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][UDP] {self._results["error_message"]}",
        )
