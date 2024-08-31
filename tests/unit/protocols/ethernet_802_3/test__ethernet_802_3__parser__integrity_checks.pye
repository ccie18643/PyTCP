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
This module contains tests for the Ethernet 802.3 packet integrity checks.

tests/unit/protocols/ethernet/test__ethernet_802_3__parser__integrity_checks.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ethernet_802_3.ethernet_802_3__errors import (
    Ethernet8023IntegrityError,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__parser import (
    Ethernet8023Parser,
)


@parameterized_class(
    [
        {
            "_description": (
                "The frame length is less than the value of the 'ETHERNET_802_3__HEADER__LEN' "
                "constant."
            ),
            "_args": {
                "bytes": b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00"
            },
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET_802_3__HEADER__LEN} "
                    f"bytes, got {ETHERNET_802_3__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": (
                "The 'dlen' field value is different than the actual payload length."
            ),
            "_args": {
                "bytes": (
                    b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00\x10\x30\x31"
                    b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x47"
                ),
            },
            "_results": {
                "error_message": (
                    f"Inconsistent payload length (16 bytes) in the Ethernet 802.3 header. "
                    f"Frame length is {ETHERNET_802_3__HEADER__LEN} + 17 bytes."
                ),
            },
        },
        {
            "_description": "Ethernet 802.3 packet (III).",
            "_args": {
                "bytes": (
                    b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xdd"
                    + b"X" * (ETHERNET_802_3__PAYLOAD__MAX_LEN + 1)
                ),
            },
            "_results": {
                "error_message": (
                    f"Payload length ({ETHERNET_802_3__PAYLOAD__MAX_LEN + 1} bytes) exceeds the "
                    f"maximum allowed value of {ETHERNET_802_3__PAYLOAD__MAX_LEN} bytes."
                )
            },
        },
    ]
)
class TestEthernet8023ParserIntegrityChecks(TestCase):
    """
    The Ethernet 802.3 packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ethernet_802_3__parser__from_bytes(self) -> None:
        """
        Ensure the Ethernet 802.3 packet parser raises integrity error on malformed
        packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(Ethernet8023IntegrityError) as error:
            Ethernet8023Parser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][Ethernet 802.3] {self._results["error_message"]}",
        )
