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
This module contains tests for the Ethernet II packet integrity checks.

tests/unit/protocols/ethernet/test__parser__integrity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ethernet.ethernet__errors import EthernetIntegrityError
from pytcp.protocols.ethernet.ethernet__header import ETHERNET__HEADER__LEN
from pytcp.protocols.ethernet.ethernet__parser import EthernetParser


@parameterized_class(
    [
        {
            "_description": (
                "The frame length is less than the value of the 'ETHERNET__HEADER__LEN' constant."
            ),
            "_args": {
                "bytes": b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\xff"
            },
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ETHERNET__HEADER__LEN} "
                    f"bytes, got {ETHERNET__HEADER__LEN - 1} bytes."
                ),
            },
        },
    ]
)
class TestEthernetParserIntegrityChecks(TestCase):
    """
    The Ethernet packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ethernet__parser__from_bytes(self) -> None:
        """
        Ensure the Ethernet packet parser raises integrity error on malformed packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(EthernetIntegrityError) as error:
            EthernetParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][Ethernet] {self._results["error_message"]}",
        )
