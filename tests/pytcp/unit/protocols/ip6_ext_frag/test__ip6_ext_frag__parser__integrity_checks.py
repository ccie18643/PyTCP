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
This module contains tests for the IPv6 Ext Frag packet integrity checks.

tests/pytcp/unit/protocols/tcp/test__ip6_ext_frag__parser__integrity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__errors import (
    Ip6ExtFragIntegrityError,
)
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__parser import Ip6ExtFragParser
from tests.pytcp.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": (
                "The length of the frame is lower than the value of the "
                "'IP6_EXT_FRAG__HEADER__LEN' constant."
            ),
            "_args": [b"\xff\x00\x00\x00\x00\x00\x00"],
            "_kwargs": {},
            "_results": {
                "error_message": "The wrong packet length (I).",
            },
        },
    ],
)
class TestIp6ExtFragParserIntegrityChecks(TestCasePacketRxIp6):
    """
    The IPv6 Ext Frag packet parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ip6_ext_frag__parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 Ext Frag packet parser raises integrity error on malformed packets.
        """

        with self.assertRaises(Ip6ExtFragIntegrityError) as error:
            Ip6ExtFragParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][IPv6 Ext Frag] {self._results["error_message"]}",
        )
