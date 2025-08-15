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
This module contains tests for the IPv6 Frag packet sanity checks.

tests/pytcp/unit/protocols/tcp/test__ip6_frag__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.ip6_frag.ip6_frag__errors import Ip6FragSanityError
from pytcp.protocols.ip6_frag.ip6_frag__parser import Ip6FragParser
from tests.pytcp.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class([])
class TestIp6FragParserSanityChecks(TestCasePacketRxIp6):
    """
    The IPv6 Frag packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ip6_frag__parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 Frag packet parser raises sanity error on crazy packets.
        """

        with self.assertRaises(Ip6FragSanityError) as error:
            Ip6FragParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv6 Frag] {self._results["error_message"]}",
        )
