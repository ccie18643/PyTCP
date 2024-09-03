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
This module contains tests for the IPv6 Ext Frag packet sanity checks.

tests/unit/protocols/tcp/test__ip6_ext_frag__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__errors import (
    Ip6ExtFragSanityError,
)
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__parser import Ip6ExtFragParser


@parameterized_class([])
class TestIp6ExtFragParserSanityChecks(TestCase):
    """
    The IPv6 Ext Frag packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_ext_frag__parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 Ext Frag packet parser raises sanity error on crazy packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        with self.assertRaises(Ip6ExtFragSanityError) as error:
            Ip6ExtFragParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv6 Ext Frag] {self._results["error_message"]}",
        )
