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
This module contains tests for the ICMPv6 ND Router Solicitation message parser.

tests/unit/protocols/icmp6/test__icmp6__message__nd__router_solicitation__parser.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Router Solicitation message, no options.",
            "_args": {
                "bytes": b"\x85\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6NdRouterSolicitationMessage(
                    cksum=0,
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Solicitation message, Slla option present.",
            "_args": {
                "bytes": b"\x85\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55",
            },
            "_results": {
                "from_bytes": Icmp6NdRouterSolicitationMessage(
                    cksum=0,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Solicitation message, incorrect 'type' field.",
            "_args": {
                "bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": (
                    "The 'type' field must be <Icmp6Type.ND__ROUTER_SOLICITATION: 143>. "
                    "Got: <Icmp6Type.UNKNOWN_255: 255>"
                ),
            },
        },
    ]
)
class TestIcmp6MessageNdRouterSolicitationParser(TestCase):
    """
    The ICMPv6 ND Router Solicitation message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__message__nd__router_solicitation__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Solicitation message 'from_bytes()' method
        creates a proper message object.
        """

        if "error" in self._results:
            with self.assertRaises(AssertionError) as error:
                Icmp6NdRouterSolicitationMessage.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error"],
            )

        if "from_bytes" in self._results:
            self.assertEqual(
                Icmp6NdRouterSolicitationMessage.from_bytes(
                    self._args["bytes"]
                ),
                self._results["from_bytes"],
            )
