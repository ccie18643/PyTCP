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
This module contains tests for the ICMPv6 ND Router Advertisement message parser.

tests/unit/protocols/icmp6/test__icmp6__message__nd__router_advertisement__parser.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Network
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__pi import (
    Icmp6NdOptionPi,
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
            "_description": "ICMPv6 ND Router Advertisement message, no options.",
            "_args": {
                "bytes": b"\x86\x00\x00\x00\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            },
            "_results": {
                "from_bytes": Icmp6NdRouterAdvertisementMessage(
                    cksum=0,
                    hop=255,
                    flag_m=True,
                    flag_o=True,
                    router_lifetime=65535,
                    reachable_time=4294967295,
                    retrans_timer=4294967295,
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla option present.",
            "_args": {
                "bytes": (
                    b"\x86\x00\x00\x00\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_results": {
                "from_bytes": Icmp6NdRouterAdvertisementMessage(
                    cksum=0,
                    hop=64,
                    flag_m=False,
                    flag_o=False,
                    router_lifetime=123,
                    reachable_time=456,
                    retrans_timer=789,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla & Pi options present.",
            "_args": {
                "bytes": (
                    b"\x86\x00\x00\x00\x16\x80\x00\x21\x00\x00\x00\x2c\x00\x00\x00\x37"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55\x03\x04\x40\xe0\x00\x01\xe2\x40"
                    b"\x00\x09\xfb\xf1\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
            },
            "_results": {
                "from_bytes": Icmp6NdRouterAdvertisementMessage(
                    cksum=0,
                    hop=22,
                    flag_m=True,
                    flag_o=False,
                    router_lifetime=33,
                    reachable_time=44,
                    retrans_timer=55,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                        Icmp6NdOptionPi(
                            prefix=Ip6Network("2001:db8::/64"),
                            valid_lifetime=123456,
                            preferred_lifetime=654321,
                            flag_l=True,
                            flag_a=True,
                            flag_r=True,
                        ),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, incorrect 'type' field.",
            "_args": {
                "bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": (
                    "The 'type' field must be <Icmp6Type.ND__ROUTER_ADVERTISEMENT: 134>. "
                    "Got: <Icmp6Type.UNKNOWN_255: 255>"
                ),
            },
        },
    ]
)
class TestIcmp6MessageNdRouterAdvertisementParser(TestCase):
    """
    The ICMPv6 ND Router Advertisement message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__message__nd__router_advertisement__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'from_bytes()' method
        creates a proper message object.
        """

        if "error" in self._results:
            with self.assertRaises(AssertionError) as error:
                Icmp6NdRouterAdvertisementMessage.from_bytes(
                    self._args["bytes"]
                )

            self.assertEqual(
                str(error.exception),
                self._results["error"],
            )

        if "from_bytes" in self._results:
            self.assertEqual(
                Icmp6NdRouterAdvertisementMessage.from_bytes(
                    self._args["bytes"]
                ),
                self._results["from_bytes"],
            )
