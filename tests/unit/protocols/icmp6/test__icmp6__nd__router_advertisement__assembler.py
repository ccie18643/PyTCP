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
Module contains tests for the ICMPv6 ND Router Sdvertisement message assembler.

tests/unit/protocols/icmp6/test__icmp6__nd__router_advertisement__assembler.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Network
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Type
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementCode,
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
                "hop": 255,
                "flag_m": True,
                "flag_o": True,
                "router_lifetime": 65535,
                "reachable_time": 4294967295,
                "retrans_timer": 4294967295,
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 16,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 255, flags MO, rlft 65535, "
                    "reacht 4294967295, retrt 4294967295, len 16 (16+0)"
                ),
                "__repr__": (
                    "Icmp6NdRouterAdvertisementMessage(code=<Icmp6NdRouterAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[]), hop=255, "
                    "flag_m=True, flag_o=True, router_lifetime=65535, reachable_time=4294967295, "
                    "retrans_timer=4294967295)"
                ),
                "__bytes__": (
                    b"\x86\x00\x7a\x3e\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "flag_m": True,
                "flag_o": True,
                "router_lifetime": 65535,
                "reachable_time": 4294967295,
                "retrans_timer": 4294967295,
                "options": Icmp6NdOptions(),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla option present.",
            "_args": {
                "hop": 64,
                "flag_m": False,
                "flag_o": False,
                "router_lifetime": 123,
                "reachable_time": 456,
                "retrans_timer": 789,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                ),
            },
            "_results": {
                "__len__": 24,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 64, flags --, rlft 123, reacht 456, "
                    "retrt 789, opts [slla 00:11:22:33:44:55], len 24 (16+8)"
                ),
                "__repr__": (
                    "Icmp6NdRouterAdvertisementMessage(code=<Icmp6NdRouterAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]), hop=64, flag_m=False, flag_o=False, "
                    "router_lifetime=123, reachable_time=456, retrans_timer=789)"
                ),
                "__bytes__": (
                    b"\x86\x00\xcd\x0c\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "hop": 64,
                "flag_m": False,
                "flag_o": False,
                "router_lifetime": 123,
                "reachable_time": 456,
                "retrans_timer": 789,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla & Pi options present.",
            "_args": {
                "hop": 22,
                "flag_m": True,
                "flag_o": False,
                "router_lifetime": 33,
                "reachable_time": 44,
                "retrans_timer": 55,
                "options": Icmp6NdOptions(
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
            },
            "_results": {
                "__len__": 56,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 22, flags M-, rlft 33, "
                    "reacht 44, retrt 55, opts [slla 00:11:22:33:44:55, prefix_info "
                    "(prefix 2001:db8::/64, flags LAR, valid_lifetime 123456, "
                    "preferred_lifetime 654321)], len 56 (16+40)"
                ),
                "__repr__": (
                    "Icmp6NdRouterAdvertisementMessage(code=<Icmp6NdRouterAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55')), Icmp6NdOptionPi(flag_l=True, "
                    "flag_a=True, flag_r=True, valid_lifetime=123456, preferred_lifetime=654321, "
                    "prefix=Ip6Network('2001:db8::/64'))]), hop=22, flag_m=True, flag_o=False, "
                    "router_lifetime=33, reachable_time=44, retrans_timer=55)"
                ),
                "__bytes__": (
                    b"\x86\x00\xab\x86\x16\x80\x00\x21\x00\x00\x00\x2c\x00\x00\x00\x37"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55\x03\x04\x40\xe0\x00\x01\xe2\x40"
                    b"\x00\x09\xfb\xf1\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "hop": 22,
                "flag_m": True,
                "flag_o": False,
                "router_lifetime": 33,
                "reachable_time": 44,
                "retrans_timer": 55,
                "options": Icmp6NdOptions(
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
            },
        },
    ]
)
class TestIcmp6NdRouterAdvertisementAssembler(TestCase):
    """
    The ICMPv6 ND Router Advertisement message assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        The ICMPv6 ND Router Advertisement message assembler tests.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6NdRouterAdvertisementMessage(**self._args)
        )

    def test__icmp6__nd__router_advertisement__assembler__len(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message '__len__()' method
        returns a correct value.
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
        )

    def test__icmp6__nd__router_advertisement__assembler__str(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message '__str__()' method
        returns a correct value.
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
        )

    def test__icmp6__nd__router_advertisement__assembler__repr(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message '__repr__()' method
        returns a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
        )

    def test__icmp6__nd__router_advertisement__assembler__bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message '__bytes__()' method
        returns a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__router_advertisement__assembler__type(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'type' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
        )

    def test__icmp6__nd__router_advertisement__assembler__code(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'code' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
        )

    def test__icmp6__nd__router_advertisement__assembler__cksum(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'cksum' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__nd__router_advertisement__assembler__flag_m(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'flag_m' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).flag_m,
            self._results["flag_m"],
        )

    def test__icmp6__nd__router_advertisement__assembler__flag_o(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'flag_o' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).flag_o,
            self._results["flag_o"],
        )

    def test__icmp6__nd__router_advertisement__assembler__router_lifetime(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'router_lifetime' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).router_lifetime,
            self._results["router_lifetime"],
        )

    def test__icmp6__nd__router_advertisement__assembler__reachable_time(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'reachable_time' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).reachable_time,
            self._results["reachable_time"],
        )

    def test__icmp6__nd__router_advertisement__assembler__retrans_timer(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'retrans_timer' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).retrans_timer,
            self._results["retrans_timer"],
        )

    def test__icmp6__nd__router_advertisement__assembler__options(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement message 'options' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdRouterAdvertisementMessage,
                self._icmp6__assembler.message,
            ).options,
            self._results["options"],
        )
