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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message
assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__neighbor_advertisement__assembler.py

ver 3.0.4
"""


from typing import Any, cast

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdNeighborAdvertisementMessage,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Type,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, no options.",
            "_args": [],
            "_kwargs": {
                "flag_r": True,
                "flag_s": False,
                "flag_o": True,
                "target_address": Ip6Address("2001:db8::1"),
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 24,
                "__str__": (
                    "ICMPv6 ND Neighbor Advertisement, flags R-O, target 2001:db8::1, "
                    "len 24 (24+0)"
                ),
                "__repr__": (
                    "Icmp6NdNeighborAdvertisementMessage(code=<Icmp6NdNeighborAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[]), flag_r=True, "
                    "flag_s=False, flag_o=True, target_address=Ip6Address('2001:db8::1'))"
                ),
                "__bytes__": (
                    b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
                "code": Icmp6NdNeighborAdvertisementCode.DEFAULT,
                "cksum": 0,
                "flag_r": True,
                "flag_s": False,
                "flag_o": True,
                "target_address": Ip6Address("2001:db8::1"),
                "options": Icmp6NdOptions(),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, Slla option present.",
            "_args": [],
            "_kwargs": {
                "flag_r": False,
                "flag_s": True,
                "flag_o": False,
                "target_address": Ip6Address("2001:db8::2"),
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                ),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "ICMPv6 ND Neighbor Advertisement, flags -S-, target 2001:db8::2, opts "
                    "[slla 00:11:22:33:44:55], len 32 (24+8)"
                ),
                "__repr__": (
                    "Icmp6NdNeighborAdvertisementMessage(code=<Icmp6NdNeighborAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]), flag_r=False, flag_s=True, "
                    "flag_o=False, target_address=Ip6Address('2001:db8::2'))"
                ),
                "__bytes__": (
                    b"\x88\x00\xa2\xa9\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
                "code": Icmp6NdNeighborAdvertisementCode.DEFAULT,
                "cksum": 0,
                "flag_r": False,
                "flag_s": True,
                "flag_o": False,
                "target_address": Ip6Address("2001:db8::2"),
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                ),
            },
        },
    ]
)
class TestIcmp6NdNeighborAdvertisementAssembler(TestCase):
    """
    The ICMPv6 ND Neighbor Advertisement message assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        The ICMPv6 ND Neighbor Advertisement message assembler tests.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6NdNeighborAdvertisementMessage(
                *self._args, **self._kwargs
            )
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__len(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message '__len__()' method
        returns a correct value.
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__str(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message '__str__()' method
        returns a correct value.
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__repr(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message '__repr__()' method
        returns a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message '__bytes__()' method
        returns a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__type(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'type' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__code(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'code' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__cksum(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'cksum' field
        contains a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__flag_r(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'flag_r' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdNeighborAdvertisementMessage,
                self._icmp6__assembler.message,
            ).flag_r,
            self._results["flag_r"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__flag_s(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'flag_s' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdNeighborAdvertisementMessage,
                self._icmp6__assembler.message,
            ).flag_s,
            self._results["flag_s"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__flag_o(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'flag_o' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdNeighborAdvertisementMessage,
                self._icmp6__assembler.message,
            ).flag_o,
            self._results["flag_o"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__target_address(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'target_address' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdNeighborAdvertisementMessage,
                self._icmp6__assembler.message,
            ).target_address,
            self._results["target_address"],
        )

    def test__icmp6__nd__neighbor_advertisement__assembler__options(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement message 'options' field
        contains a correct value.
        """

        self.assertEqual(
            cast(
                Icmp6NdNeighborAdvertisementMessage,
                self._icmp6__assembler.message,
            ).options,
            self._results["options"],
        )
