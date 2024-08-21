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
This module contains tests for the ICMPv6 ND Neighbor Solicitation message assembler.

tests/unit/protocols/icmp6/test__icmp6__message__nd__neighbor_solicitation__assembler.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Type
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_solicitation import (
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdNeighborSolicitationMessage,
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
            "_description": "ICMPv6 ND Neighbor Solicitation message, no options.",
            "_args": {
                "cksum": 12345,
                "target_address": Ip6Address("2001:db8::1"),
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMP6 ND Neighbor Solicitation, target 2001:db8::1, opts [], len 24 (24+0)",
                "__repr__": (
                    "Icmp6NdNeighborSolicitationMessage(code=<Icmp6NdNeighborSolicitationCode.DEFAULT: 0>, "
                    "cksum=12345, options=Icmp6NdOptions(options=[]), target_address=Ip6Address('2001:db8::1'))"
                ),
                "__bytes__": (
                    b"\x87\x00\x00\x00\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_SOLICITATION,
                "code": Icmp6NdNeighborSolicitationCode.DEFAULT,
                "cksum": 12345,
                "options": Icmp6NdOptions(),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Solicitation message, Slla option present.",
            "_args": {
                "cksum": 12345,
                "target_address": Ip6Address("2001:db8::2"),
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                ),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "ICMP6 ND Neighbor Solicitation, target 2001:db8::2, opts [slla 00:11:22:33:44:55], "
                    "len 32 (24+8)"
                ),
                "__repr__": (
                    "Icmp6NdNeighborSolicitationMessage(code=<Icmp6NdNeighborSolicitationCode.DEFAULT: 0>, "
                    "cksum=12345, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla(slla=MacAddress"
                    "('00:11:22:33:44:55'))]), target_address=Ip6Address('2001:db8::2'))"
                ),
                "__bytes__": (
                    b"\x87\x00\x00\x00\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_SOLICITATION,
                "code": Icmp6NdNeighborSolicitationCode.DEFAULT,
                "cksum": 12345,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                ),
            },
        },
    ]
)
class TestIcmp6MessageNdNeighborSolicitationAssembler(TestCase):
    """
    The ICMPv6 ND Neighbor Solicitation message assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        The ICMPv6 ND Neighbor Solicitation message assembler tests.
        """

        self._icmp6__nd__neighbor_solicitation__message = (
            Icmp6NdNeighborSolicitationMessage(**self._args)
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__len(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp6__nd__neighbor_solicitation__message),
            self._results["__len__"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__str(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp6__nd__neighbor_solicitation__message),
            self._results["__str__"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__repr(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__nd__neighbor_solicitation__message),
            self._results["__repr__"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__nd__neighbor_solicitation__message),
            self._results["__bytes__"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__type(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message 'type' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__nd__neighbor_solicitation__message.type,
            self._results["type"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__code(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message 'code' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__nd__neighbor_solicitation__message.code,
            self._results["code"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__cksum(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message 'cksum' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__nd__neighbor_solicitation__message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__message__nd__neighbor_solicitation__assembler__options(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation message 'options' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__nd__neighbor_solicitation__message.options,
            self._results["options"],
        )
