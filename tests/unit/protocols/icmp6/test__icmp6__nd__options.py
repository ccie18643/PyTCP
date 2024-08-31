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
Module contains tests for the ICMPv6 ND options support code.

tests/unit/protocols/icmp6/test__icmp6__nd__options.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOption,
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
            "_description": "The ICMPv6 ND options (I).",
            "_args": [
                Icmp6NdOptionSlla(slla=MacAddress()),
                Icmp6NdOptionSlla(slla=MacAddress()),
                Icmp6NdOptionSlla(slla=MacAddress()),
                Icmp6NdOptionSlla(slla=MacAddress()),
            ],
            "_results": {
                "__len__": 32,
                "__str__": (
                    "slla 00:00:00:00:00:00, slla 00:00:00:00:00:00, "
                    "slla 00:00:00:00:00:00, slla 00:00:00:00:00:00"
                ),
                "__repr__": (
                    "Icmp6NdOptions(options=[Icmp6NdOptionSlla(slla=MacAddress("
                    "'00:00:00:00:00:00')), Icmp6NdOptionSlla(slla=MacAddress("
                    "'00:00:00:00:00:00')), Icmp6NdOptionSlla(slla="
                    "MacAddress('00:00:00:00:00:00')), Icmp6NdOptionSlla(slla="
                    "MacAddress('00:00:00:00:00:00'))])"
                ),
                "__bytes__": (
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionsAssembler(TestCase):
    """
    The ICMPv6 ND options assembler tests.
    """

    _description: str
    _args: list[Icmp6NdOption]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize an Icmp6NdOptions object with the testcase arguments.
        """

        self._icmp6_nd_options = Icmp6NdOptions(*self._args)

    def test__icmp6_nd_options__len(self) -> None:
        """
        Ensure the Icmp6NdOptions '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._icmp6_nd_options),
            self._results["__len__"],
        )

    def test__icmp6_nd_options__str(self) -> None:
        """
        Ensure the Icmp6NdOptions '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._icmp6_nd_options),
            self._results["__str__"],
        )

    def test__icmp6_nd_options__repr(self) -> None:
        """
        Ensure the Icmp6NdOptions '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_options),
            self._results["__repr__"],
        )

    def test__icmp6_options__bytes(self) -> None:
        """
        Ensure the Icmp6NdOptions '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_options),
            self._results["__bytes__"],
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND options (II).",
            "_args": {
                "bytes": (
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                    b"\x01\x01\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00"
                ),
            },
            "_results": {
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress()),
                    Icmp6NdOptionSlla(slla=MacAddress()),
                    Icmp6NdOptionSlla(slla=MacAddress()),
                    Icmp6NdOptionSlla(slla=MacAddress()),
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionsParser(TestCase):
    """
    The 'Icmp6NdOptions' class parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6_nd_options__from_bytes(self) -> None:
        """
        Ensure the 'Icmp6NdOptions' class parser creates the proper options
        object.
        """

        icmp6_nd_options = Icmp6NdOptions.from_bytes(self._args["bytes"])

        self.assertEqual(
            icmp6_nd_options,
            self._results["options"],
        )
