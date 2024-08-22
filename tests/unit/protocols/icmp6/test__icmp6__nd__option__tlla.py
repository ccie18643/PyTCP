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
This module contains tests for the ICMPv6 ND Tlla (Target Link Layer Address)
option code.

tests/unit/protocols/icmp6/test__icmp6__nd__option__tlla.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOptionType,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__tlla import (
    Icmp6NdOptionTlla,
)


class TestIcmp6NdOptionTllaAsserts(TestCase):
    """
    The ICMPv6 ND Tlla option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Tlla option constructor.
        """

        self._option_args = {
            "tlla": MacAddress(),
        }

    def test__icmp6__nd__option__tlla__tlla__not_MacAddress(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option constructor raises an exception when
        the provided 'tlla' argument is not a MacAddress.
        """

        self._option_args["tlla"] = value = "not a MacAddress"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionTlla(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'tlla' field must be a MacAddress. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Tlla option (I).",
            "_args": {
                "tlla": MacAddress("01:02:03:04:05:06"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "tlla 01:02:03:04:05:06",
                "__repr__": (
                    "Icmp6NdOptionTlla(tlla=MacAddress('01:02:03:04:05:06'))"
                ),
                "__bytes__": b"\x02\x01\x01\x02\x03\x04\x05\x06",
                "type": Icmp6NdOptionType.TLLA,
                "len": 8,
                "tlla": MacAddress("01:02:03:04:05:06"),
            },
        },
    ]
)
class TestIcmp6NdOptionTllaAssembler(TestCase):
    """
    The ICMPv6 ND Tlla option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 ND Tlla option object with testcase arguments.
        """

        self._icmp6_nd_option_tlla = Icmp6NdOptionTlla(**self._args)

    def test__icmp6__nd__option__tlla__len(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._icmp6_nd_option_tlla),
            self._results["__len__"],
        )

    def test__icmp6__nd__option__tlla__str(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._icmp6_nd_option_tlla),
            self._results["__str__"],
        )

    def test__icmp6__nd__option__tlla__repr(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_option_tlla),
            self._results["__repr__"],
        )

    def test__icmp6__nd__option__tlla__bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_option_tlla),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__option__tlla__type(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option 'type' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_tlla.type,
            self._results["type"],
        )

    def test__icmp6__nd__option__tlla__length(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option 'len' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_tlla.len,
            self._results["len"],
        )

    def test__icmp6__nd__option__tlla__tlla(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option 'tlla' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_tlla.tlla,
            self._results["tlla"],
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Tlla option (I).",
            "_args": {
                "bytes": b"\x02\x01\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "option": Icmp6NdOptionTlla(
                    tlla=MacAddress("01:02:03:04:05:06")
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Tlla option minimum length assert.",
            "_args": {
                "bytes": b"\x02",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the ICMPv6 ND Tlla option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Tlla option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\x01\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Tlla option type must be {Icmp6NdOptionType.TLLA!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Tlla option length integrity check (I).",
            "_args": {
                "bytes": b"\x02\x02\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Tlla option length "
                    "must be 8 bytes. Got: 16"
                ),
            },
        },
        {
            "_description": "The ND Tlla option length integrity check (II).",
            "_args": {
                "bytes": b"\x02\x01\x01\x02\x03\x04\x05",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Tlla option length "
                    "must be less than or equal to the length of provided bytes "
                    "(7). Got: 8"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionTllaParser(TestCase):
    """
    The ICMPv6 ND Tlla option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__tlla__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Tlla option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            icmp6_nd_option_tlla = Icmp6NdOptionTlla.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                icmp6_nd_option_tlla,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Icmp6NdOptionTlla.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
