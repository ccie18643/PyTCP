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
Module contains tests for the ICMPv6 ND Slla (Source Link Layer Address) option
code.

tests/unit/protocols/icmp6/test__icmp6__nd__option__slla.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOptionType,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)


class TestIcmp6NdOptionSllaAsserts(TestCase):
    """
    The ICMPv6 ND Slla option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Slla option constructor.
        """

        self._option_args = {
            "slla": MacAddress(),
        }

    def test__icmp6__nd__option__slla__slla__not_MacAddress(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option constructor raises an exception when
        the provided 'slla' argument is not a MacAddress.
        """

        self._option_args["slla"] = value = "not a MacAddress"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionSlla(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'slla' field must be a MacAddress. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Slla option (I).",
            "_args": {
                "slla": MacAddress("01:02:03:04:05:06"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "slla 01:02:03:04:05:06",
                "__repr__": (
                    "Icmp6NdOptionSlla(slla=MacAddress('01:02:03:04:05:06'))"
                ),
                "__bytes__": b"\x01\x01\x01\x02\x03\x04\x05\x06",
                "type": Icmp6NdOptionType.SLLA,
                "len": 8,
                "slla": MacAddress("01:02:03:04:05:06"),
            },
        },
    ]
)
class TestIcmp6NdOptionSllaAssembler(TestCase):
    """
    The ICMPv6 ND Slla option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 ND Slla option object with testcase arguments.
        """

        self._icmp6_nd_option_slla = Icmp6NdOptionSlla(**self._args)

    def test__icmp6__nd__option__slla__len(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._icmp6_nd_option_slla),
            self._results["__len__"],
        )

    def test__icmp6__nd__option__slla__str(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._icmp6_nd_option_slla),
            self._results["__str__"],
        )

    def test__icmp6__nd__option__slla__repr(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_option_slla),
            self._results["__repr__"],
        )

    def test__icmp6__nd__option__slla__bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_option_slla),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__option__slla__type(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_slla.type,
            self._results["type"],
        )

    def test__icmp6__nd__option__slla__length(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_slla.len,
            self._results["len"],
        )

    def test__icmp6__nd__option__slla__slla(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option 'slla' field contains a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_slla.slla,
            self._results["slla"],
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Slla option (I).",
            "_args": {
                "bytes": b"\x01\x01\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "option": Icmp6NdOptionSlla(
                    slla=MacAddress("01:02:03:04:05:06")
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Slla option minimum length assert.",
            "_args": {
                "bytes": b"\x01",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the ICMPv6 ND Slla option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Slla option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\x01\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Slla option type must be {Icmp6NdOptionType.SLLA!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Slla option length integrity check (I).",
            "_args": {
                "bytes": b"\x01\x02\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Slla option length "
                    "must be 8 bytes. Got: 16"
                ),
            },
        },
        {
            "_description": "The ND Slla option length integrity check (II).",
            "_args": {
                "bytes": b"\x01\x01\x01\x02\x03\x04\x05",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Slla option length "
                    "must be less than or equal to the length of provided bytes "
                    "(7). Got: 8"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionSllaParser(TestCase):
    """
    The ICMPv6 ND Slla option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__slla__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            icmp6_nd_option_slla = Icmp6NdOptionSlla.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            )

            self.assertEqual(
                icmp6_nd_option_slla,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Icmp6NdOptionSlla.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
