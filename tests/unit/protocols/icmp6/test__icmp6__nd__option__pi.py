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
This module contains tests for the ICMPv6 ND Pi (Prefix Information) option code.

tests/unit/protocols/icmp6/test__icmp6__nd__option__pi.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_32__MAX, UINT_32__MIN
from pytcp.lib.ip6_address import Ip6Network
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__pi import (
    Icmp6NdOptionPi,
)


class TestIcmp6NdOptionPiAsserts(TestCase):
    """
    The ICMPv6 ND Pi option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Pi option constructor.
        """

        self._option_args = {
            "flag_l": False,
            "flag_a": False,
            "flag_r": False,
            "valid_lifetime": 0,
            "preferred_lifetime": 0,
            "prefix": Ip6Network(),
        }

    def test__icmp6__nd__option__pi__flag_l__not_boolean(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when the provided
        'flag_l' argument is not a boolean.
        """

        self._option_args["flag_l"] = value = "not a boolean"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_l' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__flag_a__not_boolean(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when the provided
        'flag_a' argument is not a boolean.
        """

        self._option_args["flag_a"] = value = "not a boolean"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_a' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__flag_r__not_boolean(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when the provided
        'flag_r' argument is not a boolean.
        """

        self._option_args["flag_r"] = value = "not a boolean"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_r' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__under_min(self) -> None:
        """
        Ensure the  option constructor raises an exception when the
        provided 'valid_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["valid_lifetime"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__over_max(self) -> None:
        """
        Ensure the  option constructor raises an exception when the
        provided 'valid_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["valid_lifetime"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__under_min(
        self,
    ) -> None:
        """
        Ensure the  option constructor raises an exception when the
        provided 'preferred_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["preferred_lifetime"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__over_max(self) -> None:
        """
        Ensure the  option constructor raises an exception when the
        provided 'preferred_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["preferred_lifetime"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__icmp6__nd__option__pi__prefix__not_Ip6Network(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when the provided
        'prefix' argument is not a Ip6Network.
        """

        self._option_args["prefix"] = value = "not a Ip6Network"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'prefix' field must be an Ip6Network. Got: {type(value)!r}",
        )


'''
@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Slla option.",
            "_args": {
                "slla": MacAddress("01:02:03:04:05:06"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "slla 01:02:03:04:05:06",
                "__repr__": "Icmp6NdOptionSlla(slla=MacAddress('01:02:03:04:05:06'))",
                "__bytes__": b"\x01\x01\x01\x02\x03\x04\x05\x06",
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

    def test__icmp6_nd_option_slla__len(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._icmp6_nd_option_slla),
            self._results["__len__"],
        )

    def test__icmp6_nd_option_slla__str(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._icmp6_nd_option_slla),
            self._results["__str__"],
        )

    def test__icmp6_nd_option_slla__repr(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_option_slla),
            self._results["__repr__"],
        )

    def test__icmp6_nd_option_slla__bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_option_slla),
            self._results["__bytes__"],
        )

    def test__icmp6_nd_option_slla__slla(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option 'mss' property returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_slla.slla,
            self._results["slla"],
        )
'''

'''
@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Slla option.",
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
            },
        },
        {
            "_description": "The ICMPv6 ND Slla option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\x01\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The ICMPv6 ND Slla option length integrity check (I).",
            "_args": {
                "bytes": b"\x01\x02\x01\x02\x03\x04\x05\x06",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": "Invalid ND Slla option length (I).",
            },
        },
        {
            "_description": "The ND Slla option length integrity check (II).",
            "_args": {
                "bytes": b"\x01\x01\x01\x02\x03\x04\x05",
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": "Invalid ND Slla option length (II).",
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

    def test__icmp6_nd_option_slla__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Slla option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            icmp6_nd_option_slla = Icmp6NdOptionSlla.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                icmp6_nd_option_slla,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Icmp6NdOptionSlla.from_bytes(self._args["bytes"])

            if "error_message" in self._results:
                self.assertEqual(
                    str(error.exception),
                    f"[INTEGRITY ERROR][ICMPv6] {self._results['error_message']}",
                )
'''
