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
This module contains tests for the ICMPv6 ND Pi (Prefix Information) option
code.

tests/unit/protocols/icmp6/test__icmp6__nd__option__pi.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_32__MAX, UINT_32__MIN
from pytcp.lib.ip6_address import Ip6Network
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOptionType,
)
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
        Ensure the ICMPv6 ND Pi option constructor raises an exception when
        the provided 'flag_l' argument is not a boolean.
        """

        self._option_args["flag_l"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_l' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__flag_a__not_boolean(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when
        the provided 'flag_a' argument is not a boolean.
        """

        self._option_args["flag_a"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_a' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__flag_r__not_boolean(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when
        the provided 'flag_r' argument is not a boolean.
        """

        self._option_args["flag_r"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_r' field must be a boolean. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__under_min(self) -> None:
        """
        Ensure the  option constructor raises an exception when the provided
        'valid_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["valid_lifetime"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {value}",
        )

    def test__icmp6__nd__option__pi__valid_lifetime__over_max(self) -> None:
        """
        Ensure the  option constructor raises an exception when the provided
        'valid_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["valid_lifetime"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {value}",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__under_min(
        self,
    ) -> None:
        """
        Ensure the  option constructor raises an exception when the provided
        'preferred_lifetime' argument is lower than the minimum supported
        value.
        """

        self._option_args["preferred_lifetime"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {value}",
        )

    def test__icmp6__nd__option__pi__preferred_lifetime__over_max(self) -> None:
        """
        Ensure the  option constructor raises an exception when the provided
        'preferred_lifetime' argument is lower than the minimum supported value.
        """

        self._option_args["preferred_lifetime"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {value}",
        )

    def test__icmp6__nd__option__pi__prefix__not_Ip6Network(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option constructor raises an exception when
        the provided 'prefix' argument is not a Ip6Network.
        """

        self._option_args["prefix"] = value = "not a Ip6Network"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionPi(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'prefix' field must be an Ip6Network. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Pi option (I).",
            "_args": {
                "flag_l": True,
                "flag_a": False,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 0,
                "prefix": Ip6Network("2001:db8::/64"),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "prefix_info (prefix 2001:db8::/64, flags L-R, valid_lifetime "
                    "4294967295, preferred_lifetime 0)"
                ),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=True, flag_a=False, flag_r=True, "
                    "valid_lifetime=4294967295, preferred_lifetime=0, prefix=Ip6Network("
                    "'2001:db8::/64'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x40\xa0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "flag_l": True,
                "flag_a": False,
                "flag_r": True,
                "valid_lifetime": 4294967295,
                "preferred_lifetime": 0,
                "prefix": Ip6Network("2001:db8::/64"),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option (II).",
            "_args": {
                "flag_l": False,
                "flag_a": True,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("2007:db8::abcd/128"),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "prefix_info (prefix 2007:db8::abcd/128, flags -A-, valid_lifetime 0, "
                    "preferred_lifetime 4294967295)"
                ),
                "__repr__": (
                    "Icmp6NdOptionPi(flag_l=False, flag_a=True, flag_r=False, "
                    "valid_lifetime=0, preferred_lifetime=4294967295, prefix=Ip6Network("
                    "'2007:db8::abcd/128'))"
                ),
                "__bytes__": (
                    b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"
                ),
                "flag_l": False,
                "flag_a": True,
                "flag_r": False,
                "valid_lifetime": 0,
                "preferred_lifetime": 4294967295,
                "prefix": Ip6Network("2007:db8::abcd/128"),
            },
        },
    ]
)
class TestIcmp6NdOptionPiAssembler(TestCase):
    """
    The ICMPv6 ND Pi option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 ND Pi option object with testcase arguments.
        """

        self._icmp6_nd_option_pi = Icmp6NdOptionPi(**self._args)

    def test__icmp6__nd__option__pi__len(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._icmp6_nd_option_pi),
            self._results["__len__"],
        )

    def test__icmp6__nd__option__pi__str(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._icmp6_nd_option_pi),
            self._results["__str__"],
        )

    def test__icmp6__nd__option__pi__repr(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_option_pi),
            self._results["__repr__"],
        )

    def test__icmp6__nd__option__pi__bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_option_pi),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__option__pi__flag_l(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'flag_l' field returns a correct
        value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.flag_l,
            self._results["flag_l"],
        )

    def test__icmp6__nd__option__pi__flag_a(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'flag_a' field returns a correct
        value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.flag_a,
            self._results["flag_a"],
        )

    def test__icmp6__nd__option__pi__flag_r(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'flag_r' field returns a correct
        value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.flag_r,
            self._results["flag_r"],
        )

    def test__icmp6__nd__option__pi__valid_lifetime(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'valid_lifetime' field returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.valid_lifetime,
            self._results["valid_lifetime"],
        )

    def test__icmp6__nd__option__pi__preferred_lifetime(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'preferred_lifetime' field returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.preferred_lifetime,
            self._results["preferred_lifetime"],
        )

    def test__icmp6__nd__option__pi__prefix(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option 'prefix' field returns a correct
        value.
        """

        self.assertEqual(
            self._icmp6_nd_option_pi.prefix,
            self._results["prefix"],
        )


@parameterized_class(
    [
        {
            "_description": "The ICMPv6 ND Pi option .",
            "_args": {
                "bytes": (
                    b"\x03\x04\x40\xa0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
            },
            "_results": {
                "option": Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=False,
                    flag_r=True,
                    valid_lifetime=4294967295,
                    preferred_lifetime=0,
                    prefix=Ip6Network("2001:db8::/64"),
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option (I).",
            "_args": {
                "bytes": (
                    b"\x03\x04\x40\xa0\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
            },
            "_results": {
                "option": Icmp6NdOptionPi(
                    flag_l=True,
                    flag_a=False,
                    flag_r=True,
                    valid_lifetime=4294967295,
                    preferred_lifetime=0,
                    prefix=Ip6Network("2001:db8::/64"),
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option (II).",
            "_args": {
                "bytes": (
                    b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"
                ),
            },
            "_results": {
                "option": Icmp6NdOptionPi(
                    flag_l=False,
                    flag_a=True,
                    flag_r=False,
                    valid_lifetime=0,
                    preferred_lifetime=4294967295,
                    prefix=Ip6Network("2007:db8::abcd/128"),
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option minimum length assert.",
            "_args": {
                "bytes": b"\x03",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the ICMPv6 ND Pi option must be 2 bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option incorrect 'type' field assert.",
            "_args": {
                "bytes": (
                    b"\xff\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Pi option type must be {Icmp6NdOptionType.PI!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option length integrity check (I).",
            "_args": {
                "bytes": (
                    b"\x03\x05\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab\xcd"
                ),
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Pi option length must be "
                    "32 bytes. Got: 40"
                ),
            },
        },
        {
            "_description": "The ICMPv6 ND Pi option length integrity check (II).",
            "_args": {
                "bytes": (
                    b"\x03\x04\x80\x40\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00"
                    b"\x20\x07\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xab"
                ),
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Pi option length must be "
                    "less than or equal to the length of provided bytes (31). Got: 32"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionPiParser(TestCase):
    """
    The ICMPv6 ND Pi option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__pi__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Pi option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            icmp6_nd_option_pi = Icmp6NdOptionPi.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            )

            self.assertEqual(
                icmp6_nd_option_pi,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Icmp6NdOptionPi.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
