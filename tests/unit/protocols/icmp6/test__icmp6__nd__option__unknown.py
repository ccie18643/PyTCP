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
This module contains tests for the unknown ICMPv6 ND option code.

tests/unit/protocols/icmp6/test__icmp6__nd__option__unknown.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MAX, UINT_8__MIN
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    ICMP6__ND_OPTION__LEN,
    Icmp6NdOptionType,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__unknown import (
    Icmp6NdOptionUnknown,
)


class TestIcmp6NdOptionUnknownAsserts(TestCase):
    """
    The unknown ICMPv6 ND option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND unknown option constructor.
        """

        self._option_args = {
            "type": Icmp6NdOptionType.from_int(255),
            "len": 8,
            "data": b"012345",
        }

    def test__icmp6__nd__option__unknown__type__not_Icmp6NdOptionType(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the provided 'type' argument is not an Icmp6NdOptionType.
        """

        self._option_args["type"] = value = "not an Icmp6NdOptionType"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp6NdOptionType. Got: {type(value)!r}",
        )

    def test__icmp6__nd__option__unknown__type__known_value(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the provided 'type' argument is a known Icmp6NdOptionType.
        """

        for type in Icmp6NdOptionType.get_known_values():
            self._option_args["type"] = value = Icmp6NdOptionType(type)

            with self.assertRaises(AssertionError) as error:
                Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

            self.assertEqual(
                str(error.exception),
                "The 'type' field must not be a known Icmp6NdOptionType. "
                f"Got: {value!r}",
            )

    def test__icmp6__nd__option__unknown__len__under_min(self) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the provided 'len' argument is lower than the minimum supported value.
        """

        self._option_args["len"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__icmp6__nd__option__unknown__len__over_max(self) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the provided 'len' argument is higher than the maximum supported value.
        """

        self._option_args["len"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__tcp__assembler__hlen__not_8_bytes_alligned(self) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the value of the 'len' field is not 8 bytes aligned.
        """

        self._option_args["len"] = value = UINT_8__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be 8-byte aligned. Got: {value!r}",
        )

    def test__icmp6__nd__option__unknown__len__mismatch(self) -> None:
        """
        Ensure the ICMPv6 ND unknown option constructor raises an exception when
        the provided 'len' argument is different than the length of the 'data'
        field.
        """

        self._option_args["len"] = value = (
            ICMP6__ND_OPTION__LEN + len(self._option_args["data"]) + 8  # type: ignore
        )

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            (
                "The 'len' field must reflect the length of the 'data' field. "
                f"Got: {value} != {ICMP6__ND_OPTION__LEN + len(self._option_args['data'])}"  # type: ignore
            ),
        )


@parameterized_class(
    [
        {
            "_description": "The unknown ICMPv6 ND option.",
            "_args": {
                "type": Icmp6NdOptionType.from_int(255),
                "len": 16,
                "data": b"0123456789ABCD",
            },
            "_results": {
                "__len__": 16,
                "__str__": "unk-255-16",
                "__repr__": (
                    f"Icmp6NdOptionUnknown(type={Icmp6NdOptionType.from_int(255)!r}, "
                    "len=16, data=b'0123456789ABCD')"
                ),
                "__bytes__": (
                    b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                ),
                "type": Icmp6NdOptionType.from_int(255),
                "len": 16,
                "data": b"0123456789ABCD",
            },
        },
    ]
)
class TestIcmp6NdOptionUnknownAssembler(TestCase):
    """
    The unknown ICMPv6 ND option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the unknown ICMPv6 ND option object with testcase arguments.
        """

        self._icmp6_nd_option_unknown = Icmp6NdOptionUnknown(**self._args)

    def test__icmp6__nd__option__unknown__len(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._icmp6_nd_option_unknown),
            self._results["__len__"],
        )

    def test__icmp6__nd__option__unknown__str(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._icmp6_nd_option_unknown),
            self._results["__str__"],
        )

    def test__icmp6__nd__option__unknown__repr(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._icmp6_nd_option_unknown),
            self._results["__repr__"],
        )

    def test__icmp6__nd__option__unknown__bytes(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._icmp6_nd_option_unknown),
            self._results["__bytes__"],
        )

    def test__icmp6__nd__option__unknown__type(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option 'type' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_unknown.type,
            self._results["type"],
        )

    def test__icmp6__nd__option__unknown__length(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option 'len' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_unknown.len,
            self._results["len"],
        )

    def test__icmp6__nd__option__unknown__data(self) -> None:
        """
        Ensure the unknown ICMPv6 ND option 'data' field returns a correct value.
        """

        self.assertEqual(
            self._icmp6_nd_option_unknown.data,
            self._results["data"],
        )


@parameterized_class(
    [
        {
            "_description": "The unknown ICMPv6 ND option.",
            "_args": {
                "bytes": (
                    b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                ),
            },
            "_results": {
                "option": Icmp6NdOptionUnknown(
                    type=Icmp6NdOptionType.from_int(255),
                    len=16,
                    data=b"0123456789ABCD",
                ),
            },
        },
        {
            "_description": "The unknown ICMPv6 ND option minimum length assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the unknown ICMPv6 ND option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The unknown ICMPv6 option incorrect 'type' field (1) assert.",
            "_args": {
                "bytes": (
                    b"\x01\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown ICMPv6 ND option type must not be known. "
                    f"Got: {Icmp6NdOptionType.SLLA!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (2) assert.",
            "_args": {
                "bytes": (
                    b"\x02\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown ICMPv6 ND option type must not be known. "
                    f"Got: {Icmp6NdOptionType.TLLA!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (3) assert.",
            "_args": {
                "bytes": (
                    b"\x03\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown ICMPv6 ND option type must not be known. "
                    f"Got: {Icmp6NdOptionType.PI!r}"
                ),
            },
        },
        {
            "_description": "The unknown ICMPv4 ND option length integrity check (II).",
            "_args": {
                "bytes": (
                    b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43"
                ),
            },
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The unknown ICMPv6 ND option length "
                    "must be less than or equal to the length of provided bytes "
                    "(15). Got: 16"
                ),
            },
        },
    ]
)
class TestIcmp4NdOptionUnknownParser(TestCase):
    """
    The unknown TCP option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__unknown__from_bytes(self) -> None:
        """
        Ensure the unknown ICMPv4 ND option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            icmp6_nd_option_unknown = Icmp6NdOptionUnknown.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                icmp6_nd_option_unknown,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Icmp6NdOptionUnknown.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
