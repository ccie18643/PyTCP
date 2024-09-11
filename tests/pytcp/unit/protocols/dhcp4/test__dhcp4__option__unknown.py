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
Module contains tests for the unknown DHCPv4 option code.

tests/pytcp/unit/protocols/dhcp4/test__dhcp4__option__unknown.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MAX, UINT_8__MIN
from pytcp.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from pytcp.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4OptionType,
)
from pytcp.protocols.dhcp4.options.dhcp4_option__unknown import (
    Dhcp4OptionUnknown,
)


class TestDhcp4OptionUnknownAsserts(TestCase):
    """
    The unknown DHCPv4 option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 unknown option constructor.
        """

        self._option_args = {
            "type": Dhcp4OptionType.from_int(254),
            "len": 8,
            "data": b"012345",
        }

    def test__dhcp4__option__unknown__type__not_Dhcp4OptionType(self) -> None:
        """
        Ensure the DHCPv4 unknown option constructor raises an exception
        when the provided 'type' argument is not a Dhcp4OptionType.
        """

        self._option_args["type"] = value = "not a Dhcp4OptionType"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Dhcp4OptionType. Got: {type(value)!r}",
        )

    def test__dhcp4__option__unknown__type__core_value(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 unknown option constructor raises an exception
        when the provided 'type' argument is a core Dhcp4OptionType.
        """

        for type in Dhcp4OptionType.get_known_values():
            self._option_args["type"] = value = Dhcp4OptionType(type)

            with self.assertRaises(AssertionError) as error:
                Dhcp4OptionUnknown(**self._option_args)  # type: ignore

            self.assertEqual(
                str(error.exception),
                "The 'type' field must not be a core Dhcp4OptionType. "
                f"Got: {value!r}",
            )

    def test__dhcp4__option__unknown__len__under_min(self) -> None:
        """
        Ensure the DHCPv4 unknown option constructor raises an exception
        when the provided 'len' argument is lower than the minimum supported
        value.
        """

        self._option_args["len"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__dhcp4__option__unknown__len__over_max(self) -> None:
        """
        Ensure the DHCPv4 unknown option constructor raises an exception
        when the provided 'len' argument is higher than the maximum supported
        value.
        """

        self._option_args["len"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__dhcp4__option__unknown__len__mismatch(self) -> None:
        """
        Ensure the DHCPv4 unknown option constructor raises an exception
        when the provided 'len' argument is different than the length of the
        'data' field.
        """

        self._option_args["len"] = value = (
            DHCP4__OPTION__LEN + len(self._option_args["data"]) + 1  # type: ignore
        )

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            (
                "The 'len' field must reflect the length of the 'data' field. "
                f"Got: {value} != {DHCP4__OPTION__LEN + len(self._option_args['data'])}"  # type: ignore
            ),
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv4 option.",
            "_args": {
                "type": Dhcp4OptionType.from_int(254),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-254-18",
                "__repr__": (
                    f"Dhcp4OptionUnknown(type={Dhcp4OptionType.from_int(254)!r}, "
                    "len=18, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xfe\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
                "type": Dhcp4OptionType.from_int(254),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestDhcp4OptionUnknownAssembler(TestCase):
    """
    The unknown DHCPv4 option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the unknown DHCPv4 option object with testcase arguments.
        """

        self._option = Dhcp4OptionUnknown(**self._args)

    def test__dhcp4__option__unknown__len(self) -> None:
        """
        Ensure the unknown DHCPv4 option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__unknown__str(self) -> None:
        """
        Ensure the unknown DHCPv4 option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__unknown__repr(self) -> None:
        """
        Ensure the unknown DHCPv4 option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__unknown__bytes(self) -> None:
        """
        Ensure the unknown DHCPv4 option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__unknown__type(self) -> None:
        """
        Ensure the unknown DHCPv4 option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__dhcp4__option__unknown__length(self) -> None:
        """
        Ensure the unknown DHCPv4 option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )

    def test__dhcp4__option__unknown__data(self) -> None:
        """
        Ensure the unknown DHCPv4 option 'data' field contains a correct value.
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv4 option.",
            "_args": {
                "bytes": (
                    b"\xfe\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "option": Dhcp4OptionUnknown(
                    type=Dhcp4OptionType.from_int(254),
                    len=18,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option minimum length assert.",
            "_args": {
                "bytes": b"\xfe",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the unknown DHCPv4 option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option incorrect 'type' field (End) assert.",
            "_args": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown DHCPv4 option type must not be known. "
                    "Got: <Dhcp4OptionType.END: 255>"
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option incorrect 'type' field (Pad) assert.",
            "_args": {
                "bytes": (
                    b"\x00\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown DHCPv4 option type must not be known. "
                    f"Got: {Dhcp4OptionType.PAD!r}"
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option length integrity check (II).",
            "_args": {
                "bytes": (
                    b"\xfe\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45"
                ),
            },
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The unknown DHCPv4 option length must be "
                    "less than or equal to the length of provided bytes (17). Got: 18"
                ),
            },
        },
    ]
)
class TestDhcp4OptionUnknownParser(TestCase):
    """
    The unknown DHCPv4 option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__unknown__from_bytes(self) -> None:
        """
        Ensure the unknown DHCPv4 option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionUnknown.from_bytes(self._args["bytes"])

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionUnknown.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
