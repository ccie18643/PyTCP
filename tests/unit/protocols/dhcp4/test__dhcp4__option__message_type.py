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
Module contains tests for the DHCPv4 Message Type option code.

tests/unit/protocols/dhcp4/test__dhcp4__option__message_type.py

ver 3.0.2
"""

'''
from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MIN
from pytcp.protocols.dhcp4.options.dhcp4_option import Dhcp4OptionType
from pytcp.protocols.dhcp4.options.dhcp4_option__message_type import (
    Dhcp4OptionMessageType,
)
from pytcp.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError


class TestDhcp4OptionMessageTypeAsserts(TestCase):
    """
    The DHCPv4 Message Type option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Message Type option constructor.
        """

        self._option_kwargs = {
            "message_type": Dhcp4OptionType.MESSAGE_TYPE,
        }

    def test__dhcp4__option__message_type__message_type__not_Dhcp4MessageType(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'message_type' argument is not a Dhcp4MessageType.
        """

        self._option_kwargs["message_type"] = value = "not an Dhcp4MessageType"  # type: ignore

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType(**self._option_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'message_type' field must be a Dhcp4MEssageType. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option.",
            "_args": [],
            "_kwargs": {
                "message_type": Dhcp4OptionType.MESSAGE_TYPE,
            },
            "_results": {
                "__len__": 3,
                "__str__": "message_type ",
                "__repr__": "Dhcp4OptionMessageType(wscale=14)",
                "__bytes__": b"\x03\x03\x0e",
                "wscale": 14,
            },
        },
    ]
)
class TestDhcp4OptionMessageTypeAssembler(TestCase):
    """
    The DHCPv4 Message Type option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Message Type option object with testcase arguments.
        """

        self._option = Dhcp4OptionMessageType(**self._args)

    def test__dhcp4__option__message_type__len(self) -> None:
        """
        Ensure the DHCPv4 Message Type option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__message_type__str(self) -> None:
        """
        Ensure the DHCPv4 Message Type option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__message_type__repr(self) -> None:
        """
        Ensure the DHCPv4 Message Type option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__message_type__bytes(self) -> None:
        """
        Ensure the DHCPv4 Message Type option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__message_type__wscale(self) -> None:
        """
        Ensure the DHCPv4 Message Type option 'wscale' field contains a correct value.
        """

        self.assertEqual(
            self._option.wscale,
            self._results["wscale"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option.",
            "_args": {
                "bytes": b"\x03\x03\x0e",
            },
            "_results": {
                "option": Dhcp4OptionMessageType(wscale=14),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (maximum value correction).",
            "_args": {
                "bytes": b"\x03\x03\xff",
            },
            "_results": {
                "option": Dhcp4OptionMessageType(wscale=14),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option minimum length assert.",
            "_args": {
                "bytes": b"\x03",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Message Type option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\03\x0e",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Message Type option type must be {Dhcp4OptionType.WSCALE!r}. "
                    f"Got: {Dhcp4OptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option length integrity check (I).",
            "_args": {
                "bytes": b"\x03\02\x0e",
            },
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Message Type option length must be "
                    "3 bytes. Got: 2"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option length integrity check (II).",
            "_args": {
                "bytes": b"\x03\03",
            },
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Message Type option length must "
                    "be less than or equal to the length of provided bytes "
                    "(2). Got: 3"
                ),
            },
        },
    ]
)
class TestDhcp4OptionMessageTypeParser(TestCase):
    """
    The DHCPv4 Message Type option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__message_type__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 Message Type option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionMessageType.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            )

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionMessageType.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
'''
