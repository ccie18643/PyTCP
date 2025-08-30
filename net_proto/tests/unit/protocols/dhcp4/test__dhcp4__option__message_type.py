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

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__message_type.py

ver 3.0.4
"""


from typing import Any

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4MessageType,
    Dhcp4OptionMessageType,
    Dhcp4OptionType,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


class TestDhcp4OptionMessageTypeAsserts(TestCase):
    """
    The DHCPv4 Message Type option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Message Type option constructor.
        """

        self._args: list[Any] = [Dhcp4MessageType.DISCOVER]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__message_type__message_type__not_Dhcp4MessageType(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'message_type' argument is not a Dhcp4MessageType.
        """

        self._args[0] = value = "not an Dhcp4MessageType"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'message_type' field must be a Dhcp4MessageType. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option (discover).",
            "_args": [Dhcp4MessageType.DISCOVER],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Discover",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.DISCOVER: 1>)"
                ),
                "__bytes__": b"\x35\x03\x01",
                "message_type": Dhcp4MessageType.DISCOVER,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (offer).",
            "_args": [Dhcp4MessageType.OFFER],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Offer",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.OFFER: 2>)"
                ),
                "__bytes__": b"\x35\x03\x02",
                "message_type": Dhcp4MessageType.OFFER,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (request).",
            "_args": [Dhcp4MessageType.REQUEST],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Request",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.REQUEST: 3>)"
                ),
                "__bytes__": b"\x35\x03\x03",
                "message_type": Dhcp4MessageType.REQUEST,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (decline).",
            "_args": [Dhcp4MessageType.DECLINE],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Decline",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.DECLINE: 4>)"
                ),
                "__bytes__": b"\x35\x03\x04",
                "message_type": Dhcp4MessageType.DECLINE,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (ack).",
            "_args": [Dhcp4MessageType.ACK],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Ack",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.ACK: 5>)"
                ),
                "__bytes__": b"\x35\x03\x05",
                "message_type": Dhcp4MessageType.ACK,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (nak).",
            "_args": [Dhcp4MessageType.NAK],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Nak",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.NAK: 6>)"
                ),
                "__bytes__": b"\x35\x03\x06",
                "message_type": Dhcp4MessageType.NAK,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (release).",
            "_args": [Dhcp4MessageType.RELEASE],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Release",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.RELEASE: 7>)"
                ),
                "__bytes__": b"\x35\x03\x07",
                "message_type": Dhcp4MessageType.RELEASE,
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (inform).",
            "_args": [Dhcp4MessageType.INFORM],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "message_type Inform",
                "__repr__": (
                    "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.INFORM: 8>)"
                ),
                "__bytes__": b"\x35\x03\x08",
                "message_type": Dhcp4MessageType.INFORM,
            },
        },
    ]
)
class TestDhcp4OptionMessageTypeAssembler(TestCase):
    """
    The DHCPv4 Message Type option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Message Type option object with testcase arguments.
        """

        self._option = Dhcp4OptionMessageType(*self._args, **self._kwargs)

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

    def test__dhcp4__option__message_type__mesage_type(self) -> None:
        """
        Ensure the DHCPv4 Message Type option 'message_type' field contains a correct
        value.
        """

        self.assertEqual(
            self._option.message_type,
            self._results["message_type"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option (discover).",
            "_args": [b"\x35\x03\x01" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.DISCOVER
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (offer).",
            "_args": [b"\x35\x03\x02" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.OFFER
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (request).",
            "_args": [b"\x35\x03\x03" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.REQUEST
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (decline).",
            "_args": [b"\x35\x03\x04" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.DECLINE
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (ack).",
            "_args": [b"\x35\x03\x05" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.ACK
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (nak).",
            "_args": [b"\x35\x03\x06" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.NAK
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (release).",
            "_args": [b"\x35\x03\x07" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.RELEASE
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option (inform).",
            "_args": [b"\x35\x03\x08" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionMessageType(
                    message_type=Dhcp4MessageType.INFORM
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option minimum length assert.",
            "_args": [b"\x35"],
            "_kwargs": {},
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
            "_args": [b"\xfe\03\x01"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Message Type option type must be {Dhcp4OptionType.MESSAGE_TYPE!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Message Type option length integrity check (I).",
            "_args": [b"\x35\02\x01"],
            "_kwargs": {},
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
            "_args": [b"\x35\03"],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Message Type option length must "
                    "be less than or equal to the length of provided bytes (2). Got: 3"
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
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__message_type__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 Message Type option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionMessageType.from_bytes(
                *self._args, **self._kwargs
            )

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionMessageType.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
