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
Module contains tests for the ICMPv6 ND Slla (Source Link Layer Address)
option.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__slla.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    ICMP6__ND__OPTION__SLLA__LEN,
    Icmp6IntegrityError,
    Icmp6NdOptionSlla,
    Icmp6NdOptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIcmp6NdOptionSllaAsserts(TestCase):
    """
    The ICMPv6 ND Slla option constructor argument assert tests.
    """

    def test__icmp6__nd__option__slla__slla__not_MacAddress(self) -> None:
        """
        Ensure the constructor rejects a 'slla' argument that is not a
        MacAddress instance.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionSlla(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'slla' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-MacAddress 'slla'.",
        )

    def test__icmp6__nd__option__slla__slla__default_accepted(self) -> None:
        """
        Ensure a default-constructed MacAddress is accepted as 'slla'.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        slla = MacAddress()

        option = Icmp6NdOptionSlla(slla)

        self.assertEqual(
            option.slla,
            slla,
            msg="Constructed option.slla must equal the provided MacAddress().",
        )

    def test__icmp6__nd__option__slla__slla__populated_accepted(self) -> None:
        """
        Ensure a populated MacAddress is accepted as 'slla'.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        slla = MacAddress("01:02:03:04:05:06")

        option = Icmp6NdOptionSlla(slla)

        self.assertEqual(
            option.slla,
            slla,
            msg="Constructed option.slla must equal the provided MacAddress.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Slla option carrying 01:02:03:04:05:06.",
            "_kwargs": {
                "slla": MacAddress("01:02:03:04:05:06"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "slla 01:02:03:04:05:06",
                "__repr__": "Icmp6NdOptionSlla(slla=MacAddress('01:02:03:04:05:06'))",
                "__bytes__": b"\x01\x01\x01\x02\x03\x04\x05\x06",
                "type": Icmp6NdOptionType.SLLA,
                "len": 8,
                "slla": MacAddress("01:02:03:04:05:06"),
            },
        },
        {
            "_description": "ICMPv6 ND Slla option carrying the zero MAC address.",
            "_kwargs": {
                "slla": MacAddress(),
            },
            "_results": {
                "__len__": 8,
                "__str__": "slla 00:00:00:00:00:00",
                "__repr__": "Icmp6NdOptionSlla(slla=MacAddress('00:00:00:00:00:00'))",
                "__bytes__": b"\x01\x01\x00\x00\x00\x00\x00\x00",
                "type": Icmp6NdOptionType.SLLA,
                "len": 8,
                "slla": MacAddress(),
            },
        },
    ]
)
class TestIcmp6NdOptionSllaAssembler(TestCase):
    """
    The ICMPv6 ND Slla option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the ICMPv6 ND Slla option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionSlla(**self._kwargs)

    def test__icmp6__nd__option__slla__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__type(self) -> None:
        """
        Ensure the option 'type' field is Icmp6NdOptionType.SLLA.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__length(self) -> None:
        """
        Ensure the option 'len' field equals ICMP6__ND__OPTION__SLLA__LEN.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__slla__slla(self) -> None:
        """
        Ensure the option 'slla' field carries the provided MacAddress.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        self.assertEqual(
            self._option.slla,
            self._results["slla"],
            msg=f"Unexpected 'slla' for case: {self._description}",
        )


class TestIcmp6NdOptionSllaParser(TestCase):
    """
    The ICMPv6 ND Slla option parser positive tests.
    """

    def test__icmp6__nd__option__slla__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses an 8-byte Slla option whose buffer length
        exactly matches ICMP6__ND__OPTION__SLLA__LEN.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        buffer = b"\x01\x01\x01\x02\x03\x04\x05\x06"

        self.assertEqual(
            len(buffer),
            ICMP6__ND__OPTION__SLLA__LEN,
            msg="Fixture must match ICMP6__ND__OPTION__SLLA__LEN.",
        )

        option = Icmp6NdOptionSlla.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionSlla(slla=MacAddress("01:02:03:04:05:06")),
            msg="Parsed option must equal the reference Icmp6NdOptionSlla.",
        )

    def test__icmp6__nd__option__slla__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an Slla option when the buffer carries
        trailing bytes past the 8-byte option payload.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        buffer = b"\x01\x01\x01\x02\x03\x04\x05\x06" + b"ZH0PA"

        option = Icmp6NdOptionSlla.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionSlla(slla=MacAddress("01:02:03:04:05:06")),
            msg="Parsed option must equal the reference Icmp6NdOptionSlla (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Slla option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x01"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the ICMPv6 ND Slla option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "ICMPv6 ND Slla option, buffer 'type' byte is not Icmp6NdOptionType.SLLA.",
            "_args": [b"\xff\x01\x01\x02\x03\x04\x05\x06"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Slla option type must be {Icmp6NdOptionType.SLLA!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Slla option, encoded length value (in 8-byte units) exceeds 1.",
            "_args": [b"\x01\x02\x01\x02\x03\x04\x05\x06"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Slla option length value " "must be 8 bytes. Got: 16"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Slla option, encoded length value exceeds available buffer bytes.",
            "_args": [b"\x01\x01\x01\x02\x03\x04\x05"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Slla option length value "
                    "must be less than or equal to the length of provided bytes (7). Got: 8"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionSllaParserFailures(TestCase):
    """
    The ICMPv6 ND Slla option parser failure-path tests (asserts and
    integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__slla__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionSlla.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
