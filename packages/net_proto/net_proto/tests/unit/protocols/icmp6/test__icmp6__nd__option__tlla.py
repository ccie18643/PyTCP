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
Module contains tests for the ICMPv6 ND Tlla (Target Link Layer Address)
option.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__tlla.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    ICMP6__ND__OPTION__TLLA__LEN,
    Icmp6IntegrityError,
    Icmp6NdOptionTlla,
    Icmp6NdOptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIcmp6NdOptionTllaAsserts(TestCase):
    """
    The ICMPv6 ND Tlla option constructor argument assert tests.
    """

    def test__icmp6__nd__option__tlla__tlla__not_MacAddress(self) -> None:
        """
        Ensure the constructor rejects a 'tlla' argument that is not a
        MacAddress instance.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionTlla(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'tlla' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-MacAddress 'tlla'.",
        )

    def test__icmp6__nd__option__tlla__tlla__default_accepted(self) -> None:
        """
        Ensure a default-constructed MacAddress is accepted as 'tlla'.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        tlla = MacAddress()

        option = Icmp6NdOptionTlla(tlla)

        self.assertEqual(
            option.tlla,
            tlla,
            msg="Constructed option.tlla must equal the provided MacAddress().",
        )

    def test__icmp6__nd__option__tlla__tlla__populated_accepted(self) -> None:
        """
        Ensure a populated MacAddress is accepted as 'tlla'.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        tlla = MacAddress("01:02:03:04:05:06")

        option = Icmp6NdOptionTlla(tlla)

        self.assertEqual(
            option.tlla,
            tlla,
            msg="Constructed option.tlla must equal the provided MacAddress.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Tlla option carrying 01:02:03:04:05:06.",
            "_kwargs": {
                "tlla": MacAddress("01:02:03:04:05:06"),
            },
            "_results": {
                "__len__": 8,
                "__str__": "tlla 01:02:03:04:05:06",
                "__repr__": "Icmp6NdOptionTlla(tlla=MacAddress('01:02:03:04:05:06'))",
                "__bytes__": b"\x02\x01\x01\x02\x03\x04\x05\x06",
                "type": Icmp6NdOptionType.TLLA,
                "len": 8,
                "tlla": MacAddress("01:02:03:04:05:06"),
            },
        },
        {
            "_description": "ICMPv6 ND Tlla option carrying the zero MAC address.",
            "_kwargs": {
                "tlla": MacAddress(),
            },
            "_results": {
                "__len__": 8,
                "__str__": "tlla 00:00:00:00:00:00",
                "__repr__": "Icmp6NdOptionTlla(tlla=MacAddress('00:00:00:00:00:00'))",
                "__bytes__": b"\x02\x01\x00\x00\x00\x00\x00\x00",
                "type": Icmp6NdOptionType.TLLA,
                "len": 8,
                "tlla": MacAddress(),
            },
        },
    ]
)
class TestIcmp6NdOptionTllaAssembler(TestCase):
    """
    The ICMPv6 ND Tlla option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the ICMPv6 ND Tlla option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionTlla(**self._kwargs)

    def test__icmp6__nd__option__tlla__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__type(self) -> None:
        """
        Ensure the option 'type' field is Icmp6NdOptionType.TLLA.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__length(self) -> None:
        """
        Ensure the option 'len' field equals ICMP6__ND__OPTION__TLLA__LEN.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__tlla__tlla(self) -> None:
        """
        Ensure the option 'tlla' field carries the provided MacAddress.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        self.assertEqual(
            self._option.tlla,
            self._results["tlla"],
            msg=f"Unexpected 'tlla' for case: {self._description}",
        )


class TestIcmp6NdOptionTllaParser(TestCase):
    """
    The ICMPv6 ND Tlla option parser positive tests.
    """

    def test__icmp6__nd__option__tlla__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses an 8-byte Tlla option whose buffer length
        exactly matches ICMP6__ND__OPTION__TLLA__LEN.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        buffer = b"\x02\x01\x01\x02\x03\x04\x05\x06"

        self.assertEqual(
            len(buffer),
            ICMP6__ND__OPTION__TLLA__LEN,
            msg="Fixture must match ICMP6__ND__OPTION__TLLA__LEN.",
        )

        option = Icmp6NdOptionTlla.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionTlla(tlla=MacAddress("01:02:03:04:05:06")),
            msg="Parsed option must equal the reference Icmp6NdOptionTlla.",
        )

    def test__icmp6__nd__option__tlla__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Tlla option when the buffer carries
        trailing bytes past the 8-byte option payload.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        buffer = b"\x02\x01\x01\x02\x03\x04\x05\x06" + b"ZH0PA"

        option = Icmp6NdOptionTlla.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionTlla(tlla=MacAddress("01:02:03:04:05:06")),
            msg="Parsed option must equal the reference Icmp6NdOptionTlla (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Tlla option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x02"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the ICMPv6 ND Tlla option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "ICMPv6 ND Tlla option, buffer 'type' byte is not Icmp6NdOptionType.TLLA.",
            "_args": [b"\xff\x01\x01\x02\x03\x04\x05\x06"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Tlla option type must be {Icmp6NdOptionType.TLLA!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Tlla option, encoded length value (in 8-byte units) exceeds 1.",
            "_args": [b"\x02\x02\x01\x02\x03\x04\x05\x06"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Tlla option length value " "must be 8 bytes. Got: 16"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Tlla option, encoded length value exceeds available buffer bytes.",
            "_args": [b"\x02\x01\x01\x02\x03\x04\x05"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Tlla option length value "
                    "must be less than or equal to the length of provided bytes (7). Got: 8"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionTllaParserFailures(TestCase):
    """
    The ICMPv6 ND Tlla option parser failure-path tests (asserts and
    integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__tlla__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 4861 §4.6.1 (Target Link-Layer Address option).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionTlla.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
