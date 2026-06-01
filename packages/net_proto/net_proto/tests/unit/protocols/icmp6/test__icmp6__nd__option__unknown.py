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
Module contains tests for the unknown ICMPv6 ND option.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__unknown.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    ICMP6__ND__OPTION__LEN,
    UINT_8__MAX,
    Icmp6IntegrityError,
    Icmp6NdOptionType,
    Icmp6NdOptionUnknown,
)


class TestIcmp6NdOptionUnknownAsserts(TestCase):
    """
    The unknown ICMPv6 ND option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default kwargs for the unknown ICMPv6 ND option
        constructor.
        """

        self._kwargs: dict[str, Any] = {
            "type": Icmp6NdOptionType.from_int(255),
            "data": b"012345",
        }

    def test__icmp6__nd__option__unknown__type__not_Icmp6NdOptionType(self) -> None:
        """
        Ensure the constructor rejects a 'type' argument that is not an
        Icmp6NdOptionType instance.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        value = "not an Icmp6NdOptionType"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**{**self._kwargs, "type": value})

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp6NdOptionType. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdOptionType 'type'.",
        )

    def test__icmp6__nd__option__unknown__type__known_value_rejected(self) -> None:
        """
        Ensure the constructor rejects a 'type' argument that is a known
        Icmp6NdOptionType (SLLA/TLLA/PI), as those have dedicated classes.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        for known_type in Icmp6NdOptionType.get_known_values():
            with self.subTest(type=known_type):
                value = Icmp6NdOptionType(known_type)

                with self.assertRaises(AssertionError) as error:
                    Icmp6NdOptionUnknown(**{**self._kwargs, "type": value})

                self.assertEqual(
                    str(error.exception),
                    f"The 'type' field must not be a known Icmp6NdOptionType. Got: {value!r}",
                    msg=f"Unexpected assertion message for known 'type'={value!r}.",
                )

    def test__icmp6__nd__option__unknown__type__unknown_value_accepted(self) -> None:
        """
        Ensure an Icmp6NdOptionType value that is not known (e.g. 255) is
        accepted as 'type'.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        type_ = Icmp6NdOptionType.from_int(255)

        option = Icmp6NdOptionUnknown(**{**self._kwargs, "type": type_})

        self.assertEqual(
            option.type,
            type_,
            msg="Constructed option.type must equal the provided Icmp6NdOptionType.",
        )

    def test__icmp6__nd__option__unknown__len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' payload that pushes 'len'
        past the 8-bit unsigned maximum.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**{**self._kwargs, "data": b"X" * (UINT_8__MAX - ICMP6__ND__OPTION__LEN + 1)})

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {UINT_8__MAX + 1}",
            msg="Unexpected assertion message for 'len' above UINT_8__MAX.",
        )

    def test__icmp6__nd__option__unknown__len__not_8_byte_aligned(self) -> None:
        """
        Ensure the constructor rejects a 'data' payload whose length leaves
        the computed 'len' field not 8-byte aligned.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionUnknown(**{**self._kwargs, "data": b"X" * 7})

        self.assertEqual(
            str(error.exception),
            "The 'len' field must be 8-byte aligned. Got: 9",
            msg="Unexpected assertion message for non-aligned 'len'.",
        )

    def test__icmp6__nd__option__unknown__data__empty_accepted(self) -> None:
        """
        Ensure an empty-except-for-padding 'data' payload that produces an
        8-byte-aligned 'len' is accepted.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        option = Icmp6NdOptionUnknown(**{**self._kwargs, "data": b"\x00" * (8 - ICMP6__ND__OPTION__LEN)})

        self.assertEqual(
            option.len,
            8,
            msg="Constructed option.len must equal 8 for the minimum aligned payload.",
        )


@parameterized_class(
    [
        {
            "_description": "Unknown ICMPv6 ND option, type=255 with 14-byte data payload.",
            "_kwargs": {
                "type": Icmp6NdOptionType.from_int(255),
                "data": b"0123456789ABCD",
            },
            "_results": {
                "__len__": 16,
                "__str__": "unk-255-16",
                "__repr__": (
                    f"Icmp6NdOptionUnknown(type={Icmp6NdOptionType.from_int(255)!r}, " "len=16, data=b'0123456789ABCD')"
                ),
                "__bytes__": b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44",
                "type": Icmp6NdOptionType.from_int(255),
                "len": 16,
                "data": b"0123456789ABCD",
            },
        },
        {
            "_description": "Unknown ICMPv6 ND option, type=254 with 6-byte data payload.",
            "_kwargs": {
                "type": Icmp6NdOptionType.from_int(254),
                "data": b"012345",
            },
            "_results": {
                "__len__": 8,
                "__str__": "unk-254-8",
                "__repr__": (
                    f"Icmp6NdOptionUnknown(type={Icmp6NdOptionType.from_int(254)!r}, " "len=8, data=b'012345')"
                ),
                "__bytes__": b"\xfe\x01\x30\x31\x32\x33\x34\x35",
                "type": Icmp6NdOptionType.from_int(254),
                "len": 8,
                "data": b"012345",
            },
        },
    ]
)
class TestIcmp6NdOptionUnknownAssembler(TestCase):
    """
    The unknown ICMPv6 ND option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the unknown ICMPv6 ND option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionUnknown(**self._kwargs)

    def test__icmp6__nd__option__unknown__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__type(self) -> None:
        """
        Ensure the option 'type' field carries the provided
        Icmp6NdOptionType.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__length(self) -> None:
        """
        Ensure the option 'len' field equals ICMP6__ND__OPTION__LEN +
        len(data) (already validated as 8-byte aligned).

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__unknown__data(self) -> None:
        """
        Ensure the option 'data' field carries the provided bytes payload.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )


class TestIcmp6NdOptionUnknownParser(TestCase):
    """
    The unknown ICMPv6 ND option parser positive tests.
    """

    def test__icmp6__nd__option__unknown__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses an unknown option whose buffer length
        exactly matches the encoded option length.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        buffer = b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"

        option = Icmp6NdOptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionUnknown(
                type=Icmp6NdOptionType.from_int(255),
                data=b"0123456789ABCD",
            ),
            msg="Parsed option must equal the reference Icmp6NdOptionUnknown.",
        )

    def test__icmp6__nd__option__unknown__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an unknown option when the buffer
        carries trailing bytes past the declared option length.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        buffer = b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" + b"ZH0PA"

        option = Icmp6NdOptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionUnknown(
                type=Icmp6NdOptionType.from_int(255),
                data=b"0123456789ABCD",
            ),
            msg="Parsed option must equal the reference Icmp6NdOptionUnknown (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "Unknown ICMPv6 ND option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the unknown ICMPv6 ND option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "Unknown ICMPv6 ND option, buffer 'type' byte is Icmp6NdOptionType.SLLA (known).",
            "_args": [b"\x01\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The unknown ICMPv6 ND option type must not be known. Got: {Icmp6NdOptionType.SLLA!r}"
                ),
            },
        },
        {
            "_description": "Unknown ICMPv6 ND option, buffer 'type' byte is Icmp6NdOptionType.TLLA (known).",
            "_args": [b"\x02\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The unknown ICMPv6 ND option type must not be known. Got: {Icmp6NdOptionType.TLLA!r}"
                ),
            },
        },
        {
            "_description": "Unknown ICMPv6 ND option, buffer 'type' byte is Icmp6NdOptionType.PI (known).",
            "_args": [b"\x03\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown ICMPv6 ND option type must not be known. Got: {Icmp6NdOptionType.PI!r}",
            },
        },
        {
            "_description": "Unknown ICMPv6 ND option, encoded length value exceeds available buffer bytes.",
            "_args": [b"\xff\x02\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The unknown ICMPv6 ND option length value "
                    "must be less than or equal to the length of provided bytes (15). Got: 16"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionUnknownParserFailures(TestCase):
    """
    The unknown ICMPv6 ND option parser failure-path tests (asserts and
    integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__unknown__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 4861 §4.6 (ND option general format).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionUnknown.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
