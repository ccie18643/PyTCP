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
Module contains tests for the unknown IPv4 option code.

net_proto/tests/unit/protocols/ip4/test__ip4__option__unknown.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    Ip4IntegrityError,
    Ip4OptionType,
    Ip4OptionUnknown,
)
from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.ip4.options.ip4__option import IP4__OPTION__LEN
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionUnknownAsserts(TestCase):
    """
    The unknown IPv4 option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict so each test can override exactly
        one field and trigger its assert.
        """

        self._kwargs: dict[str, Any] = {
            "type": Ip4OptionType.from_int(255),
            "data": b"",
        }

    def test__ip4__option__unknown__type__not_Ip4OptionType(self) -> None:
        """
        Ensure the constructor rejects 'type' when it is not an
        Ip4OptionType instance.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self._kwargs["type"] = value = "not a Ip4OptionType"

        with self.assertRaises(AssertionError) as error:
            Ip4OptionUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Ip4OptionType. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip4OptionType 'type'.",
        )

    def test__ip4__option__unknown__type__known_value(self) -> None:
        """
        Ensure the constructor rejects every known Ip4OptionType value
        (the unknown option MUST NOT overlap with Eol or Nop).

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        for known in Ip4OptionType.get_known_values():
            with self.subTest(known=known):
                kwargs = dict(self._kwargs)
                kwargs["type"] = value = Ip4OptionType(known)

                with self.assertRaises(AssertionError) as error:
                    Ip4OptionUnknown(**kwargs)

                self.assertEqual(
                    str(error.exception),
                    f"The 'type' field must not be a known Ip4OptionType. Got: {value!r}",
                    msg=f"Unexpected assertion message for known type {value!r}.",
                )

    def test__ip4__option__unknown__len__8bit_integer(self) -> None:
        """
        Ensure the constructor rejects 'data' long enough that
        IP4__OPTION__LEN + len(data) overflows an 8-bit unsigned integer.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self._kwargs["data"] = b"X" * (UINT_8__MAX - IP4__OPTION__LEN + 1)

        with self.assertRaises(AssertionError) as error:
            Ip4OptionUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {UINT_8__MAX + 1}",
            msg="Unexpected assertion message for over-max 'len' derived from oversized 'data'.",
        )

    def test__ip4__option__unknown__len__at_max_accepted(self) -> None:
        """
        Ensure the constructor accepts 'data' whose length brings the
        derived 'len' field exactly to UINT_8__MAX (boundary case).

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self._kwargs["data"] = b"X" * (UINT_8__MAX - IP4__OPTION__LEN)

        option = Ip4OptionUnknown(**self._kwargs)

        self.assertEqual(
            option.len,
            UINT_8__MAX,
            msg="Constructed option.len must equal UINT_8__MAX at the boundary.",
        )

    def test__ip4__option__unknown__data__empty_accepted(self) -> None:
        """
        Ensure the constructor accepts an empty 'data' buffer (the
        resulting option is exactly IP4__OPTION__LEN bytes on the wire).

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        option = Ip4OptionUnknown(**self._kwargs)

        self.assertEqual(
            option.len,
            IP4__OPTION__LEN,
            msg="Constructed option.len must equal IP4__OPTION__LEN for empty 'data'.",
        )
        self.assertEqual(
            option.data,
            b"",
            msg="Constructed option.data must be empty.",
        )


@parameterized_class(
    [
        {
            "_description": "Unknown IPv4 option with type=255 and 16-byte 'data'.",
            "_kwargs": {
                "type": Ip4OptionType.from_int(255),
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-255-18",
                "__repr__": (
                    f"Ip4OptionUnknown(type={Ip4OptionType.from_int(255)!r}, " "len=18, data=b'0123456789ABCDEF')"
                ),
                # IPv4 unknown option wire format:
                #   Type:  0xff (UNKNOWN_255)
                #   Len:   0x12 (18 bytes total)
                #   Data:  b"0123456789ABCDEF" (16 bytes of ASCII)
                "__bytes__": (b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"),
                "type": Ip4OptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "Unknown IPv4 option with type=254 and empty 'data'.",
            "_kwargs": {
                "type": Ip4OptionType.from_int(254),
                "data": b"",
            },
            "_results": {
                "__len__": 2,
                "__str__": "unk-254-2",
                "__repr__": (f"Ip4OptionUnknown(type={Ip4OptionType.from_int(254)!r}, " "len=2, data=b'')"),
                # IPv4 unknown option wire format:
                #   Type:  0xfe (UNKNOWN_254)
                #   Len:   0x02 (2 bytes total; empty data)
                "__bytes__": b"\xfe\x02",
                "type": Ip4OptionType.from_int(254),
                "len": 2,
                "data": b"",
            },
        },
    ]
)
class TestIp4OptionUnknownAssembler(TestCase):
    """
    The unknown IPv4 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the unknown IPv4 option from the parametrized kwargs.
        """

        self._option = Ip4OptionUnknown(**self._kwargs)

    def test__ip4__option__unknown__len(self) -> None:
        """
        Ensure '__len__()' returns the expected wire-byte length.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip4__option__unknown__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip4__option__unknown__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip4__option__unknown__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip4__option__unknown__type(self) -> None:
        """
        Ensure the 'type' field carries the provided Ip4OptionType.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__unknown__length(self) -> None:
        """
        Ensure the 'len' field equals IP4__OPTION__LEN + len(data).

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__ip4__option__unknown__data(self) -> None:
        """
        Ensure the 'data' field carries the provided payload verbatim.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )


class TestIp4OptionUnknownParser(TestCase):
    """
    The unknown IPv4 option parser positive tests.
    """

    def test__ip4__option__unknown__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses an unknown option whose buffer length
        equals the declared 'len' byte (boundary case).

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        # IPv4 unknown option wire format (exactly 18 bytes):
        #   Type: 0xff (UNKNOWN_255)
        #   Len:  0x12 (18 bytes total)
        #   Data: b"0123456789ABCDEF" (16 bytes of ASCII)
        buffer = b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"

        option = Ip4OptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionUnknown(
                type=Ip4OptionType.from_int(255),
                data=b"0123456789ABCDEF",
            ),
            msg="Parsed option must equal the reference Ip4OptionUnknown.",
        )

    def test__ip4__option__unknown__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an unknown option when the buffer
        carries trailing bytes past the declared 'len' byte.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        # IPv4 unknown option with 5 trailing bytes that must be ignored
        # (the option is truncated to its declared 18-byte length):
        #   Type: 0xff (UNKNOWN_255)
        #   Len:  0x12 (18 bytes total)
        #   Data: b"0123456789ABCDEF" (16 bytes)
        #   Trail: b"ZH0PA"
        buffer = b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46" + b"ZH0PA"

        option = Ip4OptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionUnknown(
                type=Ip4OptionType.from_int(255),
                data=b"0123456789ABCDEF",
            ),
            msg="Parsed option must equal the reference Ip4OptionUnknown (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "Unknown IPv4 option, buffer shorter than IP4__OPTION__LEN.",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the unknown IPv4 option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "Unknown IPv4 option, buffer 'type' byte is known (Eol).",
            "_args": [
                # IPv4 unknown option parser rejection fixture:
                #   Type: 0x00 (Ip4OptionType.EOL, i.e. a KNOWN type)
                #   Len:  0x12 (18 bytes total)
                #   Data: b"0123456789ABCDEF" (16 bytes)
                b"\x00\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                b"\x45\x46",
            ],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown IPv4 option type must not be known. Got: {Ip4OptionType.EOL!r}",
            },
        },
        {
            "_description": "Unknown IPv4 option, buffer 'type' byte is known (Nop).",
            "_args": [
                # IPv4 unknown option parser rejection fixture:
                #   Type: 0x01 (Ip4OptionType.NOP, i.e. a KNOWN type)
                #   Len:  0x12 (18 bytes total)
                #   Data: b"0123456789ABCDEF" (16 bytes)
                b"\x01\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                b"\x45\x46",
            ],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown IPv4 option type must not be known. Got: {Ip4OptionType.NOP!r}",
            },
        },
        {
            "_description": "Unknown IPv4 option, declared 'len' exceeds available buffer bytes.",
            "_args": [
                # IPv4 unknown option integrity-failure fixture:
                #   Type: 0xff (UNKNOWN_255)
                #   Len:  0x12 (declared 18 bytes)
                #   Data: 15 ASCII bytes (buffer is only 17 bytes total)
                b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                b"\x45",
            ],
            "_results": {
                "error": Ip4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][IPv4] The unknown IPv4 option length value must "
                    "be less than or equal to the length of provided bytes (17). "
                    "Got: 18"
                ),
            },
        },
    ]
)
class TestIp4OptionUnknownParserFailures(TestCase):
    """
    The unknown IPv4 option parser failure-path tests (short-buffer
    assert, known-type rejection, and length-integrity error).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__ip4__option__unknown__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 791 §3.1 (IPv4 option TLV — type, length, data).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4OptionUnknown.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
