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
Module contains tests for the ICMPv6 ND Redirected Header option (RFC 4861 §4.6.3).

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__redirected_header.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN,
    Icmp6IntegrityError,
    Icmp6NdOptionRedirectedHeader,
    Icmp6NdOptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIcmp6NdOptionRedirectedHeaderAsserts(TestCase):
    """
    The ICMPv6 ND Redirected Header option constructor argument
    assert tests.
    """

    def test__icmp6__nd__option__redirected_header__data__not_bytes(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument that is
        not a bytes instance.

        Reference: RFC 4861 §4.6.3 (Redirected Header option).
        """

        value = "not bytes"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRedirectedHeader(data=value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be bytes. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-bytes 'data'.",
        )

    def test__icmp6__nd__option__redirected_header__data__not_8_byte_aligned(self) -> None:
        """
        Ensure the constructor rejects a 'data' length that does
        not produce an 8-byte aligned total option size — every
        ND option MUST be 8-byte aligned per the generic option
        format.

        Reference: RFC 4861 §4.6 (ND option 8-byte alignment).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdOptionRedirectedHeader(data=b"\x00\x01\x02")

        self.assertIn(
            "8-byte aligned",
            str(error.exception),
            msg="Rejection must call out the 8-byte alignment requirement.",
        )

    def test__icmp6__nd__option__redirected_header__data__empty_accepted(self) -> None:
        """
        Ensure an empty 'data' (zero-length carried packet) is
        accepted — option total length 8 = aligned.

        Reference: RFC 4861 §4.6.3 (Redirected Header option, IP header + data may be empty).
        """

        option = Icmp6NdOptionRedirectedHeader(data=b"")

        self.assertEqual(
            option.len,
            ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN,
            msg="Empty-data option must have len == 8.",
        )

    def test__icmp6__nd__option__redirected_header__data__multiple_of_8_accepted(self) -> None:
        """
        Ensure a 'data' length that is a multiple of 8 is
        accepted — total option size remains 8-byte aligned.

        Reference: RFC 4861 §4.6 (ND option 8-byte alignment).
        """

        data = bytes(range(16))
        option = Icmp6NdOptionRedirectedHeader(data=data)

        self.assertEqual(
            option.len,
            ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN + len(data),
            msg="Option len must equal fixed-portion length plus data length.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Redirected Header option carrying empty data.",
            "_kwargs": {
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "redirected-header 0B",
                "__repr__": "Icmp6NdOptionRedirectedHeader(len=8, data=b'')",
                "__bytes__": b"\x04\x01\x00\x00\x00\x00\x00\x00",
                "type": Icmp6NdOptionType.REDIRECTED_HEADER,
                "len": 8,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 ND Redirected Header option carrying 8 bytes of data.",
            "_kwargs": {
                "data": b"\x60\x00\x00\x00\x00\x10\x06\x40",
            },
            "_results": {
                "__len__": 16,
                "__str__": "redirected-header 8B",
                "__repr__": ("Icmp6NdOptionRedirectedHeader(len=16, " "data=b'`\\x00\\x00\\x00\\x00\\x10\\x06@')"),
                "__bytes__": (b"\x04\x02\x00\x00\x00\x00\x00\x00" b"\x60\x00\x00\x00\x00\x10\x06\x40"),
                "type": Icmp6NdOptionType.REDIRECTED_HEADER,
                "len": 16,
                "data": b"\x60\x00\x00\x00\x00\x10\x06\x40",
            },
        },
        {
            "_description": "ICMPv6 ND Redirected Header option carrying 16 bytes of data.",
            "_kwargs": {
                "data": bytes(range(16)),
            },
            "_results": {
                "__len__": 24,
                "__str__": "redirected-header 16B",
                "__repr__": (
                    "Icmp6NdOptionRedirectedHeader(len=24, "
                    "data=b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"
                    "\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f')"
                ),
                "__bytes__": (b"\x04\x03\x00\x00\x00\x00\x00\x00" + bytes(range(16))),
                "type": Icmp6NdOptionType.REDIRECTED_HEADER,
                "len": 24,
                "data": bytes(range(16)),
            },
        },
    ]
)
class TestIcmp6NdOptionRedirectedHeaderAssembler(TestCase):
    """
    The ICMPv6 ND Redirected Header option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from the parametrized kwargs.
        """

        self._option = Icmp6NdOptionRedirectedHeader(**self._kwargs)

    def test__icmp6__nd__option__redirected_header__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.6.3 (Redirected Header option size).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__bytes(self) -> None:
        """
        Ensure '__bytes__()' produces the expected wire bytes —
        type=4, length-in-8-octet-units, six reserved zero bytes,
        then the carried IP packet verbatim.

        Reference: RFC 4861 §4.6.3 (Redirected Header wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__type(self) -> None:
        """
        Ensure the option 'type' field is REDIRECTED_HEADER (4).

        Reference: RFC 4861 §4.6.3 (Type = 4).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__length(self) -> None:
        """
        Ensure the option 'len' field equals fixed-portion-length
        plus data length, in bytes (the wire encoding divides by 8).

        Reference: RFC 4861 §4.6 (Length in 8-octet units).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__icmp6__nd__option__redirected_header__data(self) -> None:
        """
        Ensure the option 'data' field carries the provided bytes
        verbatim.

        Reference: RFC 4861 §4.6.3 (IP header + data).
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )


class TestIcmp6NdOptionRedirectedHeaderParser(TestCase):
    """
    The ICMPv6 ND Redirected Header option parser positive tests.
    """

    def test__icmp6__nd__option__redirected_header__from_buffer__minimum(self) -> None:
        """
        Ensure 'from_buffer' parses a minimal (empty-data, length=8)
        option correctly.

        Reference: RFC 4861 §4.6.3 (Redirected Header wire format).
        """

        buffer = b"\x04\x01\x00\x00\x00\x00\x00\x00"

        option = Icmp6NdOptionRedirectedHeader.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionRedirectedHeader(data=b""),
            msg="Parsed minimal option must equal the reference.",
        )

    def test__icmp6__nd__option__redirected_header__from_buffer__round_trip(self) -> None:
        """
        Ensure assemble→parse round-trip preserves the data
        payload exactly.

        Reference: RFC 4861 §4.6.3 (Redirected Header wire format).
        """

        original = Icmp6NdOptionRedirectedHeader(data=bytes(range(16)))

        parsed = Icmp6NdOptionRedirectedHeader.from_buffer(bytes(original))

        self.assertEqual(
            parsed,
            original,
            msg="Round-trip parse must reproduce the original option.",
        )

    def test__icmp6__nd__option__redirected_header__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure 'from_buffer' parses a Redirected Header option when
        the input buffer carries trailing bytes past the encoded
        option length — sibling options in the same options block.

        Reference: RFC 4861 §4.6 (option chaining within a message).
        """

        buffer = b"\x04\x01\x00\x00\x00\x00\x00\x00" + b"NEXT_OPT"

        option = Icmp6NdOptionRedirectedHeader.from_buffer(buffer)

        self.assertEqual(
            option,
            Icmp6NdOptionRedirectedHeader(data=b""),
            msg="Trailing bytes past the encoded length must be ignored.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Redirected Header option, buffer shorter than ICMP6__ND__OPTION__LEN.",
            "_args": [b"\x04"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the ICMPv6 ND Redirected Header option must be " "2 bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Redirected Header option, buffer 'type' byte is not REDIRECTED_HEADER.",
            "_args": [b"\xff\x01\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The ICMPv6 ND Redirected Header option type must be "
                    f"{Icmp6NdOptionType.REDIRECTED_HEADER!r}. "
                    f"Got: {Icmp6NdOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 ND Redirected Header option, encoded length value "
                "below the minimum (1×8 = 8 bytes required)."
            ),
            "_args": [b"\x04\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Redirected Header option "
                    "length value must be at least 8 bytes. Got: 0"
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Redirected Header option, encoded length exceeds available buffer bytes.",
            "_args": [b"\x04\x02\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": Icmp6IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][ICMPv6] The ICMPv6 ND Redirected Header option "
                    "length value must be less than or equal to the length of provided "
                    "bytes (8). Got: 16"
                ),
            },
        },
    ]
)
class TestIcmp6NdOptionRedirectedHeaderParserFailures(TestCase):
    """
    The ICMPv6 ND Redirected Header option parser failure-path
    tests (asserts and integrity checks).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__icmp6__nd__option__redirected_header__from_buffer__error(self) -> None:
        """
        Ensure 'from_buffer' raises the expected exception with the
        expected message for each malformed buffer.

        Reference: RFC 4861 §4.6.3 (Redirected Header wire format).
        """

        with self.assertRaises(self._results["error"]) as error:
            Icmp6NdOptionRedirectedHeader.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
