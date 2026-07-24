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
Module contains tests for the TCP Timestamps option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__timestamps.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TCP__OPTION__TIMESTAMPS__LEN,
    UINT_32__MAX,
    UINT_32__MIN,
    TcpIntegrityError,
    TcpOptionTimestamps,
    TcpOptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionTimestampsAsserts(TestCase):
    """
    The TCP Timestamps option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP Timestamps option
        constructor so each test can override one field and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "tsval": 0,
            "tsecr": 0,
        }

    def test__tcp__option__timestamps__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions that would make the
        baseline invalid.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        option = TcpOptionTimestamps(**self._kwargs)

        self.assertEqual(
            len(option),
            TCP__OPTION__TIMESTAMPS__LEN,
            msg="Default-constructed option must serialize to the 10-byte Timestamps option.",
        )

    def test__tcp__option__timestamps__tsval__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception
        when the provided 'tsval' argument is lower than the minimum
        supported value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self._kwargs["tsval"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'tsval' under UINT_32__MIN.",
        )

    def test__tcp__option__timestamps__tsval__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception
        when the provided 'tsval' argument is higher than the maximum
        supported value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self._kwargs["tsval"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'tsval' over UINT_32__MAX.",
        )

    def test__tcp__option__timestamps__tsecr__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception
        when the provided 'tsecr' argument is lower than the minimum
        supported value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self._kwargs["tsecr"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'tsecr' under UINT_32__MIN.",
        )

    def test__tcp__option__timestamps__tsecr__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception
        when the provided 'tsecr' argument is higher than the maximum
        supported value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self._kwargs["tsecr"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'tsecr' over UINT_32__MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Timestamps with tsval=tsecr=UINT_32__MAX (maximum values).",
            "_kwargs": {
                "tsval": 4294967295,
                "tsecr": 4294967295,
            },
            "_results": {
                "__str__": "timestamps 4294967295/4294967295",
                "__repr__": "TcpOptionTimestamps(tsval=4294967295, tsecr=4294967295)",
                # TCP Timestamps option wire frame (10 bytes):
                #   Byte 0     : 0x08       -> type=TcpOptionType.TIMESTAMPS (8)
                #   Byte 1     : 0x0a       -> len=TCP__OPTION__TIMESTAMPS__LEN (10)
                #   Bytes 2-5  : 0xffffffff -> tsval=4294967295 (UINT_32__MAX)
                #   Bytes 6-9  : 0xffffffff -> tsecr=4294967295 (UINT_32__MAX)
                "__bytes__": b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
            },
        },
        {
            "_description": "TCP Timestamps with typical-range tsval and tsecr values.",
            "_kwargs": {
                "tsval": 1111111111,
                "tsecr": 2222222222,
            },
            "_results": {
                "__str__": "timestamps 1111111111/2222222222",
                "__repr__": "TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222)",
                # TCP Timestamps option wire frame (10 bytes):
                #   Byte 0     : 0x08       -> type=TcpOptionType.TIMESTAMPS (8)
                #   Byte 1     : 0x0a       -> len=TCP__OPTION__TIMESTAMPS__LEN (10)
                #   Bytes 2-5  : 0x423a35c7 -> tsval=1111111111
                #   Bytes 6-9  : 0x84746b8e -> tsecr=2222222222
                "__bytes__": b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e",
            },
        },
        {
            "_description": "TCP Timestamps with tsval=tsecr=0 (minimum values).",
            "_kwargs": {
                "tsval": 0,
                "tsecr": 0,
            },
            "_results": {
                "__str__": "timestamps 0/0",
                "__repr__": "TcpOptionTimestamps(tsval=0, tsecr=0)",
                # TCP Timestamps option wire frame (10 bytes):
                #   Byte 0     : 0x08       -> type=TcpOptionType.TIMESTAMPS (8)
                #   Byte 1     : 0x0a       -> len=TCP__OPTION__TIMESTAMPS__LEN (10)
                #   Bytes 2-5  : 0x00000000 -> tsval=0
                #   Bytes 6-9  : 0x00000000 -> tsecr=0
                "__bytes__": b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00",
            },
        },
    ]
)
class TestTcpOptionTimestampsAssembler(TestCase):
    """
    The TCP Timestamps option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP Timestamps option from the parametrized kwargs.
        """

        self._option = TcpOptionTimestamps(**self._kwargs)

    def test__tcp__option__timestamps__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__TIMESTAMPS__LEN (10 bytes).

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__TIMESTAMPS__LEN,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__timestamps__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__timestamps__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__timestamps__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__timestamps__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.TIMESTAMPS.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.TIMESTAMPS,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__timestamps__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__TIMESTAMPS__LEN.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__TIMESTAMPS__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__tcp__option__timestamps__tsval(self) -> None:
        """
        Ensure the 'tsval' field exposes the provided value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            self._option.tsval,
            self._kwargs["tsval"],
            msg=f"Unexpected 'tsval' field for case: {self._description}",
        )

    def test__tcp__option__timestamps__tsecr(self) -> None:
        """
        Ensure the 'tsecr' field exposes the provided value.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            self._option.tsecr,
            self._kwargs["tsecr"],
            msg=f"Unexpected 'tsecr' field for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Timestamps option, UINT_32__MAX edges with trailing bytes.",
            "_args": [b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff" + b"ZH0PA"],
            "_expected": TcpOptionTimestamps(tsval=4294967295, tsecr=4294967295),
        },
        {
            "_description": "TCP Timestamps option, typical values with trailing bytes.",
            "_args": [b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e" + b"ZH0PA"],
            "_expected": TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222),
        },
        {
            "_description": "TCP Timestamps option, exact 10-byte buffer (no trailing bytes).",
            "_args": [b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_expected": TcpOptionTimestamps(tsval=0, tsecr=0),
        },
    ]
)
class TestTcpOptionTimestampsParser(TestCase):
    """
    The TCP Timestamps option parser positive tests.
    """

    _description: str
    _args: list[Any]
    _expected: TcpOptionTimestamps

    def test__tcp__option__timestamps__from_buffer(self) -> None:
        """
        Ensure from_buffer parses the Timestamps wire frame into the
        expected TcpOptionTimestamps (trailing bytes must be ignored).

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        option = TcpOptionTimestamps.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._expected,
            msg=f"Unexpected parsed option for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Timestamps option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\x08"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Timestamps option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "TCP Timestamps option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Timestamps option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "TCP Timestamps option, buffer 'type' byte is not TcpOptionType.TIMESTAMPS.",
            "_args": [b"\xff\x0a\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Timestamps option type must be {TcpOptionType.TIMESTAMPS!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Timestamps option, buffer 'type' byte is below TcpOptionType.TIMESTAMPS.",
            "_args": [b"\x05\x0a\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Timestamps option type must be {TcpOptionType.TIMESTAMPS!r}. "
                    f"Got: {TcpOptionType.from_int(5)!r}"
                ),
            },
        },
        {
            "_description": "TCP Timestamps option, declared 'len' differs from TCP__OPTION__TIMESTAMPS__LEN.",
            "_args": [b"\x08\x09\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Timestamps option length value must be 10 bytes. Got: 9"
                ),
            },
        },
        {
            "_description": "TCP Timestamps option, declared 'len' over TCP__OPTION__TIMESTAMPS__LEN (buffer present).",
            "_args": [b"\x08\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Timestamps option length value must be 10 bytes. Got: 11"
                ),
            },
        },
        {
            "_description": "TCP Timestamps option, declared 'len' exceeds provided buffer size.",
            "_args": [b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Timestamps option length value must be "
                    "less than or equal to the length of provided bytes (9). Got: 10"
                ),
            },
        },
    ]
)
class TestTcpOptionTimestampsParserFailures(TestCase):
    """
    The TCP Timestamps option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__timestamps__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionTimestamps.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
