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
Module contains tests for the unknown TCP option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__unknown.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TcpIntegrityError,
    TcpOptionType,
    TcpOptionUnknown,
)
from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.tcp.options.tcp__option import TCP__OPTION__LEN
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionUnknownAsserts(TestCase):
    """
    The unknown TCP option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP unknown option
        constructor so each test can override one field and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "type": TcpOptionType.from_int(255),
            "data": b"012345",
        }

    def test__tcp__option__unknown__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        option = TcpOptionUnknown(**self._kwargs)

        self.assertEqual(
            option.len,
            TCP__OPTION__LEN + len(self._kwargs["data"]),
            msg="Default-constructed unknown option 'len' must be header + data length.",
        )

    def test__tcp__option__unknown__type__not_TcpOptionType(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'type' argument is not a TcpOptionType.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self._kwargs["type"] = value = "not a TcpOptionType"

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a TcpOptionType. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-TcpOptionType 'type'.",
        )

    def test__tcp__option__unknown__type__core_value(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'type' argument is a core (known) TcpOptionType.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        for type_value in TcpOptionType.get_known_values():
            with self.subTest(type_value=type_value):
                self._kwargs["type"] = enum_value = TcpOptionType(type_value)

                with self.assertRaises(AssertionError) as error:
                    TcpOptionUnknown(**self._kwargs)

                self.assertEqual(
                    str(error.exception),
                    f"The 'type' field must not be a known TcpOptionType. Got: {enum_value!r}",
                    msg=f"Unexpected assertion message for known 'type'={enum_value!r}.",
                )

    def test__tcp__option__unknown__len__8bit_integer(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the computed 'len' field would exceed the 8-bit unsigned integer
        range (i.e. data is longer than UINT_8__MAX - 2 bytes).

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self._kwargs["data"] = b"X" * (UINT_8__MAX - TCP__OPTION__LEN + 1)

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {UINT_8__MAX + 1}",
            msg="Unexpected assertion message for over-long data payload.",
        )

    def test__tcp__option__unknown__len__8bit_integer__boundary(self) -> None:
        """
        Ensure the TCP unknown option constructor accepts exactly
        UINT_8__MAX bytes of total length (data length = UINT_8__MAX - 2).

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self._kwargs["data"] = b"X" * (UINT_8__MAX - TCP__OPTION__LEN)

        option = TcpOptionUnknown(**self._kwargs)

        self.assertEqual(
            option.len,
            UINT_8__MAX,
            msg="Option must accept a data payload that makes 'len' exactly UINT_8__MAX.",
        )


class TestTcpOptionUnknownAssembler(TestCase):
    """
    The unknown TCP option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the unknown TCP option fixture (type=255, data=ASCII hex).
        """

        self._option = TcpOptionUnknown(
            type=TcpOptionType.from_int(255),
            data=b"0123456789ABCDEF",
        )

    def test__tcp__option__unknown__len(self) -> None:
        """
        Ensure '__len__()' returns 2 (header) + 16 (data) = 18 bytes.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            len(self._option),
            18,
            msg="Unexpected __len__ for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__str(self) -> None:
        """
        Ensure '__str__()' returns 'unk-<type>-<len>'.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            str(self._option),
            "unk-255-18",
            msg="Unexpected __str__ for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            repr(self._option),
            (f"TcpOptionUnknown(type={TcpOptionType.from_int(255)!r}, " "len=18, data=b'0123456789ABCDEF')"),
            msg="Unexpected __repr__ for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected 18-byte wire frame.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        # Unknown TCP option wire frame (18 bytes = 2-byte header + 16-byte data):
        #   Byte 0     : 0xff             -> type=255
        #   Byte 1     : 0x12             -> len=18
        #   Bytes 2-17 : b"0123456789ABCDEF" (ASCII payload)
        self.assertEqual(
            bytes(self._option),
            b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46",
            msg="Unexpected __bytes__ for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__type(self) -> None:
        """
        Ensure the 'type' field is the provided non-core TcpOptionType(255).

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.from_int(255),
            msg="Unexpected 'type' field for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__length(self) -> None:
        """
        Ensure the 'len' field is TCP__OPTION__LEN + len(data) = 18.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            self._option.len,
            18,
            msg="Unexpected 'len' field for unknown TCP option fixture.",
        )

    def test__tcp__option__unknown__data(self) -> None:
        """
        Ensure the 'data' field exposes the provided payload bytes.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        self.assertEqual(
            self._option.data,
            b"0123456789ABCDEF",
            msg="Unexpected 'data' field for unknown TCP option fixture.",
        )


class TestTcpOptionUnknownParser(TestCase):
    """
    The unknown TCP option parser positive tests.
    """

    def test__tcp__option__unknown__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an unknown TCP option when the buffer
        carries trailing bytes past the declared option length.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        # Unknown TCP option wire frame (18 bytes) followed by 5 trailing bytes:
        #   Byte 0     : 0xff             -> type=255 (non-core)
        #   Byte 1     : 0x12             -> len=18
        #   Bytes 2-17 : b"0123456789ABCDEF" (ASCII payload)
        #   Bytes 18-22: b"ZH0PA"          -> trailing data, ignored
        buffer = b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46" + b"ZH0PA"

        option = TcpOptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionUnknown(type=TcpOptionType.from_int(255), data=b"0123456789ABCDEF"),
            msg="Parsed option must equal the reference unknown option (trailing bytes ignored).",
        )

    def test__tcp__option__unknown__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses an unknown TCP option whose buffer length
        exactly matches the declared option length.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        # Unknown TCP option wire frame (exactly 18 bytes):
        #   Byte 0     : 0xff             -> type=255 (non-core)
        #   Byte 1     : 0x12             -> len=18
        #   Bytes 2-17 : b"0123456789ABCDEF" (ASCII payload)
        buffer = b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"

        option = TcpOptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionUnknown(type=TcpOptionType.from_int(255), data=b"0123456789ABCDEF"),
            msg="Parsed option must equal the reference unknown option.",
        )

    def test__tcp__option__unknown__from_buffer__empty_data(self) -> None:
        """
        Ensure from_buffer parses an unknown TCP option with an empty
        data payload (len=2, header only).

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        # Unknown TCP option wire frame (2 bytes = header only, no data):
        #   Byte 0 : 0xff -> type=255
        #   Byte 1 : 0x02 -> len=2 (header only)
        buffer = b"\xff\x02"

        option = TcpOptionUnknown.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionUnknown(type=TcpOptionType.from_int(255), data=b""),
            msg="Parsed option must equal the reference unknown option with empty data.",
        )


@parameterized_class(
    [
        {
            "_description": "Unknown TCP option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the unknown TCP option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "Unknown TCP option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the unknown TCP option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core EOL.",
            "_args": [b"\x00\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.EOL!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core NOP.",
            "_args": [b"\x01\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.NOP!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core MSS.",
            "_args": [b"\x02\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.MSS!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core WSCALE.",
            "_args": [b"\x03\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.WSCALE!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core SACKPERM.",
            "_args": [b"\x04\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.SACKPERM!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core SACK.",
            "_args": [b"\x05\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The unknown TCP option type must not be known. Got: {TcpOptionType.SACK!r}",
            },
        },
        {
            "_description": "Unknown TCP option, buffer 'type' byte is core TIMESTAMPS.",
            "_args": [b"\x08\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45\x46"],
            "_results": {
                "error": AssertionError,
                "error_message": (f"The unknown TCP option type must not be known. Got: {TcpOptionType.TIMESTAMPS!r}"),
            },
        },
        {
            "_description": "Unknown TCP option, declared 'len' exceeds provided buffer size.",
            "_args": [b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44" b"\x45"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The unknown TCP option length value must be "
                    "less than or equal to the length of provided bytes (17). Got: 18"
                ),
            },
        },
    ]
)
class TestTcpOptionUnknownParserFailures(TestCase):
    """
    The unknown TCP option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__unknown__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 9293 §3.1 (TCP option TLV format).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionUnknown.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
