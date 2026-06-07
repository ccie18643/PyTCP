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
Module contains tests for the TCP Mss (Maximum Segment Size) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__mss.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    TCP__OPTION__MSS__LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    TcpIntegrityError,
    TcpOptionMss,
    TcpOptionType,
)


class TestTcpOptionMssAsserts(TestCase):
    """
    The TCP Mss option constructor argument assert tests.
    """

    def test__tcp__option__mss__mss__under_min(self) -> None:
        """
        Ensure the TCP Mss option constructor raises an exception when the
        provided 'mss' argument is lower than the minimum supported value.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionMss(value)

        self.assertEqual(
            str(error.exception),
            f"The 'mss' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'mss' under UINT_16__MIN.",
        )

    def test__tcp__option__mss__mss__over_max(self) -> None:
        """
        Ensure the TCP Mss option constructor raises an exception when the
        provided 'mss' argument is higher than the maximum supported value.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionMss(value)

        self.assertEqual(
            str(error.exception),
            f"The 'mss' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'mss' over UINT_16__MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Mss option, mss=0 (minimum value).",
            "_mss": 0,
            "_results": {
                "__len__": 4,
                "__str__": "mss 0",
                "__repr__": "TcpOptionMss(mss=0)",
                # TCP Mss option wire frame (4 bytes):
                #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
                #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
                #   Bytes 2-3 : 0x0000      -> mss=0
                "__bytes__": b"\x02\x04\x00\x00",
            },
        },
        {
            "_description": "TCP Mss option, mss=UINT_16__MAX (maximum value).",
            "_mss": UINT_16__MAX,
            "_results": {
                "__len__": 4,
                "__str__": "mss 65535",
                "__repr__": "TcpOptionMss(mss=65535)",
                # TCP Mss option wire frame (4 bytes):
                #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
                #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
                #   Bytes 2-3 : 0xffff      -> mss=65535 (UINT_16__MAX)
                "__bytes__": b"\x02\x04\xff\xff",
            },
        },
        {
            "_description": "TCP Mss option, mss=1460 (typical Ethernet MSS).",
            "_mss": 1460,
            "_results": {
                "__len__": 4,
                "__str__": "mss 1460",
                "__repr__": "TcpOptionMss(mss=1460)",
                # TCP Mss option wire frame (4 bytes):
                #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
                #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
                #   Bytes 2-3 : 0x05b4      -> mss=1460 (typical Ethernet MSS)
                "__bytes__": b"\x02\x04\x05\xb4",
            },
        },
    ]
)
class TestTcpOptionMssAssembler(TestCase):
    """
    The TCP Mss option assembler tests.
    """

    _description: str
    _mss: int
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP Mss option from the parametrized 'mss' value.
        """

        self._option = TcpOptionMss(self._mss)

    def test__tcp__option__mss__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total option length.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__mss__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__mss__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__mss__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__mss__mss(self) -> None:
        """
        Ensure the 'mss' field exposes the provided MSS value.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            self._option.mss,
            self._mss,
            msg=f"Unexpected 'mss' field for case: {self._description}",
        )

    def test__tcp__option__mss__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.MSS.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.MSS,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__mss__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__MSS__LEN.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__MSS__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )


class TestTcpOptionMssParser(TestCase):
    """
    The TCP Mss option parser positive tests.
    """

    def test__tcp__option__mss__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 4-byte Mss whose buffer length exactly
        matches TCP__OPTION__MSS__LEN.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        # TCP Mss option wire frame (exactly 4 bytes):
        #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
        #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
        #   Bytes 2-3 : 0xffff      -> mss=65535
        buffer = b"\x02\x04\xff\xff"

        option = TcpOptionMss.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionMss(mss=65535),
            msg="Parsed option must equal the reference TcpOptionMss(mss=65535).",
        )

    def test__tcp__option__mss__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Mss option when the buffer carries
        trailing bytes past the 4-byte option payload (those trailing
        bytes are consumed by the next option in the options container).

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        # TCP Mss option wire frame followed by 5 trailing bytes:
        #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
        #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
        #   Bytes 2-3 : 0xffff      -> mss=65535
        #   Bytes 4-8 : b"ZH0PA"    -> trailing data, not part of the Mss
        buffer = b"\x02\x04\xff\xff" + b"ZH0PA"

        option = TcpOptionMss.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionMss(mss=65535),
            msg="Parsed option must equal TcpOptionMss(mss=65535) (trailing bytes ignored).",
        )

    def test__tcp__option__mss__from_buffer__zero_mss(self) -> None:
        """
        Ensure from_buffer parses a valid Mss option carrying the minimum
        mss value of 0.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        # TCP Mss option wire frame (4 bytes, mss=0):
        #   Byte 0    : 0x02        -> type=TcpOptionType.MSS (2)
        #   Byte 1    : 0x04        -> len=TCP__OPTION__MSS__LEN (4)
        #   Bytes 2-3 : 0x0000      -> mss=0
        buffer = b"\x02\x04\x00\x00"

        option = TcpOptionMss.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionMss(mss=0),
            msg="Parsed option must equal TcpOptionMss(mss=0) for zero-value frame.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Mss option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\x02"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Mss option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "TCP Mss option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Mss option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "TCP Mss option, buffer 'type' byte is not TcpOptionType.MSS.",
            "_args": [b"\xff\x04\xff\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Mss option type must be {TcpOptionType.MSS!r}. " f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Mss option, declared 'len' byte differs from TCP__OPTION__MSS__LEN.",
            "_args": [b"\x02\x03\xff\xff"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "[INTEGRITY ERROR][TCP] The TCP Mss option length value must be 4 bytes. Got: 3",
            },
        },
        {
            "_description": "TCP Mss option, declared 'len' exceeds provided buffer size.",
            "_args": [b"\x02\x04\xff"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Mss option length value must be "
                    "less than or equal to the length of provided bytes (3). Got: 4"
                ),
            },
        },
    ]
)
class TestTcpOptionMssParserFailures(TestCase):
    """
    The TCP Mss option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__mss__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionMss.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
