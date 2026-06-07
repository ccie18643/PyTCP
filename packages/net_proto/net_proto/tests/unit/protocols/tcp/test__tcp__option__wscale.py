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
Module contains tests for the TCP Wscale (Window Scale) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__wscale.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TCP__OPTION__WSCALE__LEN,
    TCP__OPTION__WSCALE__MAX_VALUE,
    UINT_8__MIN,
    TcpIntegrityError,
    TcpOptionType,
    TcpOptionWscale,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionWscaleAsserts(TestCase):
    """
    The TCP Wscale option constructor argument assert tests.
    """

    def test__tcp__option__wscale__wscale__under_min(self) -> None:
        """
        Ensure the TCP Wscale option constructor raises an exception when
        the provided 'wscale' argument is lower than the minimum supported
        value.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionWscale(value)

        self.assertEqual(
            str(error.exception),
            (
                "The 'wscale' field must be an 8-bit unsigned integer less than "
                f"or equal to {TCP__OPTION__WSCALE__MAX_VALUE}. Got: {value!r}"
            ),
            msg="Unexpected assertion message for 'wscale' under UINT_8__MIN.",
        )

    def test__tcp__option__wscale__wscale__over_max(self) -> None:
        """
        Ensure the TCP Wscale option constructor raises an exception when
        the provided 'wscale' argument is higher than the Wscale option
        maximum supported value.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        value = TCP__OPTION__WSCALE__MAX_VALUE + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionWscale(value)

        self.assertEqual(
            str(error.exception),
            (
                "The 'wscale' field must be an 8-bit unsigned integer less than "
                f"or equal to {TCP__OPTION__WSCALE__MAX_VALUE}. Got: {value!r}"
            ),
            msg="Unexpected assertion message for 'wscale' over TCP__OPTION__WSCALE__MAX_VALUE.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Wscale option, wscale=0 (minimum value).",
            "_wscale": 0,
            "_results": {
                "__str__": "wscale 0",
                "__repr__": "TcpOptionWscale(wscale=0)",
                # TCP Wscale option wire frame (3 bytes):
                #   Byte 0 : 0x03 -> type=TcpOptionType.WSCALE (3)
                #   Byte 1 : 0x03 -> len=TCP__OPTION__WSCALE__LEN (3)
                #   Byte 2 : 0x00 -> wscale=0
                "__bytes__": b"\x03\x03\x00",
            },
        },
        {
            "_description": "TCP Wscale option, wscale=TCP__OPTION__WSCALE__MAX_VALUE (14).",
            "_wscale": TCP__OPTION__WSCALE__MAX_VALUE,
            "_results": {
                "__str__": "wscale 14",
                "__repr__": "TcpOptionWscale(wscale=14)",
                # TCP Wscale option wire frame (3 bytes):
                #   Byte 0 : 0x03 -> type=TcpOptionType.WSCALE (3)
                #   Byte 1 : 0x03 -> len=TCP__OPTION__WSCALE__LEN (3)
                #   Byte 2 : 0x0e -> wscale=14 (TCP__OPTION__WSCALE__MAX_VALUE)
                "__bytes__": b"\x03\x03\x0e",
            },
        },
        {
            "_description": "TCP Wscale option, wscale=7 (mid-range value).",
            "_wscale": 7,
            "_results": {
                "__str__": "wscale 7",
                "__repr__": "TcpOptionWscale(wscale=7)",
                # TCP Wscale option wire frame (3 bytes):
                #   Byte 0 : 0x03 -> type=TcpOptionType.WSCALE (3)
                #   Byte 1 : 0x03 -> len=TCP__OPTION__WSCALE__LEN (3)
                #   Byte 2 : 0x07 -> wscale=7
                "__bytes__": b"\x03\x03\x07",
            },
        },
    ]
)
class TestTcpOptionWscaleAssembler(TestCase):
    """
    The TCP Wscale option assembler tests.
    """

    _description: str
    _wscale: int
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP Wscale option from the parametrized 'wscale' value.
        """

        self._option = TcpOptionWscale(self._wscale)

    def test__tcp__option__wscale__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__WSCALE__LEN (3 bytes).

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__WSCALE__LEN,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__wscale__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__wscale__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__wscale__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__wscale__wscale(self) -> None:
        """
        Ensure the 'wscale' field exposes the provided wscale value.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            self._option.wscale,
            self._wscale,
            msg=f"Unexpected 'wscale' field for case: {self._description}",
        )

    def test__tcp__option__wscale__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.WSCALE.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.WSCALE,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__wscale__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__WSCALE__LEN.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__WSCALE__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )


class TestTcpOptionWscaleParser(TestCase):
    """
    The TCP Wscale option parser positive tests.
    """

    def test__tcp__option__wscale__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 3-byte Wscale whose buffer length
        exactly matches TCP__OPTION__WSCALE__LEN.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        # TCP Wscale option wire frame (exactly 3 bytes):
        #   Byte 0 : 0x03 -> type=TcpOptionType.WSCALE (3)
        #   Byte 1 : 0x03 -> len=TCP__OPTION__WSCALE__LEN (3)
        #   Byte 2 : 0x0e -> wscale=14
        buffer = b"\x03\x03\x0e"

        option = TcpOptionWscale.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionWscale(wscale=14),
            msg="Parsed option must equal TcpOptionWscale(wscale=14).",
        )

    def test__tcp__option__wscale__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Wscale option when the buffer carries
        trailing bytes past the 3-byte option payload.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        # TCP Wscale option wire frame followed by 5 trailing bytes:
        #   Byte 0    : 0x03        -> type=TcpOptionType.WSCALE (3)
        #   Byte 1    : 0x03        -> len=TCP__OPTION__WSCALE__LEN (3)
        #   Byte 2    : 0x0e        -> wscale=14
        #   Bytes 3-7 : b"ZH0PA"    -> trailing data, not part of the Wscale
        buffer = b"\x03\x03\x0e" + b"ZH0PA"

        option = TcpOptionWscale.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionWscale(wscale=14),
            msg="Parsed option must equal TcpOptionWscale(wscale=14) (trailing bytes ignored).",
        )

    def test__tcp__option__wscale__from_buffer__value_clamped_to_max(self) -> None:
        """
        Ensure from_buffer clamps a received wscale value that exceeds
        TCP__OPTION__WSCALE__MAX_VALUE down to the maximum on the
        resilience behaviour path (the wire value 0xff is clamped to
        14).

        Reference: RFC 7323 §2.3 (wscale clamp to 14 on receive resilience).
        """

        # TCP Wscale option wire frame with out-of-range wscale=0xff:
        #   Byte 0    : 0x03        -> type=TcpOptionType.WSCALE (3)
        #   Byte 1    : 0x03        -> len=TCP__OPTION__WSCALE__LEN (3)
        #   Byte 2    : 0xff        -> wscale=255 (to be clamped to 14)
        #   Bytes 3-7 : b"ZH0PA"    -> trailing data, ignored
        buffer = b"\x03\x03\xff" + b"ZH0PA"

        option = TcpOptionWscale.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionWscale(wscale=TCP__OPTION__WSCALE__MAX_VALUE),
            msg="Parsed option must be clamped to TCP__OPTION__WSCALE__MAX_VALUE.",
        )

    def test__tcp__option__wscale__from_buffer__zero_wscale(self) -> None:
        """
        Ensure from_buffer parses a valid Wscale option carrying wscale=0.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        # TCP Wscale option wire frame (3 bytes, wscale=0):
        #   Byte 0 : 0x03 -> type=TcpOptionType.WSCALE (3)
        #   Byte 1 : 0x03 -> len=TCP__OPTION__WSCALE__LEN (3)
        #   Byte 2 : 0x00 -> wscale=0
        buffer = b"\x03\x03\x00"

        option = TcpOptionWscale.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionWscale(wscale=0),
            msg="Parsed option must equal TcpOptionWscale(wscale=0).",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Wscale option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\x03"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Wscale option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "TCP Wscale option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Wscale option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "TCP Wscale option, buffer 'type' byte is not TcpOptionType.WSCALE.",
            "_args": [b"\xff\x03\x0e"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Wscale option type must be {TcpOptionType.WSCALE!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Wscale option, declared 'len' byte differs from TCP__OPTION__WSCALE__LEN.",
            "_args": [b"\x03\x02\x0e"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": ("[INTEGRITY ERROR][TCP] The TCP Wscale option length value must be 3 bytes. Got: 2"),
            },
        },
        {
            "_description": "TCP Wscale option, declared 'len' exceeds provided buffer size.",
            "_args": [b"\x03\x03"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Wscale option length value must be "
                    "less than or equal to the length of provided bytes (2). Got: 3"
                ),
            },
        },
    ]
)
class TestTcpOptionWscaleParserFailures(TestCase):
    """
    The TCP Wscale option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__wscale__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionWscale.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
