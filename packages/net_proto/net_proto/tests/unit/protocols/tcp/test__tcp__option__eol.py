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
Module contains tests for the TCP Eol (End of Option List) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__eol.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import TCP__OPTION__EOL__LEN, TcpOptionEol, TcpOptionType


class TestTcpOptionEolAssembler(TestCase):
    """
    The TCP Eol option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the TCP Eol option; the option takes no constructor args.
        """

        self._option = TcpOptionEol()

    def test__tcp__option__eol__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__EOL__LEN (1 byte).

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__EOL__LEN,
            msg="Unexpected __len__ for TCP Eol option.",
        )

    def test__tcp__option__eol__str(self) -> None:
        """
        Ensure '__str__()' returns the log string 'eol'.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        self.assertEqual(
            str(self._option),
            "eol",
            msg="Unexpected __str__ for TCP Eol option.",
        )

    def test__tcp__option__eol__repr(self) -> None:
        """
        Ensure '__repr__()' returns 'TcpOptionEol()'.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        self.assertEqual(
            repr(self._option),
            "TcpOptionEol()",
            msg="Unexpected __repr__ for TCP Eol option.",
        )

    def test__tcp__option__eol__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the single wire byte 0x00.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        # TCP Eol option wire format (1 byte):
        #   Byte 0 : 0x00 -> type=TcpOptionType.EOL (0)
        self.assertEqual(
            bytes(self._option),
            b"\x00",
            msg="Unexpected __bytes__ for TCP Eol option.",
        )

    def test__tcp__option__eol__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.EOL.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.EOL,
            msg="Unexpected 'type' field for TCP Eol option.",
        )

    def test__tcp__option__eol__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__EOL__LEN.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__EOL__LEN,
            msg="Unexpected 'len' field for TCP Eol option.",
        )


class TestTcpOptionEolParser(TestCase):
    """
    The TCP Eol option parser positive tests.
    """

    def test__tcp__option__eol__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 1-byte Eol whose buffer length exactly
        matches TCP__OPTION__EOL__LEN.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        # TCP Eol option wire format (exactly 1 byte):
        #   Byte 0 : 0x00 -> type=TcpOptionType.EOL (0)
        buffer = b"\x00"

        self.assertEqual(
            len(buffer),
            TCP__OPTION__EOL__LEN,
            msg="Fixture must match TCP__OPTION__EOL__LEN.",
        )

        option = TcpOptionEol.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionEol(),
            msg="Parsed option must equal the reference TcpOptionEol.",
        )

    def test__tcp__option__eol__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an Eol option when the buffer carries
        trailing bytes past the 1-byte option payload (those trailing
        bytes are consumed by the next option in the options container).

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        # TCP Eol option wire format followed by 5 trailing bytes that
        # must be ignored by TcpOptionEol.from_buffer:
        #   Byte 0    : 0x00        -> type=TcpOptionType.EOL (0)
        #   Bytes 1-5 : b"ZH0PA"    -> trailing data, not part of the Eol
        buffer = b"\x00" + b"ZH0PA"

        option = TcpOptionEol.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionEol(),
            msg="Parsed option must equal the reference TcpOptionEol (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Eol option, buffer shorter than TCP__OPTION__EOL__LEN.",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Eol option must be 1 byte. Got: 0",
            },
        },
        {
            "_description": "TCP Eol option, buffer 'type' byte is not TcpOptionType.EOL.",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Eol option type must be {TcpOptionType.EOL!r}. " f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Eol option, buffer 'type' byte is Nop (another known type).",
            "_args": [b"\x01"],
            "_results": {
                "error": AssertionError,
                "error_message": f"The TCP Eol option type must be {TcpOptionType.EOL!r}. Got: {TcpOptionType.NOP!r}",
            },
        },
    ]
)
class TestTcpOptionEolParserFailures(TestCase):
    """
    The TCP Eol option parser failure-path tests (assertion errors on
    short and mistyped buffers).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__eol__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 9293 §3.1 (End of Option List — kind 0).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionEol.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
