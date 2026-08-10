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
Module contains tests for the IPv4 Eol (End of Option List) option code.

net_proto/tests/unit/protocols/ip4/test__ip4__option__eol.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import IP4__OPTION__EOL__LEN, Ip4OptionEol, Ip4OptionType
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionEolAssembler(TestCase):
    """
    The IPv4 Eol option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the IPv4 Eol option; the option takes no constructor args.
        """

        self._option = Ip4OptionEol()

    def test__ip4__option__eol__len(self) -> None:
        """
        Ensure '__len__()' returns IP4__OPTION__EOL__LEN (1 byte).

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        self.assertEqual(
            len(self._option),
            IP4__OPTION__EOL__LEN,
            msg="Unexpected __len__ for IPv4 Eol option.",
        )

    def test__ip4__option__eol__str(self) -> None:
        """
        Ensure '__str__()' returns the log string 'eol'.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        self.assertEqual(
            str(self._option),
            "eol",
            msg="Unexpected __str__ for IPv4 Eol option.",
        )

    def test__ip4__option__eol__repr(self) -> None:
        """
        Ensure '__repr__()' returns 'Ip4OptionEol()'.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        self.assertEqual(
            repr(self._option),
            "Ip4OptionEol()",
            msg="Unexpected __repr__ for IPv4 Eol option.",
        )

    def test__ip4__option__eol__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the single wire byte 0x00.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        # IPv4 Eol option wire format:
        #   Type: 0x00 (Ip4OptionType.EOL)
        self.assertEqual(
            bytes(self._option),
            b"\x00",
            msg="Unexpected __bytes__ for IPv4 Eol option.",
        )

    def test__ip4__option__eol__type(self) -> None:
        """
        Ensure the 'type' field is Ip4OptionType.EOL.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        self.assertEqual(
            self._option.type,
            Ip4OptionType.EOL,
            msg="Unexpected 'type' field for IPv4 Eol option.",
        )

    def test__ip4__option__eol__length(self) -> None:
        """
        Ensure the 'len' field equals IP4__OPTION__EOL__LEN.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        self.assertEqual(
            self._option.len,
            IP4__OPTION__EOL__LEN,
            msg="Unexpected 'len' field for IPv4 Eol option.",
        )


class TestIp4OptionEolParser(TestCase):
    """
    The IPv4 Eol option parser positive tests.
    """

    def test__ip4__option__eol__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 1-byte Eol whose buffer length
        exactly matches IP4__OPTION__EOL__LEN.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        # IPv4 Eol option wire format (exactly 1 byte):
        #   Type: 0x00 (Ip4OptionType.EOL)
        buffer = b"\x00"

        self.assertEqual(
            len(buffer),
            IP4__OPTION__EOL__LEN,
            msg="Fixture must match IP4__OPTION__EOL__LEN.",
        )

        option = Ip4OptionEol.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionEol(),
            msg="Parsed option must equal the reference Ip4OptionEol.",
        )

    def test__ip4__option__eol__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses an Eol option when the buffer carries
        trailing bytes past the 1-byte option payload (those trailing
        bytes are consumed by the next option in the options container).

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        # IPv4 Eol option wire format followed by 5 trailing bytes that
        # must be ignored by Ip4OptionEol.from_buffer:
        #   Type: 0x00 (Ip4OptionType.EOL)
        #   Trail: b"ZH0PA"
        buffer = b"\x00" + b"ZH0PA"

        option = Ip4OptionEol.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionEol(),
            msg="Parsed option must equal the reference Ip4OptionEol (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 Eol option, buffer shorter than IP4__OPTION__EOL__LEN.",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the IPv4 Eol option must be 1 byte. Got: 0",
            },
        },
        {
            "_description": "IPv4 Eol option, buffer 'type' byte is not Ip4OptionType.EOL.",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Eol option type must be {Ip4OptionType.EOL!r}. " f"Got: {Ip4OptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "IPv4 Eol option, buffer 'type' byte is Nop (another known type).",
            "_args": [b"\x01"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Eol option type must be {Ip4OptionType.EOL!r}. " f"Got: {Ip4OptionType.NOP!r}"
                ),
            },
        },
    ]
)
class TestIp4OptionEolParserFailures(TestCase):
    """
    The IPv4 Eol option parser failure-path tests (assertion errors on
    short and mistyped buffers).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__ip4__option__eol__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 791 §3.1 (End of Option List — type byte = 0).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4OptionEol.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
