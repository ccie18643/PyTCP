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
Module contains tests for the IPv4 Nop (No Operation) option code.

net_proto/tests/unit/protocols/ip4/test__ip4__option__nop.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import IP4__OPTION__NOP__LEN, Ip4OptionNop, Ip4OptionType
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionNopAssembler(TestCase):
    """
    The IPv4 Nop option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the IPv4 Nop option; the option takes no constructor args.
        """

        self._option = Ip4OptionNop()

    def test__ip4__option__nop__len(self) -> None:
        """
        Ensure '__len__()' returns IP4__OPTION__NOP__LEN (1 byte).

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        self.assertEqual(
            len(self._option),
            IP4__OPTION__NOP__LEN,
            msg="Unexpected __len__ for IPv4 Nop option.",
        )

    def test__ip4__option__nop__str(self) -> None:
        """
        Ensure '__str__()' returns the log string 'nop'.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        self.assertEqual(
            str(self._option),
            "nop",
            msg="Unexpected __str__ for IPv4 Nop option.",
        )

    def test__ip4__option__nop__repr(self) -> None:
        """
        Ensure '__repr__()' returns 'Ip4OptionNop()'.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        self.assertEqual(
            repr(self._option),
            "Ip4OptionNop()",
            msg="Unexpected __repr__ for IPv4 Nop option.",
        )

    def test__ip4__option__nop__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the single wire byte 0x01.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        # IPv4 Nop option wire format:
        #   Type: 0x01 (Ip4OptionType.NOP)
        self.assertEqual(
            bytes(self._option),
            b"\x01",
            msg="Unexpected __bytes__ for IPv4 Nop option.",
        )

    def test__ip4__option__nop__type(self) -> None:
        """
        Ensure the 'type' field is Ip4OptionType.NOP.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        self.assertEqual(
            self._option.type,
            Ip4OptionType.NOP,
            msg="Unexpected 'type' field for IPv4 Nop option.",
        )

    def test__ip4__option__nop__length(self) -> None:
        """
        Ensure the 'len' field equals IP4__OPTION__NOP__LEN.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        self.assertEqual(
            self._option.len,
            IP4__OPTION__NOP__LEN,
            msg="Unexpected 'len' field for IPv4 Nop option.",
        )


class TestIp4OptionNopParser(TestCase):
    """
    The IPv4 Nop option parser positive tests.
    """

    def test__ip4__option__nop__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 1-byte Nop whose buffer length
        exactly matches IP4__OPTION__NOP__LEN.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        # IPv4 Nop option wire format (exactly 1 byte):
        #   Type: 0x01 (Ip4OptionType.NOP)
        buffer = b"\x01"

        self.assertEqual(
            len(buffer),
            IP4__OPTION__NOP__LEN,
            msg="Fixture must match IP4__OPTION__NOP__LEN.",
        )

        option = Ip4OptionNop.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionNop(),
            msg="Parsed option must equal the reference Ip4OptionNop.",
        )

    def test__ip4__option__nop__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Nop option when the buffer carries
        trailing bytes past the 1-byte option payload (those trailing
        bytes are consumed by the next option in the options container).

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        # IPv4 Nop option wire format followed by 5 trailing bytes that
        # must be ignored by Ip4OptionNop.from_buffer:
        #   Type: 0x01 (Ip4OptionType.NOP)
        #   Trail: b"ZH0PA"
        buffer = b"\x01" + b"ZH0PA"

        option = Ip4OptionNop.from_buffer(buffer)

        self.assertEqual(
            option,
            Ip4OptionNop(),
            msg="Parsed option must equal the reference Ip4OptionNop (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 Nop option, buffer shorter than IP4__OPTION__NOP__LEN.",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the IPv4 Nop option must be 1 byte. Got: 0",
            },
        },
        {
            "_description": "IPv4 Nop option, buffer 'type' byte is not Ip4OptionType.NOP.",
            "_args": [b"\xff"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Nop option type must be {Ip4OptionType.NOP!r}. " f"Got: {Ip4OptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "IPv4 Nop option, buffer 'type' byte is Eol (another known type).",
            "_args": [b"\x00"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Nop option type must be {Ip4OptionType.NOP!r}. " f"Got: {Ip4OptionType.EOL!r}"
                ),
            },
        },
    ]
)
class TestIp4OptionNopParserFailures(TestCase):
    """
    The IPv4 Nop option parser failure-path tests (assertion errors on
    short and mistyped buffers).
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__ip4__option__nop__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 791 §3.1 (No Operation — type byte = 1).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4OptionNop.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
