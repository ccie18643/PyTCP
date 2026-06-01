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
Module contains tests for the TCP Sackperm (SACK Permitted) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__sackperm.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    TCP__OPTION__SACKPERM__LEN,
    TcpIntegrityError,
    TcpOptionSackperm,
    TcpOptionType,
)


class TestTcpOptionSackpermAssembler(TestCase):
    """
    The TCP Sackperm option assembler tests.
    """

    def setUp(self) -> None:
        """
        Build the TCP Sackperm option; the option takes no constructor args.
        """

        self._option = TcpOptionSackperm()

    def test__tcp__option__sackperm__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__SACKPERM__LEN (2 bytes).

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__SACKPERM__LEN,
            msg="Unexpected __len__ for TCP Sackperm option.",
        )

    def test__tcp__option__sackperm__str(self) -> None:
        """
        Ensure '__str__()' returns the log string 'sackperm'.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            str(self._option),
            "sackperm",
            msg="Unexpected __str__ for TCP Sackperm option.",
        )

    def test__tcp__option__sackperm__repr(self) -> None:
        """
        Ensure '__repr__()' returns 'TcpOptionSackperm()'.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            repr(self._option),
            "TcpOptionSackperm()",
            msg="Unexpected __repr__ for TCP Sackperm option.",
        )

    def test__tcp__option__sackperm__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the 2-byte wire frame.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        # TCP Sackperm option wire frame (2 bytes):
        #   Byte 0 : 0x04 -> type=TcpOptionType.SACKPERM (4)
        #   Byte 1 : 0x02 -> len=TCP__OPTION__SACKPERM__LEN (2)
        self.assertEqual(
            bytes(self._option),
            b"\x04\x02",
            msg="Unexpected __bytes__ for TCP Sackperm option.",
        )

    def test__tcp__option__sackperm__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.SACKPERM.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.SACKPERM,
            msg="Unexpected 'type' field for TCP Sackperm option.",
        )

    def test__tcp__option__sackperm__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__SACKPERM__LEN.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__SACKPERM__LEN,
            msg="Unexpected 'len' field for TCP Sackperm option.",
        )


class TestTcpOptionSackpermParser(TestCase):
    """
    The TCP Sackperm option parser positive tests.
    """

    def test__tcp__option__sackperm__from_buffer__exact_length(self) -> None:
        """
        Ensure from_buffer parses a 2-byte Sackperm whose buffer length
        exactly matches TCP__OPTION__SACKPERM__LEN.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        # TCP Sackperm option wire frame (exactly 2 bytes):
        #   Byte 0 : 0x04 -> type=TcpOptionType.SACKPERM (4)
        #   Byte 1 : 0x02 -> len=TCP__OPTION__SACKPERM__LEN (2)
        buffer = b"\x04\x02"

        option = TcpOptionSackperm.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionSackperm(),
            msg="Parsed option must equal the reference TcpOptionSackperm.",
        )

    def test__tcp__option__sackperm__from_buffer__trailing_bytes_ignored(self) -> None:
        """
        Ensure from_buffer parses a Sackperm option when the buffer carries
        trailing bytes past the 2-byte option payload (those trailing
        bytes are consumed by the next option in the options container).

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        # TCP Sackperm option wire frame followed by 5 trailing bytes:
        #   Byte 0    : 0x04        -> type=TcpOptionType.SACKPERM (4)
        #   Byte 1    : 0x02        -> len=TCP__OPTION__SACKPERM__LEN (2)
        #   Bytes 2-6 : b"ZH0PA"    -> trailing data, not part of the Sackperm
        buffer = b"\x04\x02" + b"ZH0PA"

        option = TcpOptionSackperm.from_buffer(buffer)

        self.assertEqual(
            option,
            TcpOptionSackperm(),
            msg="Parsed option must equal TcpOptionSackperm (trailing bytes ignored).",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Sackperm option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\x04"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Sackperm option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "TCP Sackperm option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Sackperm option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "TCP Sackperm option, buffer 'type' byte is not TcpOptionType.SACKPERM.",
            "_args": [b"\xff\x02"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Sackperm option type must be {TcpOptionType.SACKPERM!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Sackperm option, declared 'len' byte differs from TCP__OPTION__SACKPERM__LEN.",
            "_args": [b"\x04\x01"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sackperm option length value must be 2 bytes. Got: 1"
                ),
            },
        },
    ]
)
class TestTcpOptionSackpermParserFailures(TestCase):
    """
    The TCP Sackperm option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__sackperm__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionSackperm.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
