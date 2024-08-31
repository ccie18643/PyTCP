#!/usr/bin/env python3

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
Module contains tests for the TCP options support code.

tests/unit/protocols/tcp/test__tcp__options.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option import TcpOption, TcpOptionType
from pytcp.protocols.tcp.options.tcp_option__eol import TcpOptionEol
from pytcp.protocols.tcp.options.tcp_option__mss import TcpOptionMss
from pytcp.protocols.tcp.options.tcp_option__nop import TcpOptionNop
from pytcp.protocols.tcp.options.tcp_option__sack import (
    TcpOptionSack,
    TcpSackBlock,
)
from pytcp.protocols.tcp.options.tcp_option__sackperm import TcpOptionSackperm
from pytcp.protocols.tcp.options.tcp_option__timestamps import (
    TcpOptionTimestamps,
    TcpTimestamps,
)
from pytcp.protocols.tcp.options.tcp_option__unknown import TcpOptionUnknown
from pytcp.protocols.tcp.options.tcp_option__wscale import TcpOptionWscale
from pytcp.protocols.tcp.options.tcp_options import TcpOptions


@parameterized_class(
    [
        {
            "_description": "The TCP options (I).",
            "_args": [
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionEol(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "nop, nop, nop, eol",
                "__repr__": (
                    "TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionEol()])"
                ),
                "__bytes__": b"\x01\x01\x01\x00",
                "mss": None,
                "wscale": None,
                "sackperm": None,
                "sack": None,
                "timestamps": None,
            },
        },
        {
            "_description": "The TCP options (II).",
            "_args": [
                TcpOptionMss(mss=1460),
                TcpOptionWscale(wscale=7),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222),
                TcpOptionNop(),
                TcpOptionUnknown(
                    type=TcpOptionType.from_int(255),
                    len=18,
                    data=b"0123456789ABCDEF",
                ),
                TcpOptionNop(),
                TcpOptionEol(),
            ],
            "_results": {
                "__len__": 40,
                "__str__": (
                    "mss 1460, wscale 7, sackperm, timestamps 1111111111/2222222222, "
                    "nop, unk-255-18, nop, eol"
                ),
                "__repr__": (
                    "TcpOptions(options=[TcpOptionMss(mss=1460), TcpOptionWscale(wscale=7), "
                    "TcpOptionSackperm(), TcpOptionTimestamps(tsval=1111111111, "
                    "tsecr=2222222222), TcpOptionNop(), TcpOptionUnknown(type=<TcpOptionType."
                    "UNKNOWN_255: 255>, len=18, data=b'0123456789ABCDEF'), TcpOptionNop(), "
                    "TcpOptionEol()])"
                ),
                "__bytes__": (
                    b"\x02\x04\x05\xb4\x03\x03\x07\x04\x02\x08\x0a\x42\x3a\x35\xc7\x84"
                    b"\x74\x6b\x8e\x01\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                    b"\x41\x42\x43\x44\x45\x46\x01\x00"
                ),
                "mss": 1460,
                "wscale": 7,
                "sackperm": True,
                "sack": None,
                "timestamps": TcpTimestamps(tsval=1111111111, tsecr=2222222222),
            },
        },
        {
            "_description": "The TCP options (III).",
            "_args": [
                TcpOptionMss(mss=1200),
                TcpOptionWscale(wscale=5),
                TcpOptionNop(),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=123, tsecr=345),
            ],
            "_results": {
                "__len__": 20,
                "__str__": (
                    "mss 1200, wscale 5, nop, sackperm, timestamps 123/345"
                ),
                "__repr__": (
                    "TcpOptions(options=[TcpOptionMss(mss=1200), TcpOptionWscale(wscale=5), "
                    "TcpOptionNop(), TcpOptionSackperm(), TcpOptionTimestamps(tsval=123, "
                    "tsecr=345)])"
                ),
                "__bytes__": (
                    b"\x02\x04\x04\xb0\x03\x03\x05\x01\x04\x02\x08\x0a\x00\x00\x00\x7b"
                    b"\x00\x00\x01\x59"
                ),
                "mss": 1200,
                "wscale": 5,
                "sackperm": True,
                "sack": None,
                "timestamps": TcpTimestamps(tsval=123, tsecr=345),
            },
        },
        {
            "_description": "The TCP options (IV).",
            "_args": [
                TcpOptionSack(
                    blocks=[
                        TcpSackBlock(1111, 2222),
                        TcpSackBlock(3333, 4444),
                        TcpSackBlock(5555, 6666),
                    ]
                ),
                TcpOptionTimestamps(tsval=123456, tsecr=654321),
            ],
            "_results": {
                "__len__": 36,
                "__str__": "sack [1111-2222, 3333-4444, 5555-6666], timestamps 123456/654321",
                "__repr__": (
                    "TcpOptions(options=[TcpOptionSack(blocks=[TcpSackBlock(left=1111, "
                    "right=2222), TcpSackBlock(left=3333, right=4444), TcpSackBlock(left=5555, "
                    "right=6666)]), TcpOptionTimestamps(tsval=123456, tsecr=654321)])"
                ),
                "__bytes__": (
                    b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                    b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a\x08\x0a\x00\x01\xe2\x40"
                    b"\x00\x09\xfb\xf1"
                ),
                "mss": None,
                "wscale": None,
                "sackperm": None,
                "sack": [
                    TcpSackBlock(1111, 2222),
                    TcpSackBlock(3333, 4444),
                    TcpSackBlock(5555, 6666),
                ],
                "timestamps": TcpTimestamps(tsval=123456, tsecr=654321),
            },
        },
        {
            "_description": "The TCP options - ensure only first option occurrences are considered.",
            "_args": [
                TcpOptionMss(mss=11111),
                TcpOptionWscale(wscale=7),
                TcpOptionTimestamps(tsval=111, tsecr=111),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionMss(mss=22222),
                TcpOptionWscale(wscale=14),
                TcpOptionTimestamps(tsval=222, tsecr=222),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
            ],
            "_results": {
                "__len__": 40,
                "__str__": (
                    "mss 11111, wscale 7, timestamps 111/111, nop, nop, nop, "
                    "mss 22222, wscale 14, timestamps 222/222, nop, nop, nop"
                ),
                "__repr__": (
                    "TcpOptions(options=[TcpOptionMss(mss=11111), TcpOptionWscale(wscale=7), "
                    "TcpOptionTimestamps(tsval=111, tsecr=111), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionMss(mss=22222), TcpOptionWscale(wscale=14), "
                    "TcpOptionTimestamps(tsval=222, tsecr=222), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop()])"
                ),
                "__bytes__": (
                    b"\x02\x04\x2b\x67\x03\x03\x07\x08\x0a\x00\x00\x00\x6f\x00\x00\x00"
                    b"\x6f\x01\x01\x01\x02\x04\x56\xce\x03\x03\x0e\x08\x0a\x00\x00\x00"
                    b"\xde\x00\x00\x00\xde\x01\x01\x01"
                ),
                "mss": 11111,
                "wscale": 7,
                "sackperm": None,
                "sack": None,
                "timestamps": TcpTimestamps(tsval=111, tsecr=111),
            },
        },
    ]
)
class TestTcpOptionsAssembler(TestCase):
    """
    The 'TcpOptions' class assembler tests.
    """

    _description: str
    _args: list[TcpOption]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the 'TcpOptions' class object with testcase arguments.
        """

        self._tcp_options = TcpOptions(*self._args)

    def test__tcp_options__len(self) -> None:
        """
        Ensure the 'TcpOptions' class '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_options),
            self._results["__len__"],
        )

    def test__tcp_options__str(self) -> None:
        """
        Ensure the 'TcpOptions' class '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_options),
            self._results["__str__"],
        )

    def test__tcp_options__repr(self) -> None:
        """
        Ensure the 'TcpOptions' class '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_options),
            self._results["__repr__"],
        )

    def test__tcp_options__bytes(self) -> None:
        """
        Ensure the 'TcpOptions' class '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_options),
            self._results["__bytes__"],
        )

    def test__tcp_options__mss(self) -> None:
        """
        Ensure the 'TcpOptions' class 'mss' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_options.mss,
            self._results["mss"],
        )

    def test__tcp_options__wscale(self) -> None:
        """
        Ensure the 'TcpOptions' class 'wscale' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_options.wscale,
            self._results["wscale"],
        )

    def test__tcp_options__sackperm(self) -> None:
        """
        Ensure the 'TcpOptions' class 'sackperm' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_options.sackperm,
            self._results["sackperm"],
        )

    def test__tcp_options__sack(self) -> None:
        """
        Ensure the 'TcpOptions' class 'sack' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_options.sack,
            self._results["sack"],
        )

    def test__tcp_options__timestamps(self) -> None:
        """
        Ensure the 'TcpOptions' class 'timestamps' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_options.timestamps,
            self._results["timestamps"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP options (I).",
            "_args": {
                "bytes": b"\x01\x01\x01\x00",
            },
            "_results": {
                "options": TcpOptions(
                    TcpOptionNop(),
                    TcpOptionNop(),
                    TcpOptionNop(),
                    TcpOptionEol(),
                ),
            },
        },
        {
            "_description": "The TCP options (II).",
            "_args": {
                "bytes": (
                    b"\x02\x04\x05\xb4\x03\x03\x07\x04\x02\x08\x0a\x42\x3a\x35\xc7\x84"
                    b"\x74\x6b\x8e\x01\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                    b"\x41\x42\x43\x44\x45\x46\x01\x00"
                ),
            },
            "_results": {
                "options": TcpOptions(
                    TcpOptionMss(mss=1460),
                    TcpOptionWscale(wscale=7),
                    TcpOptionSackperm(),
                    TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222),
                    TcpOptionNop(),
                    TcpOptionUnknown(
                        type=TcpOptionType.from_int(255),
                        len=18,
                        data=b"0123456789ABCDEF",
                    ),
                    TcpOptionNop(),
                    TcpOptionEol(),
                ),
            },
        },
        {
            "_description": "The TCP options (III).",
            "_args": {
                "bytes": (
                    b"\x02\x04\x04\xb0\x03\x03\x05\x01\x04\x02\x08\x0a\x00\x00\x00\x7b"
                    b"\x00\x00\x01\x59"
                ),
            },
            "_results": {
                "options": TcpOptions(
                    TcpOptionMss(mss=1200),
                    TcpOptionWscale(wscale=5),
                    TcpOptionNop(),
                    TcpOptionSackperm(),
                    TcpOptionTimestamps(tsval=123, tsecr=345),
                ),
            },
        },
        {
            "_description": "The TCP options (IV).",
            "_args": {
                "bytes": (
                    b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                    b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a\x08\x0a\x00\x01\xe2\x40"
                    b"\x00\x09\xfb\xf1"
                ),
            },
            "_results": {
                "options": TcpOptions(
                    TcpOptionSack(
                        blocks=[
                            TcpSackBlock(1111, 2222),
                            TcpSackBlock(3333, 4444),
                            TcpSackBlock(5555, 6666),
                        ]
                    ),
                    TcpOptionTimestamps(tsval=123456, tsecr=654321),
                ),
            },
        },
        {
            "_description": "The TCP options with options behind the 'Eol' options.",
            "_args": {
                "bytes": b"\x01\x01\x01\x00\x01\x01",
            },
            "_results": {
                "options": TcpOptions(
                    TcpOptionNop(),
                    TcpOptionNop(),
                    TcpOptionNop(),
                    TcpOptionEol(),
                ),
            },
        },
    ]
)
class TestTcpOptionsParser(TestCase):
    """
    The 'TcpOptions' class parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp_options__from_bytes(self) -> None:
        """
        Ensure the 'TcpOptions' class parser creates the proper option object.
        """

        tcp_options = TcpOptions.from_bytes(self._args["bytes"])

        self.assertEqual(
            tcp_options,
            self._results["options"],
        )
