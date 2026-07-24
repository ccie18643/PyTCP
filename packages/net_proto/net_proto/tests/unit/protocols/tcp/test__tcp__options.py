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

net_proto/tests/unit/protocols/tcp/test__tcp__options.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TcpAssembler,
    TcpOptionEol,
    TcpOptionMss,
    TcpOptionNop,
    TcpOptions,
    TcpOptionSack,
    TcpOptionSackperm,
    TcpOptionTimestamps,
    TcpOptionType,
    TcpOptionUnknown,
    TcpOptionWscale,
    TcpSackBlock,
    TcpTimestamps,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError
from net_proto.protocols.tcp.tcp__header import TCP__HEADER__LEN, TCP__MIN_MSS
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "TcpOptions with three Nop paddings and a trailing Eol (no feature options).",
            "_args": [
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionEol(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "nop, nop, nop, eol",
                "__repr__": "TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionEol()])",
                # TCP options wire frame (4 bytes):
                #   Byte 0 : 0x01 -> TcpOptionNop
                #   Byte 1 : 0x01 -> TcpOptionNop
                #   Byte 2 : 0x01 -> TcpOptionNop
                #   Byte 3 : 0x00 -> TcpOptionEol
                "__bytes__": b"\x01\x01\x01\x00",
                "mss": None,
                "wscale": None,
                "sackperm": None,
                "sack": None,
                "timestamps": None,
            },
        },
        {
            "_description": ("TcpOptions with Mss, Wscale, Sackperm, Timestamps, Unknown, and trailing Eol (max 40)."),
            "_args": [
                TcpOptionMss(mss=1460),
                TcpOptionWscale(wscale=7),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222),
                TcpOptionNop(),
                TcpOptionUnknown(
                    type=TcpOptionType.from_int(255),
                    data=b"0123456789ABCDEF",
                ),
                TcpOptionNop(),
                TcpOptionEol(),
            ],
            "_results": {
                "__len__": 40,
                "__str__": (
                    "mss 1460, wscale 7, sackperm, timestamps 1111111111/2222222222, " "nop, unk-255-18, nop, eol"
                ),
                "__repr__": (
                    "TcpOptions(options=[TcpOptionMss(mss=1460), TcpOptionWscale(wscale=7), "
                    "TcpOptionSackperm(), TcpOptionTimestamps(tsval=1111111111, "
                    "tsecr=2222222222), TcpOptionNop(), TcpOptionUnknown(type=<TcpOptionType."
                    "UNKNOWN_255: 255>, len=18, data=b'0123456789ABCDEF'), TcpOptionNop(), "
                    "TcpOptionEol()])"
                ),
                # TCP options wire frame (40 bytes, max TCP__OPTIONS__MAX_LEN):
                #   Bytes 0-3   : 0x02 0x04 0x05 0xb4       -> Mss option, mss=1460
                #   Bytes 4-6   : 0x03 0x03 0x07            -> Wscale option, wscale=7
                #   Bytes 7-8   : 0x04 0x02                 -> Sackperm option
                #   Bytes 9-18  : 0x08 0x0a 0x423a35c7 0x84746b8e
                #                 -> Timestamps option, tsval=1111111111, tsecr=2222222222
                #   Byte 19     : 0x01                      -> Nop padding
                #   Bytes 20-37 : 0xff 0x12 b"0123456789ABCDEF"
                #                 -> Unknown option, type=255, len=18
                #   Byte 38     : 0x01                      -> Nop padding
                #   Byte 39     : 0x00                      -> Eol terminator
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
            "_description": "TcpOptions with Mss, Wscale, Nop, Sackperm, Timestamps (no terminating Eol).",
            "_args": [
                TcpOptionMss(mss=1200),
                TcpOptionWscale(wscale=5),
                TcpOptionNop(),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=123, tsecr=345),
            ],
            "_results": {
                "__len__": 20,
                "__str__": "mss 1200, wscale 5, nop, sackperm, timestamps 123/345",
                "__repr__": (
                    "TcpOptions(options=[TcpOptionMss(mss=1200), TcpOptionWscale(wscale=5), "
                    "TcpOptionNop(), TcpOptionSackperm(), TcpOptionTimestamps(tsval=123, "
                    "tsecr=345)])"
                ),
                # TCP options wire frame (20 bytes):
                #   Bytes 0-3   : 0x02 0x04 0x04 0xb0       -> Mss option, mss=1200
                #   Bytes 4-6   : 0x03 0x03 0x05            -> Wscale option, wscale=5
                #   Byte 7      : 0x01                      -> Nop padding
                #   Bytes 8-9   : 0x04 0x02                 -> Sackperm option
                #   Bytes 10-19 : 0x08 0x0a 0x0000007b 0x00000159
                #                 -> Timestamps option, tsval=123, tsecr=345
                "__bytes__": (b"\x02\x04\x04\xb0\x03\x03\x05\x01\x04\x02\x08\x0a\x00\x00\x00\x7b" b"\x00\x00\x01\x59"),
                "mss": 1200,
                "wscale": 5,
                "sackperm": True,
                "sack": None,
                "timestamps": TcpTimestamps(tsval=123, tsecr=345),
            },
        },
        {
            "_description": "TcpOptions with a 3-block Sack followed by Timestamps.",
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
                # TCP options wire frame (36 bytes):
                #   Bytes 0-25  : 0x05 0x1a + 3x 8-byte Sack blocks
                #                 -> Sack option, blocks=[1111-2222, 3333-4444, 5555-6666]
                #   Bytes 26-35 : 0x08 0x0a 0x0001e240 0x0009fbf1
                #                 -> Timestamps option, tsval=123456, tsecr=654321
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
            "_description": "TcpOptions with duplicate Mss, Wscale, and Timestamps: only first occurrences exposed.",
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
                # TCP options wire frame (40 bytes):
                #   Bytes 0-3   : 0x02 0x04 0x2b 0x67       -> Mss, mss=11111 (first)
                #   Bytes 4-6   : 0x03 0x03 0x07            -> Wscale, wscale=7 (first)
                #   Bytes 7-16  : 0x08 0x0a 0x0000006f 0x0000006f
                #                 -> Timestamps, tsval=111, tsecr=111 (first)
                #   Bytes 17-19 : 0x01 0x01 0x01            -> Nop, Nop, Nop
                #   Bytes 20-23 : 0x02 0x04 0x56 0xce       -> Mss, mss=22222 (duplicate)
                #   Bytes 24-26 : 0x03 0x03 0x0e            -> Wscale, wscale=14 (duplicate)
                #   Bytes 27-36 : 0x08 0x0a 0x000000de 0x000000de
                #                 -> Timestamps, tsval=222, tsecr=222 (duplicate)
                #   Bytes 37-39 : 0x01 0x01 0x01            -> Nop, Nop, Nop
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
        {
            "_description": "Empty TcpOptions container.",
            "_args": [],
            "_results": {
                "__len__": 0,
                "__str__": "",
                "__repr__": "TcpOptions(options=[])",
                "__bytes__": b"",
                "mss": None,
                "wscale": None,
                "sackperm": None,
                "sack": None,
                "timestamps": None,
            },
        },
    ]
)
class TestTcpOptionsAssembler(TestCase):
    """
    The 'TcpOptions' container assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TcpOptions container from the parametrized option list.
        """

        self._tcp_options = TcpOptions(*self._args)

    def test__tcp_options__len(self) -> None:
        """
        Ensure '__len__()' returns the total serialized options length.

        Reference: RFC 9293 §3.1 (TCP options block).
        """

        self.assertEqual(
            len(self._tcp_options),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp_options__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 9293 §3.1 (TCP options block).
        """

        self.assertEqual(
            str(self._tcp_options),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp_options__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9293 §3.1 (TCP options block).
        """

        self.assertEqual(
            repr(self._tcp_options),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp_options__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 9293 §3.1 (TCP options block).
        """

        self.assertEqual(
            bytes(self._tcp_options),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp_options__mss(self) -> None:
        """
        Ensure the 'mss' property returns the first Mss option value (or
        None if no Mss option is present).

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        self.assertEqual(
            self._tcp_options.mss,
            self._results["mss"],
            msg=f"Unexpected 'mss' for case: {self._description}",
        )

    def test__tcp_options__wscale(self) -> None:
        """
        Ensure the 'wscale' property returns the first Wscale option value
        (or None if no Wscale option is present).

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        self.assertEqual(
            self._tcp_options.wscale,
            self._results["wscale"],
            msg=f"Unexpected 'wscale' for case: {self._description}",
        )

    def test__tcp_options__sackperm(self) -> None:
        """
        Ensure the 'sackperm' property returns True when a Sackperm option
        is present and None otherwise.

        Reference: RFC 2018 §2 (SACK-Permitted option — kind 4).
        """

        self.assertEqual(
            self._tcp_options.sackperm,
            self._results["sackperm"],
            msg=f"Unexpected 'sackperm' for case: {self._description}",
        )

    def test__tcp_options__sack(self) -> None:
        """
        Ensure the 'sack' property returns the first Sack option block
        list (or None if no Sack option is present).

        Reference: RFC 2018 §3 (SACK option — kind 5).
        """

        self.assertEqual(
            self._tcp_options.sack,
            self._results["sack"],
            msg=f"Unexpected 'sack' for case: {self._description}",
        )

    def test__tcp_options__timestamps(self) -> None:
        """
        Ensure the 'timestamps' property returns the first Timestamps
        option value (or None if no Timestamps option is present).

        Reference: RFC 7323 §3 (Timestamps option — kind 8).
        """

        self.assertEqual(
            self._tcp_options.timestamps,
            self._results["timestamps"],
            msg=f"Unexpected 'timestamps' for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "TcpOptions parse: three Nops plus trailing Eol.",
            "_buffer": b"\x01\x01\x01\x00",
            "_expected": TcpOptions(
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionEol(),
            ),
        },
        {
            "_description": "TcpOptions parse: Mss, Wscale, Sackperm, Timestamps, Nop, Unknown, Nop, Eol.",
            "_buffer": (
                b"\x02\x04\x05\xb4\x03\x03\x07\x04\x02\x08\x0a\x42\x3a\x35\xc7\x84"
                b"\x74\x6b\x8e\x01\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x41\x42\x43\x44\x45\x46\x01\x00"
            ),
            "_expected": TcpOptions(
                TcpOptionMss(mss=1460),
                TcpOptionWscale(wscale=7),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222),
                TcpOptionNop(),
                TcpOptionUnknown(
                    type=TcpOptionType.from_int(255),
                    data=b"0123456789ABCDEF",
                ),
                TcpOptionNop(),
                TcpOptionEol(),
            ),
        },
        {
            "_description": "TcpOptions parse: Mss, Wscale, Nop, Sackperm, Timestamps (no trailing Eol).",
            "_buffer": (b"\x02\x04\x04\xb0\x03\x03\x05\x01\x04\x02\x08\x0a\x00\x00\x00\x7b" b"\x00\x00\x01\x59"),
            "_expected": TcpOptions(
                TcpOptionMss(mss=1200),
                TcpOptionWscale(wscale=5),
                TcpOptionNop(),
                TcpOptionSackperm(),
                TcpOptionTimestamps(tsval=123, tsecr=345),
            ),
        },
        {
            "_description": "TcpOptions parse: 3-block Sack followed by Timestamps.",
            "_buffer": (
                b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a\x08\x0a\x00\x01\xe2\x40"
                b"\x00\x09\xfb\xf1"
            ),
            "_expected": TcpOptions(
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
        {
            "_description": "TcpOptions parse: bytes after the Eol are discarded.",
            "_buffer": b"\x01\x01\x01\x00\x01\x01",
            "_expected": TcpOptions(
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionEol(),
            ),
        },
        {
            "_description": "TcpOptions parse: empty buffer yields empty container.",
            "_buffer": b"",
            "_expected": TcpOptions(),
        },
    ]
)
class TestTcpOptionsParser(TestCase):
    """
    The 'TcpOptions' container parser tests.
    """

    _description: str
    _buffer: bytes
    _expected: TcpOptions

    def test__tcp_options__from_buffer(self) -> None:
        """
        Ensure 'TcpOptions.from_buffer()' parses the wire frame into the
        expected TcpOptions container.

        Reference: RFC 9293 §3.1 (TCP options block).
        """

        tcp_options = TcpOptions.from_buffer(self._buffer)

        self.assertEqual(
            tcp_options,
            self._expected,
            msg=f"Unexpected parsed options for case: {self._description}",
        )


class TestTcpOptionsValidateIntegrity(TestCase):
    """
    The 'TcpOptions.validate_integrity()' option-walker tests.
    """

    def test__tcp_options__validate_integrity__case2_len_two_accepted(self) -> None:
        """
        Ensure the walker accepts a Case-2 option whose Length byte is
        exactly 2 (the inclusive minimum, e.g. SACK-Permitted), pinning
        the 'Length < 2' rejection against a '<= 2' over-rejection.

        Reference: RFC 9293 §3.2 (Case-2 Length covers Kind + Length, i.e. >= 2).
        """

        # 20-byte header region followed by SACK-Permitted (Kind 4, Len 2).
        frame = bytes(TCP__HEADER__LEN) + b"\x04\x02"

        TcpOptions.validate_integrity(frame=frame, hlen=TCP__HEADER__LEN + 2)

    def test__tcp_options__validate_integrity__option_filling_hlen_accepted(self) -> None:
        """
        Ensure the walker accepts an option whose bytes end exactly at
        the header-length boundary, pinning the 'offset > hlen' overrun
        check against a '>= hlen' over-rejection.

        Reference: RFC 9293 §3.2 (an option may extend up to, not past, Data Offset).
        """

        # 20-byte header + MSS (Kind 2, Len 4) ending exactly at hlen=24.
        frame = bytes(TCP__HEADER__LEN) + b"\x02\x04\x05\xb4"

        TcpOptions.validate_integrity(frame=frame, hlen=TCP__HEADER__LEN + 4)

    def test__tcp_options__validate_integrity__eol_terminates_walk(self) -> None:
        """
        Ensure the walker stops at an EOL (Kind 0) byte and does not
        interpret the bytes after it, pinning the 'frame[offset] == EOL'
        terminator detection against a '< EOL' relaxation that would
        never match and walk into the trailing bytes.

        Reference: RFC 9293 §3.2 (EOL terminates the option list).
        """

        # 20-byte header + EOL (0x00) + a trailing byte (0x99) that, if
        # the walk did NOT stop at EOL, would be read as an over-long
        # option length and raise.
        frame = bytes(TCP__HEADER__LEN) + b"\x00\x99"

        TcpOptions.validate_integrity(frame=frame, hlen=TCP__HEADER__LEN + 2)

    def test__tcp_options__validate_integrity__case2_len_below_two_raises(self) -> None:
        """
        Ensure the walker raises when a Case-2 option carries a Length
        byte below 2.

        Reference: RFC 9293 §3.2 (Case-2 Length must be at least 2).
        """

        frame = bytes(TCP__HEADER__LEN) + b"\x04\x01"

        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptions.validate_integrity(frame=frame, hlen=TCP__HEADER__LEN + 2)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][TCP] The TCP option length must be greater than 1. Got: 1.",
            msg="Unexpected integrity-error message for a Case-2 option length below 2.",
        )

    def test__tcp_options__validate_integrity__option_past_hlen_raises(self) -> None:
        """
        Ensure the walker raises when an option's Length advances the
        cumulative offset past the header-length boundary.

        Reference: RFC 9293 §3.2 (an option must not extend past Data Offset).
        """

        # MSS option claiming Len 6 starting at offset 20 would end at
        # offset 26, past hlen=22.
        frame = bytes(TCP__HEADER__LEN) + b"\x02\x06\x05\xb4"

        with self.assertRaises(TcpIntegrityError):
            TcpOptions.validate_integrity(frame=frame, hlen=TCP__HEADER__LEN + 2)


class TestTcpOptionsPropertiesDefaults(TestCase):
    """
    The 'TcpOptionsProperties' mixin default-value tests (the
    absent-option fallbacks exposed on the Tcp packet surface).
    """

    def test__tcp_options__properties__mss_defaults_to_min_mss(self) -> None:
        """
        Ensure the 'mss' property returns TCP__MIN_MSS (the literal 536,
        RFC 879 minimum recommended MSS) when no MSS option is present,
        pinning both the 'mss is None' absent-option branch and the
        value of the TCP__MIN_MSS default constant.

        Reference: RFC 9293 §3.7.1 (default MSS when the option is absent).
        Reference: RFC 879 §1 (default MSS of 536 octets).
        """

        # The expected value is the literal 536, NOT the imported
        # TCP__MIN_MSS constant — asserting against the constant would
        # move with a mutation of its definition and fail to pin it.
        self.assertEqual(
            TcpAssembler().mss,
            536,
            msg="The 'mss' property must fall back to the literal default MSS 536 when no MSS option is present.",
        )
        self.assertEqual(
            TCP__MIN_MSS,
            536,
            msg="TCP__MIN_MSS must be the RFC 879 default of 536 octets.",
        )

    def test__tcp_options__properties__mss_returns_present_value(self) -> None:
        """
        Ensure the 'mss' property returns the option's value when an MSS
        option is present, pinning the non-absent branch.

        Reference: RFC 9293 §3.7.1 (Maximum Segment Size option — kind 2).
        """

        assembler = TcpAssembler(tcp__options=TcpOptions(TcpOptionMss(mss=1460)))

        self.assertEqual(
            assembler.mss,
            1460,
            msg="The 'mss' property must return the present MSS option value, not the default.",
        )

    def test__tcp_options__properties__wscale_defaults_to_zero(self) -> None:
        """
        Ensure the 'wscale' property returns 0 when no Window Scale
        option is present, pinning the 'wscale or 0' absent-option
        fallback against an 'and 0' relaxation.

        Reference: RFC 7323 §2 (no window scaling when the option is absent).
        """

        self.assertEqual(
            TcpAssembler().wscale,
            0,
            msg="The 'wscale' property must fall back to 0 when no Window Scale option is present.",
        )

    def test__tcp_options__properties__wscale_returns_present_value(self) -> None:
        """
        Ensure the 'wscale' property returns the option's value when a
        Window Scale option is present, pinning the truthy branch of the
        'wscale or 0' fallback.

        Reference: RFC 7323 §2 (Window Scale option — kind 3).
        """

        # A lone Wscale option is 3 bytes; pad with a Nop so the options
        # block is 4-byte aligned (the assembler enforces alignment).
        assembler = TcpAssembler(tcp__options=TcpOptions(TcpOptionWscale(wscale=7), TcpOptionNop()))

        self.assertEqual(
            assembler.wscale,
            7,
            msg="The 'wscale' property must return the present Window Scale option value.",
        )
