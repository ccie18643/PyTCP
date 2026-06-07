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
Module contains tests for the function computing Internet Checksum.

net_proto/tests/unit/lib/test__lib__inet_cksum.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Compute checksum for multiple buffers with default init.",
            "_args": [
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 55,
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 5,
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 20,
            ],
            "_kwargs": {"init": 0},
            "_results": {"inet_cksum": 0x2D2D},
        },
        {
            "_description": "Compute checksum for a 1500-byte all-ones buffer.",
            "_args": [b"\xff" * 1500],
            "_kwargs": {"init": 0},
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum for a 1500-byte all-zeros buffer.",
            "_args": [b"\x00" * 1500],
            "_kwargs": {"init": 0},
            "_results": {"inet_cksum": 0xFFFF},
        },
        {
            "_description": "Compute checksum for two unaligned non-overlapping buffers.",
            "_args": [
                b"\xf7\x24\x09" * 100,
                b"\x35\x67\x0f\x00" * 250,
            ],
            "_kwargs": {"init": 0},
            "_results": {"inet_cksum": 0xF1E5},
        },
        {
            "_description": "Compute checksum with a non-zero init value.",
            "_args": [b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" * 80],
            "_kwargs": {"init": 0x03DF},
            "_results": {"inet_cksum": 0x294E},
        },
        {
            "_description": "Compute checksum exercising carry between buffers.",
            "_args": [
                b"\xff" * 1498,
                b"\xff",
                b"\xff",
            ],
            "_kwargs": {"init": 0x0015},
            "_results": {"inet_cksum": 0xFFEA},
        },
        {
            "_description": "Compute checksum for all-zeros buffer with a large init.",
            "_args": [b"\x00" * 1500],
            "_kwargs": {"init": 0xF3FF},
            "_results": {"inet_cksum": 0x0C00},
        },
        {
            "_description": "Compute checksum for single combined buffer with init.",
            "_args": [b"\xf7\x24\x09" * 100 + b"\x35\x67\x0f\x00" * 250],
            "_kwargs": {"init": 0x7314},
            "_results": {"inet_cksum": 0x7ED1},
        },
        {
            "_description": "Compute checksum for many segmented buffers with init.",
            "_args": [
                b"\x07" * 9000,
                b"\x07" * 900,
                b"\x07" * 90,
                b"\x07" * 9,
            ],
            "_kwargs": {"init": 0xA3DC},
            "_results": {"inet_cksum": 0x1AE9},
        },
        {
            "_description": "Compute checksum with no buffers and default init.",
            "_args": [],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFFFF},
        },
        {
            "_description": "Compute checksum with no buffers and init=0xFFFF.",
            "_args": [],
            "_kwargs": {"init": 0xFFFF},
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum for a single zero byte.",
            "_args": [b"\x00"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFFFF},
        },
        {
            "_description": "Compute checksum for a single non-zero byte.",
            "_args": [b"\x01"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFEFF},
        },
        {
            "_description": "Compute checksum for two single-byte buffers exercising carry.",
            "_args": [b"\x01", b"\x02"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFEFD},
        },
        {
            "_description": "Compute checksum with carry over an empty middle buffer.",
            "_args": [b"\x01", b"", b"\x02"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFEFD},
        },
        {
            "_description": "Compute checksum with non-trivial carry over empty buffer.",
            "_args": [b"\x10", b"", b"\x20"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xEFDF},
        },
        {
            "_description": "Compute checksum for even buffer then empty then even buffer.",
            "_args": [b"\x01\x02", b"", b"\x03\x04"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFBF9},
        },
        {
            "_description": "Compute checksum for a single 0xAB 0xCD pair.",
            "_args": [b"\xab\xcd"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0x5432},
        },
        {
            "_description": "Compute checksum for a 3-byte odd-length buffer.",
            "_args": [b"\x01\x02\x03"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFBFD},
        },
        {
            "_description": "Compute checksum for a 9-byte buffer (Q + odd byte).",
            "_args": [b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xE6EB},
        },
        {
            "_description": "Compute checksum for a 10-byte buffer (Q + H).",
            "_args": [b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xE6E1},
        },
        {
            "_description": "Compute checksum for a 17-byte buffer (Q + H + odd).",
            "_args": [b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xAEB7},
        },
        {
            "_description": "Compute checksum for a 16-byte all-ones buffer (exact Q + H folds).",
            "_args": [b"\xff" * 16],
            "_kwargs": {},
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum of several 0xFF 8-byte buffers stressing 64-bit fold.",
            "_args": [b"\xff" * 8] * 5,
            "_kwargs": {},
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum for a 4-byte buffer with init=0x100.",
            "_args": [b"\x01\x02\x03\x04"],
            "_kwargs": {"init": 0x100},
            "_results": {"inet_cksum": 0xFAF9},
        },
        {
            "_description": "Compute checksum accepting a bytearray argument.",
            "_args": [bytearray(b"\xff\xff")],
            "_kwargs": {},
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum accepting a memoryview argument.",
            "_args": [memoryview(b"\x01\x00\x02\x00")],
            "_kwargs": {},
            "_results": {"inet_cksum": 0xFCFF},
        },
        {
            "_description": "Compute checksum accepting a mixed bytes/bytearray/memoryview.",
            "_args": [
                b"\x00\xff",
                bytearray(b"\xff\x00"),
                memoryview(b"\xab\xcd"),
            ],
            "_kwargs": {},
            "_results": {"inet_cksum": 0x5432},
        },
    ]
)
class TestNetProtoLibInetCksum(TestCase):
    """
    The NetProto lib Internet Checksum tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_proto__lib__inet_cksum(self) -> None:
        """
        Ensure the 'inet_cksum()' function returns the expected checksum.

        Reference: RFC 1071 (Internet checksum algorithm).
        """

        self.assertEqual(
            inet_cksum(*self._args, **self._kwargs),
            self._results["inet_cksum"],
            msg=f"Unexpected checksum for: {self._description}.",
        )


class TestNetProtoLibInetCksumRange(TestCase):
    """
    The NetProto lib Internet Checksum range invariant tests.
    """

    def test__net_proto__lib__inet_cksum__result_is_16_bit(self) -> None:
        """
        Ensure the checksum result is always a 16-bit unsigned integer.

        Reference: RFC 1071 (Internet checksum algorithm).
        """

        for sample in (
            b"",
            b"\x00",
            b"\xff" * 10,
            b"\x00\x01\x02\x03" * 4,
            b"\xaa" * 1499,
        ):
            with self.subTest(sample_len=len(sample)):
                result = inet_cksum(sample)
                self.assertGreaterEqual(
                    result,
                    0,
                    msg="Checksum result must be non-negative.",
                )
                self.assertLessEqual(
                    result,
                    0xFFFF,
                    msg="Checksum result must fit in 16 bits.",
                )

    def test__net_proto__lib__inet_cksum__verification_pattern(self) -> None:
        """
        Ensure appending the computed checksum word yields a checksum of zero,
        matching the RFC 1071 verification pattern.

        Reference: RFC 1071 (Internet checksum algorithm).
        """

        data = b"\x45\x00\x00\x28\x12\x34\x40\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"

        cksum = inet_cksum(data)
        verified = inet_cksum(data, cksum.to_bytes(2, "big"))

        self.assertEqual(
            verified,
            0x0000,
            msg="Appending the checksum to the data must verify to zero.",
        )

    def test__net_proto__lib__inet_cksum__init_parameter_is_keyword_only(
        self,
    ) -> None:
        """
        Ensure the 'init' parameter must be passed as a keyword argument.

        Reference: RFC 1071 (Internet checksum algorithm).
        """

        with self.assertRaises(TypeError):
            inet_cksum(b"\x00\x00", 0x1234)  # type: ignore[arg-type]
