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
Module contains tests for the TCP Sack (Selective ACK) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__sack.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TCP__OPTION__SACK__MAX_BLOCK_NUM,
    TcpIntegrityError,
    TcpOptionSack,
    TcpOptionType,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp__option import TCP__OPTION__LEN
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionSackAsserts(TestCase):
    """
    The TCP Sack option constructor argument assert tests.
    """

    def test__tcp__option__sack__blocks__too_many(self) -> None:
        """
        Ensure the TCP Sack option constructor raises an exception when
        the provided 'blocks' argument has more than
        TCP__OPTION__SACK__MAX_BLOCK_NUM elements.

        Reference: RFC 2018 §3 (max 4 SACK blocks per packet).
        """

        value = TCP__OPTION__SACK__MAX_BLOCK_NUM + 1
        blocks = [TcpSackBlock(0, 0)] * value

        with self.assertRaises(AssertionError) as error:
            TcpOptionSack(blocks)

        self.assertEqual(
            str(error.exception),
            (f"The 'blocks' field must have at most {TCP__OPTION__SACK__MAX_BLOCK_NUM} " f"elements. Got: {value!r}"),
            msg="Unexpected assertion message for 'blocks' over TCP__OPTION__SACK__MAX_BLOCK_NUM.",
        )

    def test__tcp__option__sack__blocks__exact_max_accepted(self) -> None:
        """
        Ensure the TCP Sack option constructor accepts exactly
        TCP__OPTION__SACK__MAX_BLOCK_NUM blocks (the boundary).

        Reference: RFC 2018 §3 (max 4 SACK blocks per packet).
        """

        blocks = [TcpSackBlock(0, 0)] * TCP__OPTION__SACK__MAX_BLOCK_NUM

        option = TcpOptionSack(blocks)

        self.assertEqual(
            len(option.blocks),
            TCP__OPTION__SACK__MAX_BLOCK_NUM,
            msg="Option must accept exactly TCP__OPTION__SACK__MAX_BLOCK_NUM blocks.",
        )


class TestTcpSackBlockAsserts(TestCase):
    """
    The TCP Sack block constructor uint32-bounds tests. The wire
    path always trims each edge to 4 bytes via 'int.from_bytes',
    so these asserts catch programmer error at construction with
    a clear AssertionError instead of an opaque struct.error
    deep inside `__buffer__` serialization.
    """

    def test__tcp__sack_block__left__over_uint32(self) -> None:
        """
        Ensure the TcpSackBlock constructor refuses a 'left' value
        outside the uint32 range — the wire-format edge is a
        32-bit unsigned integer.

        Reference: RFC 2018 §3 (SACK block edges are 32-bit unsigned).
        """

        with self.assertRaises(AssertionError) as error:
            TcpSackBlock(left=2**32, right=0)

        self.assertIn(
            "must be a 32-bit unsigned integer",
            str(error.exception),
            msg="AssertionError must cite the uint32 bound for 'left'.",
        )

    def test__tcp__sack_block__right__over_uint32(self) -> None:
        """
        Ensure the TcpSackBlock constructor refuses a 'right'
        value outside the uint32 range — the wire-format edge is
        a 32-bit unsigned integer.

        Reference: RFC 2018 §3 (SACK block edges are 32-bit unsigned).
        """

        with self.assertRaises(AssertionError) as error:
            TcpSackBlock(left=0, right=2**32)

        self.assertIn(
            "must be a 32-bit unsigned integer",
            str(error.exception),
            msg="AssertionError must cite the uint32 bound for 'right'.",
        )

    def test__tcp__sack_block__uint32_max_accepted(self) -> None:
        """
        Ensure the TcpSackBlock constructor accepts both edges at
        the uint32 boundary (2**32 - 1 = 4294967295). The wire
        path tolerates these values (a full-wraparound SACK block
        is well-formed under sequence-number modular arithmetic).

        Reference: RFC 2018 §3 (32-bit edges; wraparound permitted).
        """

        # Should not raise.
        block = TcpSackBlock(left=2**32 - 1, right=2**32 - 1)

        self.assertEqual(
            block.left,
            2**32 - 1,
            msg="Maximum-valid uint32 left edge must be accepted at construction.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Sack option with zero blocks (empty Sack).",
            "_blocks": [],
            "_results": {
                "__len__": 2,
                "__str__": "sack []",
                "__repr__": "TcpOptionSack(blocks=[])",
                # TCP Sack option wire frame (2 bytes):
                #   Byte 0 : 0x05 -> type=TcpOptionType.SACK (5)
                #   Byte 1 : 0x02 -> len=2 (header only, no blocks)
                "__bytes__": b"\x05\x02",
                "length": TCP__OPTION__LEN,
            },
        },
        {
            "_description": "TCP Sack option with a single block carrying maximum 32-bit edges.",
            "_blocks": [TcpSackBlock(4294967295, 4294967295)],
            "_results": {
                "__len__": 10,
                "__str__": "sack [4294967295-4294967295]",
                "__repr__": "TcpOptionSack(blocks=[TcpSackBlock(left=4294967295, right=4294967295)])",
                # TCP Sack option wire frame (10 bytes = 2-byte header + 1x 8-byte block):
                #   Byte 0      : 0x05       -> type=TcpOptionType.SACK (5)
                #   Byte 1      : 0x0a       -> len=10 (header + 1 block)
                #   Bytes 2-5   : 0xffffffff -> block[0].left=4294967295 (UINT_32__MAX)
                #   Bytes 6-9   : 0xffffffff -> block[0].right=4294967295
                "__bytes__": b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
                "length": TCP__OPTION__LEN + 8 * 1,
            },
        },
        {
            "_description": "TCP Sack option with three blocks (typical Sack reply).",
            "_blocks": [
                TcpSackBlock(1111, 2222),
                TcpSackBlock(3333, 4444),
                TcpSackBlock(5555, 6666),
            ],
            "_results": {
                "__len__": 26,
                "__str__": "sack [1111-2222, 3333-4444, 5555-6666]",
                "__repr__": (
                    "TcpOptionSack(blocks=[TcpSackBlock(left=1111, right=2222), "
                    "TcpSackBlock(left=3333, right=4444), TcpSackBlock(left=5555, "
                    "right=6666)])"
                ),
                # TCP Sack option wire frame (26 bytes = 2-byte header + 3x 8-byte blocks):
                #   Byte 0      : 0x05       -> type=TcpOptionType.SACK (5)
                #   Byte 1      : 0x1a       -> len=26 (header + 3 blocks)
                #   Bytes 2-5   : 0x00000457 -> block[0].left=1111
                #   Bytes 6-9   : 0x000008ae -> block[0].right=2222
                #   Bytes 10-13 : 0x00000d05 -> block[1].left=3333
                #   Bytes 14-17 : 0x0000115c -> block[1].right=4444
                #   Bytes 18-21 : 0x000015b3 -> block[2].left=5555
                #   Bytes 22-25 : 0x00001a0a -> block[2].right=6666
                "__bytes__": (
                    b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                    b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a"
                ),
                "length": TCP__OPTION__LEN + 8 * 3,
            },
        },
        {
            "_description": "TCP Sack option with TCP__OPTION__SACK__MAX_BLOCK_NUM blocks (max 4).",
            "_blocks": [
                TcpSackBlock(111, 222),
                TcpSackBlock(333, 444),
                TcpSackBlock(555, 666),
                TcpSackBlock(777, 888),
            ],
            "_results": {
                "__len__": 34,
                "__str__": "sack [111-222, 333-444, 555-666, 777-888]",
                "__repr__": (
                    "TcpOptionSack(blocks=[TcpSackBlock(left=111, right=222), "
                    "TcpSackBlock(left=333, right=444), TcpSackBlock(left=555, "
                    "right=666), TcpSackBlock(left=777, right=888)])"
                ),
                # TCP Sack option wire frame (34 bytes = 2-byte header + 4x 8-byte blocks):
                #   Byte 0      : 0x05       -> type=TcpOptionType.SACK (5)
                #   Byte 1      : 0x22       -> len=34 (header + 4 blocks)
                #   Bytes 2-5   : 0x0000006f -> block[0].left=111
                #   Bytes 6-9   : 0x000000de -> block[0].right=222
                #   Bytes 10-13 : 0x0000014d -> block[1].left=333
                #   Bytes 14-17 : 0x000001bc -> block[1].right=444
                #   Bytes 18-21 : 0x0000022b -> block[2].left=555
                #   Bytes 22-25 : 0x0000029a -> block[2].right=666
                #   Bytes 26-29 : 0x00000309 -> block[3].left=777
                #   Bytes 30-33 : 0x00000378 -> block[3].right=888
                "__bytes__": (
                    b"\x05\x22\x00\x00\x00\x6f\x00\x00\x00\xde\x00\x00\x01\x4d\x00\x00"
                    b"\x01\xbc\x00\x00\x02\x2b\x00\x00\x02\x9a\x00\x00\x03\x09\x00\x00"
                    b"\x03\x78"
                ),
                "length": TCP__OPTION__LEN + 8 * 4,
            },
        },
    ]
)
class TestTcpOptionSackAssembler(TestCase):
    """
    The TCP Sack option assembler tests.
    """

    _description: str
    _blocks: list[TcpSackBlock]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP Sack option from the parametrized block list.
        """

        self._option = TcpOptionSack(self._blocks)

    def test__tcp__option__sack__len(self) -> None:
        """
        Ensure '__len__()' returns the expected total option length
        (2-byte header + 8 bytes per block).

        Reference: RFC 2018 §3 (SACK option length = 2 + 8N).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__sack__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__sack__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__sack__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 2018 §3 (SACK option wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__sack__blocks(self) -> None:
        """
        Ensure the 'blocks' field exposes the provided block list.

        Reference: RFC 2018 §3 (SACK block list).
        """

        self.assertEqual(
            self._option.blocks,
            self._blocks,
            msg=f"Unexpected 'blocks' field for case: {self._description}",
        )

    def test__tcp__option__sack__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.SACK.

        Reference: RFC 2018 §3 (SACK option Kind = 5).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.SACK,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__sack__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__LEN + 8 * num_blocks.

        Reference: RFC 2018 §3 (SACK option length = 2 + 8N).
        """

        self.assertEqual(
            self._option.len,
            self._results["length"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Sack option, zero blocks (empty Sack) with trailing bytes.",
            "_args": [b"\x05\x02" + b"ZH0PA"],
            "_expected": TcpOptionSack(blocks=[]),
        },
        {
            "_description": "TCP Sack option, single block with trailing bytes.",
            "_args": [b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff\xff" + b"ZH0PA"],
            "_expected": TcpOptionSack(blocks=[TcpSackBlock(4294967295, 4294967295)]),
        },
        {
            "_description": "TCP Sack option, three blocks with trailing bytes.",
            "_args": [
                b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a" + b"ZH0PA"
            ],
            "_expected": TcpOptionSack(
                blocks=[
                    TcpSackBlock(1111, 2222),
                    TcpSackBlock(3333, 4444),
                    TcpSackBlock(5555, 6666),
                ]
            ),
        },
        {
            "_description": "TCP Sack option, four blocks (max) with trailing bytes.",
            "_args": [
                b"\x05\x22\x00\x00\x00\x6f\x00\x00\x00\xde\x00\x00\x01\x4d\x00\x00"
                b"\x01\xbc\x00\x00\x02\x2b\x00\x00\x02\x9a\x00\x00\x03\x09\x00\x00"
                b"\x03\x78" + b"ZH0PA"
            ],
            "_expected": TcpOptionSack(
                blocks=[
                    TcpSackBlock(111, 222),
                    TcpSackBlock(333, 444),
                    TcpSackBlock(555, 666),
                    TcpSackBlock(777, 888),
                ]
            ),
        },
    ]
)
class TestTcpOptionSackParser(TestCase):
    """
    The TCP Sack option parser positive tests.
    """

    _description: str
    _args: list[Any]
    _expected: TcpOptionSack

    def test__tcp__option__sack__from_buffer(self) -> None:
        """
        Ensure from_buffer parses the Sack wire frame into the expected
        TcpOptionSack (trailing bytes must be ignored).

        Reference: RFC 2018 §3 (SACK option wire format).
        """

        option = TcpOptionSack.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._expected,
            msg=f"Unexpected parsed option for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "TCP Sack option, buffer shorter than TCP__OPTION__LEN (2).",
            "_args": [b"\x05"],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Sack option must be 2 bytes. Got: 1",
            },
        },
        {
            "_description": "TCP Sack option, buffer empty (zero-length).",
            "_args": [b""],
            "_results": {
                "error": AssertionError,
                "error_message": "The minimum length of the TCP Sack option must be 2 bytes. Got: 0",
            },
        },
        {
            "_description": "TCP Sack option, buffer 'type' byte is not TcpOptionType.SACK.",
            "_args": [b"\xff\x02"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Sack option type must be {TcpOptionType.SACK!r}. " f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "TCP Sack option, buffer 'type' byte is below TcpOptionType.SACK.",
            "_args": [b"\x04\x02"],
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Sack option type must be {TcpOptionType.SACK!r}. " f"Got: {TcpOptionType.from_int(4)!r}"
                ),
            },
        },
        {
            "_description": "TCP Sack option, declared 'len' exceeds provided buffer size.",
            "_args": [b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sack option length value must be "
                    "less than or equal to the length of provided bytes (9). Got: 10"
                ),
            },
        },
        {
            "_description": "TCP Sack option, (len - 2) is not a multiple of 8 (malformed block alignment).",
            "_args": [b"\x05\x0b\xff\xff\xff\xff\xff\xff\xff\xff\x00"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sack option blocks length value " "must be a multiple of 8. Got: 9"
                ),
            },
        },
        {
            # len=4 makes the block-data region (len - 2) = 2 bytes, which
            # is not a multiple of 8. The 'Got: 2' value pins the
            # 'buffer[1] - TCP__OPTION__LEN' subtraction: a '^' (xor)
            # corruption would compute 4 ^ 2 = 6 and report 'Got: 6'.
            "_description": "TCP Sack option, (len - 2) = 2 is not a multiple of 8 (subtraction-pinning frame).",
            "_args": [b"\x05\x04\xff\xff"],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sack option blocks length value " "must be a multiple of 8. Got: 2"
                ),
            },
        },
        {
            "_description": "TCP Sack option, 5 blocks (one above the 4-block ceiling).",
            # Wire: type=5, len=42 (= 2 + 5*8), then 5 zero-filled 8-byte
            # blocks. The existing length-and-modulo integrity checks
            # accept this frame; before the fix, from_buffer would build
            # 5 TcpSackBlock instances and the __post_init__ assert on
            # len(blocks) <= 4 would trip a bare AssertionError that
            # leaked past the IP RX handler's PacketValidationError catch.
            "_args": [
                b"\x05\x2a"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            ],
            "_results": {
                "error": TcpIntegrityError,
                "error_message": ("[INTEGRITY ERROR][TCP] The TCP Sack option must carry at most 4 blocks. Got: 5"),
            },
        },
    ]
)
class TestTcpOptionSackParserFailures(TestCase):
    """
    The TCP Sack option parser failure-path tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__tcp__option__sack__from_buffer__error(self) -> None:
        """
        Ensure from_buffer raises the expected exception with the expected
        message for each malformed buffer.

        Reference: RFC 2018 §3 (SACK option wire format).
        """

        with self.assertRaises(self._results["error"]) as error:
            TcpOptionSack.from_buffer(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Unexpected error message for case: {self._description}",
        )
