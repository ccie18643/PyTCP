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
Module contains tests for the IPv4 Ssrr (Strict Source and Record Route)
option code.

net_proto/tests/unit/protocols/ip4/test__ip4__option__ssrr.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto import (
    IP4__OPTION__SSRR__HDR_LEN,
    IP4__OPTION__SSRR__SLOT_LEN,
    Ip4IntegrityError,
    Ip4OptionSsrr,
    Ip4OptionType,
)


class TestIp4OptionSsrrAsserts(TestCase):
    """
    The IPv4 Ssrr option constructor argument assert tests.
    """

    def test__ip4__option__ssrr__pointer__under_min(self) -> None:
        """
        Ensure the IPv4 Ssrr option constructor rejects a 'pointer' value
        below the canonical minimum of 4.

        Reference: RFC 791 §3.1 (Source Routing pointer minimum is 4).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionSsrr(pointer=3, route=[Ip4Address("10.0.0.1")])

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be at least 4. Got: 3",
            msg="Unexpected assertion message for 'pointer' < 4.",
        )

    def test__ip4__option__ssrr__pointer__misaligned(self) -> None:
        """
        Ensure the IPv4 Ssrr option constructor rejects a 'pointer' that
        is not aligned to the 4-byte slot boundary.

        Reference: RFC 791 §3.1 (route data is a list of 4-byte addresses).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionSsrr(pointer=5, route=[Ip4Address("10.0.0.1")])

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be aligned to the 4-byte slot boundary. Got: 5",
            msg="Unexpected assertion message for misaligned 'pointer'.",
        )

    def test__ip4__option__ssrr__route__empty(self) -> None:
        """
        Ensure the IPv4 Ssrr option constructor rejects an empty
        'route' list.

        Reference: RFC 791 §3.1 (Strict Source Route minimum length is 7).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionSsrr(pointer=4, route=[])

        self.assertEqual(
            str(error.exception),
            "The 'route' field must have at least 1 entry. Got: 0",
            msg="Unexpected assertion message for empty 'route'.",
        )

    def test__ip4__option__ssrr__route__overflows_uint8_length(self) -> None:
        """
        Ensure the IPv4 Ssrr option constructor rejects a 'route'
        list whose total option length (3-byte header + 4-byte slot
        per entry) would overflow the single-octet option-length
        byte.

        Reference: RFC 791 §3.1 (option-length byte is one octet).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionSsrr(pointer=4, route=[Ip4Address("10.0.0.1")] * 64)

        self.assertIn(
            "must fit in a single uint8 length byte",
            str(error.exception),
            msg="AssertionError must cite the uint8 length-byte overflow.",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 Ssrr option with one hop, pointer at start.",
            "_pointer": 4,
            "_route": [Ip4Address("10.0.0.1")],
            "_results": {
                "__len__": 7,
                "__str__": "ssrr [10.0.0.1] ptr=4",
                "__repr__": ("Ip4OptionSsrr(pointer=4, route=[Ip4Address('10.0.0.1')])"),
                # IPv4 Ssrr option wire frame (7 bytes = 3-byte header + 1x 4-byte slot):
                #   Byte  0    : 0x89       -> type=Ip4OptionType.SSRR (137)
                #   Byte  1    : 0x07       -> len=7 (header + 1 slot)
                #   Byte  2    : 0x04       -> pointer=4 (next-hop is slot 0)
                #   Bytes 3-6  : 0x0a000001 -> route[0]=10.0.0.1
                "__bytes__": b"\x89\x07\x04\x0a\x00\x00\x01",
                "length": IP4__OPTION__SSRR__HDR_LEN + IP4__OPTION__SSRR__SLOT_LEN * 1,
            },
        },
        {
            "_description": "IPv4 Ssrr option with two hops, pointer past last slot (fully consumed).",
            "_pointer": 12,
            "_route": [Ip4Address("10.0.0.1"), Ip4Address("10.0.0.2")],
            "_results": {
                "__len__": 11,
                "__str__": "ssrr [10.0.0.1, 10.0.0.2] ptr=12",
                "__repr__": ("Ip4OptionSsrr(pointer=12, route=[Ip4Address('10.0.0.1'), Ip4Address('10.0.0.2')])"),
                # IPv4 Ssrr option wire frame (11 bytes = 3-byte header + 2x 4-byte slots):
                #   Byte  0    : 0x89       -> type=Ip4OptionType.SSRR (137)
                #   Byte  1    : 0x0b       -> len=11 (header + 2 slots)
                #   Byte  2    : 0x0c       -> pointer=12 (past last slot — fully consumed)
                #   Bytes 3-6  : 0x0a000001 -> route[0]=10.0.0.1
                #   Bytes 7-10 : 0x0a000002 -> route[1]=10.0.0.2
                "__bytes__": b"\x89\x0b\x0c\x0a\x00\x00\x01\x0a\x00\x00\x02",
                "length": IP4__OPTION__SSRR__HDR_LEN + IP4__OPTION__SSRR__SLOT_LEN * 2,
            },
        },
    ]
)
class TestIp4OptionSsrrAssembler(TestCase):
    """
    The IPv4 Ssrr option assembler tests.
    """

    _description: str
    _pointer: int
    _route: list[Ip4Address]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build an Ip4OptionSsrr from the parametrized 'pointer' / 'route'.
        """

        self._option = Ip4OptionSsrr(pointer=self._pointer, route=self._route)

    def test__ip4__option__ssrr__len(self) -> None:
        """
        Ensure '__len__' reports the canonical 3-byte header plus 4 bytes
        per route slot.

        Reference: RFC 791 §3.1 (Strict Source Route length = 3 + 4N).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected '__len__' for case: {self._description}",
        )

    def test__ip4__option__ssrr__str(self) -> None:
        """
        Ensure '__str__' renders the route hops and the pointer in a
        readable single-line log form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected '__str__' for case: {self._description}",
        )

    def test__ip4__option__ssrr__repr(self) -> None:
        """
        Ensure '__repr__' is the canonical dataclass form with 'pointer'
        and 'route' as visible fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected '__repr__' for case: {self._description}",
        )

    def test__ip4__option__ssrr__bytes(self) -> None:
        """
        Ensure 'bytes()' serialises the option to the canonical RFC 791
        wire format: type=137, length, pointer, then route data slots.

        Reference: RFC 791 §3.1 (Strict Source Route wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected 'bytes()' for case: {self._description}",
        )

    def test__ip4__option__ssrr__type(self) -> None:
        """
        Ensure the option's 'type' field is Ip4OptionType.SSRR (the wire
        value 137) regardless of construction arguments.

        Reference: RFC 791 §3.1 (Strict Source Route type byte = 137).
        """

        self.assertIs(
            self._option.type,
            Ip4OptionType.SSRR,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__ssrr__length(self) -> None:
        """
        Ensure the option's 'len' field equals 3 + 4 * len(route).

        Reference: RFC 791 §3.1 (length field equals header + slots).
        """

        self.assertEqual(
            self._option.len,
            self._results["length"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__ip4__option__ssrr__roundtrip(self) -> None:
        """
        Ensure an option assembled to bytes and re-parsed via
        'from_buffer' equals the original — pointer, route, type, len
        all round-trip without loss.

        Reference: RFC 791 §3.1 (Strict Source Route wire format).
        """

        roundtripped = Ip4OptionSsrr.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            roundtripped,
            self._option,
            msg=f"Unexpected roundtrip result for case: {self._description}",
        )


class TestIp4OptionSsrrIntegrity(TestCase):
    """
    The IPv4 Ssrr option 'from_buffer' integrity-check tests.
    """

    def test__ip4__option__ssrr__integrity__length__under_min(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte is below the 7-byte minimum.

        Reference: RFC 791 §3.1 (Strict Source Route length >= 7).
        """

        # Bytes: 0x89=type, 0x06=len (one byte short), 0x04=pointer, ...
        buffer = b"\x89\x06\x04\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionSsrr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Ssrr option length must be at least 7 bytes. Got: 6",
            msg="Unexpected integrity-error message for length < 7.",
        )

    def test__ip4__option__ssrr__integrity__route_data__misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the route
        data length is not a multiple of 4.

        Reference: RFC 791 §3.1 (route data is a list of 4-byte slots).
        """

        # Bytes: 0x89=type, 0x08=len (header + 5 bytes — not a multiple of 4),
        # 0x04=pointer, 5 bytes of partial slot
        buffer = b"\x89\x08\x04\x0a\x00\x00\x01\xff"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionSsrr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Ssrr option route data length must be a multiple of 4 bytes. Got: 8",
            msg="Unexpected integrity-error message for misaligned route data.",
        )

    def test__ip4__option__ssrr__integrity__length__exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte exceeds the actual provided buffer length.

        Reference: RFC 791 §3.1 (length field bounds the option in-place).
        """

        # Bytes: 0x89=type, 0x0f=len=15 (claims 3 slots), but only 1 slot present.
        buffer = b"\x89\x0f\x04\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionSsrr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Ssrr option length value must be less "
                "than or equal to the length of provided bytes (7). Got: 15"
            ),
            msg="Unexpected integrity-error message for length > buffer.",
        )

    def test__ip4__option__ssrr__integrity__pointer__under_base(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer byte is below the canonical minimum of 4. Hostile-wire
        defense-in-depth — the __post_init__ assert would otherwise
        leak as a bare AssertionError.

        Reference: RFC 791 §3.1 (Strict Source Route pointer minimum is 4).
        """

        # Bytes: 0x89=type, 0x07=len=7, 0x03=pointer=3 (< 4), 1 valid slot.
        buffer = b"\x89\x07\x03\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionSsrr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Ssrr option pointer must be at least 4. Got: 3",
            msg="Unexpected integrity-error message for pointer < 4.",
        )

    def test__ip4__option__ssrr__integrity__pointer__misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer is not aligned to the 4-byte slot boundary.

        Reference: RFC 791 §3.1 (route data is a list of 4-byte slots;
        pointer must address a slot boundary).
        """

        # Bytes: 0x89=type, 0x07=len=7, 0x05=pointer=5 (mid-slot), 1 valid slot.
        buffer = b"\x89\x07\x05\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionSsrr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Ssrr option pointer must be aligned to the 4-byte slot boundary. Got: 5",
            msg="Unexpected integrity-error message for misaligned pointer.",
        )
