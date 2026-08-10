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
Module contains tests for the IPv4 Record Route option code.

net_proto/tests/unit/protocols/ip4/test__ip4__option__rr.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    IP4__OPTION__RR__HDR_LEN,
    IP4__OPTION__RR__SLOT_LEN,
    Ip4IntegrityError,
    Ip4OptionRr,
    Ip4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionRrAsserts(TestCase):
    """
    The IPv4 Record Route option constructor argument assert tests.
    """

    def test__ip4__option__rr__pointer__under_min(self) -> None:
        """
        Ensure the IPv4 Record Route option constructor rejects a
        'pointer' value below the canonical minimum of 4.

        Reference: RFC 791 §3.1 (Record Route pointer minimum is 4).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRr(pointer=3, route=[Ip4Address("10.0.0.1")])

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be at least 4. Got: 3",
            msg="Unexpected assertion message for 'pointer' < 4.",
        )

    def test__ip4__option__rr__pointer__misaligned(self) -> None:
        """
        Ensure the IPv4 Record Route option constructor rejects a
        'pointer' that is not aligned to the 4-byte slot boundary.

        Reference: RFC 791 §3.1 (route data is a list of 4-byte addresses).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRr(pointer=5, route=[Ip4Address("10.0.0.1")])

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be aligned to the 4-byte slot boundary. Got: 5",
            msg="Unexpected assertion message for misaligned 'pointer'.",
        )

    def test__ip4__option__rr__route__empty(self) -> None:
        """
        Ensure the IPv4 Record Route option constructor rejects an
        empty 'route' list.

        Reference: RFC 791 §3.1 (Record Route minimum length is 7).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRr(pointer=4, route=[])

        self.assertEqual(
            str(error.exception),
            "The 'route' field must have at least 1 entry. Got: 0",
            msg="Unexpected assertion message for empty 'route'.",
        )

    def test__ip4__option__rr__route__overflows_uint8_length(self) -> None:
        """
        Ensure the IPv4 Record Route option constructor rejects a
        'route' list whose total option length (3-byte header +
        4-byte slot per entry) would overflow the single-octet
        option-length byte.

        Reference: RFC 791 §3.1 (option-length byte is one octet).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionRr(pointer=4, route=[Ip4Address("10.0.0.1")] * 64)

        self.assertIn(
            "must fit in a single uint8 length byte",
            str(error.exception),
            msg="AssertionError must cite the uint8 length-byte overflow.",
        )


@parameterized_class(
    [
        {
            "_description": "IPv4 Record Route with one slot, pointer at start (slot empty).",
            "_pointer": 4,
            "_route": [Ip4Address("0.0.0.0")],
            "_results": {
                "__len__": 7,
                "__str__": "rr [0.0.0.0] ptr=4",
                "__repr__": "Ip4OptionRr(pointer=4, route=[Ip4Address('0.0.0.0')])",
                # IPv4 Record Route wire frame (7 bytes = 3-byte header + 1x 4-byte slot):
                #   Byte  0    : 0x07       -> type=Ip4OptionType.RR (7)
                #   Byte  1    : 0x07       -> len=7 (header + 1 slot)
                #   Byte  2    : 0x04       -> pointer=4 (slot 0 to be recorded into)
                #   Bytes 3-6  : 0x00000000 -> route[0]=0.0.0.0 (unfilled slot)
                "__bytes__": b"\x07\x07\x04\x00\x00\x00\x00",
                "length": IP4__OPTION__RR__HDR_LEN + IP4__OPTION__RR__SLOT_LEN * 1,
            },
        },
        {
            "_description": "IPv4 Record Route with three slots fully recorded.",
            "_pointer": 16,
            "_route": [
                Ip4Address("10.0.0.1"),
                Ip4Address("10.0.0.2"),
                Ip4Address("10.0.0.3"),
            ],
            "_results": {
                "__len__": 15,
                "__str__": "rr [10.0.0.1, 10.0.0.2, 10.0.0.3] ptr=16",
                "__repr__": (
                    "Ip4OptionRr(pointer=16, route=[Ip4Address('10.0.0.1'), "
                    "Ip4Address('10.0.0.2'), Ip4Address('10.0.0.3')])"
                ),
                # IPv4 Record Route wire frame (15 bytes = 3-byte header + 3x 4-byte slots):
                #   Byte  0    : 0x07       -> type=Ip4OptionType.RR (7)
                #   Byte  1    : 0x0f       -> len=15 (header + 3 slots)
                #   Byte  2    : 0x10       -> pointer=16 (past last slot — fully recorded)
                #   Bytes 3-6  : 0x0a000001 -> route[0]=10.0.0.1
                #   Bytes 7-10 : 0x0a000002 -> route[1]=10.0.0.2
                #   Bytes 11-14: 0x0a000003 -> route[2]=10.0.0.3
                "__bytes__": (b"\x07\x0f\x10\x0a\x00\x00\x01\x0a\x00\x00\x02\x0a\x00\x00\x03"),
                "length": IP4__OPTION__RR__HDR_LEN + IP4__OPTION__RR__SLOT_LEN * 3,
            },
        },
    ]
)
class TestIp4OptionRrAssembler(TestCase):
    """
    The IPv4 Record Route option assembler tests.
    """

    _description: str
    _pointer: int
    _route: list[Ip4Address]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an Ip4OptionRr from the parametrized 'pointer' / 'route'.
        """

        self._option = Ip4OptionRr(pointer=self._pointer, route=self._route)

    def test__ip4__option__rr__len(self) -> None:
        """
        Ensure '__len__' reports the canonical 3-byte header plus 4 bytes
        per route slot.

        Reference: RFC 791 §3.1 (Record Route length = 3 + 4N).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected '__len__' for case: {self._description}",
        )

    def test__ip4__option__rr__str(self) -> None:
        """
        Ensure '__str__' renders the recorded hops and the pointer in
        a readable single-line log form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected '__str__' for case: {self._description}",
        )

    def test__ip4__option__rr__repr(self) -> None:
        """
        Ensure '__repr__' is the canonical dataclass form with
        'pointer' and 'route' as visible fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected '__repr__' for case: {self._description}",
        )

    def test__ip4__option__rr__bytes(self) -> None:
        """
        Ensure 'bytes()' serialises the option to the canonical RFC 791
        wire format: type=7, length, pointer, then recorded data slots.

        Reference: RFC 791 §3.1 (Record Route wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected 'bytes()' for case: {self._description}",
        )

    def test__ip4__option__rr__type(self) -> None:
        """
        Ensure the option's 'type' field is Ip4OptionType.RR (the wire
        value 7) regardless of construction arguments.

        Reference: RFC 791 §3.1 (Record Route type byte = 7).
        """

        self.assertIs(
            self._option.type,
            Ip4OptionType.RR,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__rr__length(self) -> None:
        """
        Ensure the option's 'len' field equals 3 + 4 * len(route).

        Reference: RFC 791 §3.1 (length field equals header + slots).
        """

        self.assertEqual(
            self._option.len,
            self._results["length"],
            msg=f"Unexpected 'len' for case: {self._description}",
        )

    def test__ip4__option__rr__roundtrip(self) -> None:
        """
        Ensure an option assembled to bytes and re-parsed via
        'from_buffer' equals the original — pointer, route, type, len
        all round-trip without loss.

        Reference: RFC 791 §3.1 (Record Route wire format).
        """

        roundtripped = Ip4OptionRr.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            roundtripped,
            self._option,
            msg=f"Unexpected roundtrip result for case: {self._description}",
        )


class TestIp4OptionRrIntegrity(TestCase):
    """
    The IPv4 Record Route option 'from_buffer' integrity-check tests.
    """

    def test__ip4__option__rr__integrity__length__under_min(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte is below the 7-byte minimum.

        Reference: RFC 791 §3.1 (Record Route length >= 7).
        """

        # Bytes: 0x07=type, 0x06=len (one byte short), 0x04=pointer, ...
        buffer = b"\x07\x06\x04\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Record Route option length must be at least 7 bytes. Got: 6",
            msg="Unexpected integrity-error message for length < 7.",
        )

    def test__ip4__option__rr__integrity__route_data__misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the route
        data length is not a multiple of 4.

        Reference: RFC 791 §3.1 (route data is a list of 4-byte slots).
        """

        # Bytes: 0x07=type, 0x08=len (header + 5 bytes — not a multiple of 4),
        # 0x04=pointer, 5 bytes of partial slot
        buffer = b"\x07\x08\x04\x0a\x00\x00\x01\xff"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Record Route option route data length "
                "must be a multiple of 4 bytes. Got: 8"
            ),
            msg="Unexpected integrity-error message for misaligned route data.",
        )

    def test__ip4__option__rr__integrity__length__exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte exceeds the actual provided buffer length.

        Reference: RFC 791 §3.1 (length field bounds the option in-place).
        """

        # Bytes: 0x07=type, 0x0f=len=15 (claims 3 slots), but only 1 slot present.
        buffer = b"\x07\x0f\x04\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Record Route option length value must be less "
                "than or equal to the length of provided bytes (7). Got: 15"
            ),
            msg="Unexpected integrity-error message for length > buffer.",
        )

    def test__ip4__option__rr__integrity__pointer__under_base(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer byte is below the canonical minimum of 4. Hostile-wire
        defense-in-depth — the __post_init__ assert would otherwise
        leak as a bare AssertionError.

        Reference: RFC 791 §3.1 (Record Route pointer minimum is 4).
        """

        # Bytes: 0x07=type, 0x07=len=7, 0x03=pointer=3 (< 4), 1 valid slot.
        buffer = b"\x07\x07\x03\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Record Route option pointer must be at least 4. Got: 3",
            msg="Unexpected integrity-error message for pointer < 4.",
        )

    def test__ip4__option__rr__integrity__pointer__misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer is not aligned to the 4-byte slot boundary.

        Reference: RFC 791 §3.1 (recorded route is a list of 4-byte
        slots; pointer must address a slot boundary).
        """

        # Bytes: 0x07=type, 0x07=len=7, 0x05=pointer=5 (mid-slot), 1 valid slot.
        buffer = b"\x07\x07\x05\x0a\x00\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionRr.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Record Route option pointer must be aligned "
                "to the 4-byte slot boundary. Got: 5"
            ),
            msg="Unexpected integrity-error message for misaligned pointer.",
        )


class TestIp4OptionRrWrongType(TestCase):
    """
    The IPv4 Record Route option wrong-kind-byte parser tests.
    """

    def test__ip4__option__rr__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the kind byte equals
        Ip4OptionType.RR and rejects a kind byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 791 §3.1 (Record Route option kind byte).
        """

        with self.assertRaises(AssertionError):
            Ip4OptionRr.from_buffer(b"\x00\x07\x04\x0a\x00\x00\x01")

    def test__ip4__option__rr__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects a kind byte above
        Ip4OptionType.RR, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 791 §3.1 (Record Route option kind byte).
        """

        with self.assertRaises(AssertionError):
            Ip4OptionRr.from_buffer(b"\xff\x07\x04\x0a\x00\x00\x01")
