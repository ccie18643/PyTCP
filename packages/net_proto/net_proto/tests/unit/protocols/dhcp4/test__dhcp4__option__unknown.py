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
Module contains tests for the unknown DHCPv4 option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__unknown.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionType,
    Dhcp4OptionUnknown,
)
from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.dhcp4.options.dhcp4__option import DHCP4__OPTION__LEN
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionUnknownAsserts(TestCase):
    """
    The unknown DHCPv4 option constructor argument assert tests.
    """

    def test__dhcp4__option__unknown__type_not_Dhcp4OptionType(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'type'
        argument is not a Dhcp4OptionType.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        value = "not a Dhcp4OptionType"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(type=value, data=b"012345")  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Dhcp4OptionType. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message.",
        )

    def test__dhcp4__option__unknown__type_rejects_raw_int(self) -> None:
        """
        Ensure the constructor rejects a raw int — a Dhcp4OptionType is
        required.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        value = 254

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(type=value, data=b"012345")  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Dhcp4OptionType. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message for int.",
        )

    def test__dhcp4__option__unknown__type_known_value(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'type'
        argument is a known Dhcp4OptionType — the unknown option must cover
        only unassigned codes.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        for code in Dhcp4OptionType.get_known_values():
            value = Dhcp4OptionType(code)

            with self.assertRaises(AssertionError) as error:
                Dhcp4OptionUnknown(type=value, data=b"012345")

            self.assertEqual(
                str(error.exception),
                f"The 'type' field must not be a known Dhcp4OptionType. Got: {value!r}",
                msg=f"Unexpected known-type assert message for code {code}.",
            )

    def test__dhcp4__option__unknown__len_8bit_integer(self) -> None:
        """
        Ensure the option's computed 'len' field is an 8-bit unsigned
        integer — the data payload cannot exceed 255 bytes.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown(
                type=Dhcp4OptionType.from_int(254),
                data=b"X" * (UINT_8__MAX + 1),
            )

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. " f"Got: {UINT_8__MAX + DHCP4__OPTION__LEN + 1}",
            msg="Unexpected 8-bit-len assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv4 option (16-byte payload).",
            "_kwargs": {
                "type": Dhcp4OptionType.from_int(254),
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-254-18",
                "__repr__": (
                    f"Dhcp4OptionUnknown(type={Dhcp4OptionType.from_int(254)!r}, " f"len=18, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # Unknown DHCPv4 option [RFC 2132 format]
                    #   Code : 0xfe (254, unknown)
                    #   Len  : 0x10 (16, payload length)
                    #   Data : 30 31 32 33 34 35 36 37
                    #          38 39 41 42 43 44 45 46
                    #          ('0123456789ABCDEF')
                    b"\xfe\x10\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Dhcp4OptionType.from_int(254),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "The unknown DHCPv4 option (empty payload).",
            "_kwargs": {
                "type": Dhcp4OptionType.from_int(200),
                "data": b"",
            },
            "_results": {
                "__len__": 2,
                "__str__": "unk-200-2",
                "__repr__": f"Dhcp4OptionUnknown(type={Dhcp4OptionType.from_int(200)!r}, len=2, data=b'')",
                "__bytes__": (
                    # Unknown DHCPv4 option
                    #   Code : 0xc8 (200, unknown)
                    #   Len  : 0x00 (0, empty payload)
                    #   Data : (empty)
                    b"\xc8\x00"
                ),
                "type": Dhcp4OptionType.from_int(200),
                "len": 2,
                "data": b"",
            },
        },
        {
            "_description": "The unknown DHCPv4 option (single-byte payload).",
            "_kwargs": {
                "type": Dhcp4OptionType.from_int(100),
                "data": b"\x42",
            },
            "_results": {
                "__len__": 3,
                "__str__": "unk-100-3",
                "__repr__": f"Dhcp4OptionUnknown(type={Dhcp4OptionType.from_int(100)!r}, len=3, data=b'B')",
                "__bytes__": (
                    # Unknown DHCPv4 option
                    #   Code : 0x64 (100, unknown)
                    #   Len  : 0x01 (1, single-byte payload)
                    #   Data : 42 ('B')
                    b"\x64\x01\x42"
                ),
                "type": Dhcp4OptionType.from_int(100),
                "len": 3,
                "data": b"\x42",
            },
        },
        {
            "_description": "The unknown DHCPv4 option (max assemblable 253-byte payload).",
            "_kwargs": {
                "type": Dhcp4OptionType.from_int(99),
                "data": b"\xaa" * (UINT_8__MAX - DHCP4__OPTION__LEN),
            },
            "_results": {
                "__len__": UINT_8__MAX,
                "__str__": f"unk-99-{UINT_8__MAX}",
                "__repr__": (
                    f"Dhcp4OptionUnknown(type={Dhcp4OptionType.from_int(99)!r}, "
                    f"len={UINT_8__MAX}, "
                    f"data={(b'\xaa' * (UINT_8__MAX - DHCP4__OPTION__LEN))!r})"
                ),
                "__bytes__": (
                    b"\x63" + bytes([UINT_8__MAX - DHCP4__OPTION__LEN]) + b"\xaa" * (UINT_8__MAX - DHCP4__OPTION__LEN)
                ),
                "type": Dhcp4OptionType.from_int(99),
                "len": UINT_8__MAX,
                "data": b"\xaa" * (UINT_8__MAX - DHCP4__OPTION__LEN),
            },
        },
    ]
)
class TestDhcp4OptionUnknownAssembler(TestCase):
    """
    The unknown DHCPv4 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the unknown DHCPv4 option object with testcase arguments.
        """

        self._option = Dhcp4OptionUnknown(**self._kwargs)

    def test__dhcp4__option__unknown__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + payload bytes.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__unknown__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical 'unk-{type}-{len}' form.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__unknown__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__unknown__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__unknown__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__unknown__type(self) -> None:
        """
        Ensure the 'type' field reflects the constructor argument.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__unknown__len_field(self) -> None:
        """
        Ensure the 'len' field matches __len__().

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__unknown__data(self) -> None:
        """
        Ensure the 'data' field reflects the constructor argument.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__dhcp4__option__unknown__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            Dhcp4OptionUnknown.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv4 option (16-byte payload).",
            "_args": [b"\xfe\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionUnknown(
                    type=Dhcp4OptionType.from_int(254),
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option (empty payload).",
            "_args": [b"\xc8\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionUnknown(
                    type=Dhcp4OptionType.from_int(200),
                    data=b"",
                ),
            },
        },
        {
            "_description": "The unknown DHCPv4 option (single-byte payload).",
            "_args": [b"\x64\x01\x42" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionUnknown(
                    type=Dhcp4OptionType.from_int(100),
                    data=b"\x42",
                ),
            },
        },
    ]
)
class TestDhcp4OptionUnknownParser(TestCase):
    """
    The unknown DHCPv4 option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__unknown__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        option = Dhcp4OptionUnknown.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionUnknownParserErrors(TestCase):
    """
    The unknown DHCPv4 option parser error tests.
    """

    def test__dhcp4__option__unknown__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown.from_buffer(b"\xfe")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the unknown DHCPv4 option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__unknown__rejects_known_type_end(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is a known
        Dhcp4OptionType (End, 255).

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown.from_buffer(b"\xff\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46")

        self.assertEqual(
            str(error.exception),
            f"The unknown DHCPv4 option type must not be known. Got: {Dhcp4OptionType.END!r}",
            msg="Unexpected known-type assert message for End.",
        )

    def test__dhcp4__option__unknown__rejects_known_type_pad(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is a known
        Dhcp4OptionType (Pad, 0).

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionUnknown.from_buffer(b"\x00\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46")

        self.assertEqual(
            str(error.exception),
            f"The unknown DHCPv4 option type must not be known. Got: {Dhcp4OptionType.PAD!r}",
            msg="Unexpected known-type assert message for Pad.",
        )

    def test__dhcp4__option__unknown__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionUnknown.from_buffer(b"\xfe\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The unknown DHCPv4 option length value must be "
            "less than or equal to the length of provided bytes (17). Got: 18",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp4OptionUnknownBehavior(TestCase):
    """
    The unknown DHCPv4 option behavioral tests.
    """

    def test__dhcp4__option__unknown__equality(self) -> None:
        """
        Ensure two options with equal fields compare equal.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertEqual(
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data"),
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data"),
            msg="Options with identical fields must compare equal.",
        )

    def test__dhcp4__option__unknown__inequality_type(self) -> None:
        """
        Ensure two options with different 'type' compare unequal.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertNotEqual(
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data"),
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(253), data=b"data"),
            msg="Options with different type must not compare equal.",
        )

    def test__dhcp4__option__unknown__inequality_data(self) -> None:
        """
        Ensure two options with different 'data' compare unequal.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        self.assertNotEqual(
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data-a"),
            Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data-b"),
            msg="Options with different data must not compare equal.",
        )

    def test__dhcp4__option__unknown__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        option = Dhcp4OptionUnknown(type=Dhcp4OptionType.from_int(254), data=b"data")

        with self.assertRaises(FrozenInstanceError):
            option.data = b"other"  # type: ignore[misc]

    def test__dhcp4__option__unknown__len_cannot_be_overridden(self) -> None:
        """
        Ensure 'len' cannot be supplied via the constructor (init=False); it
        is always derived from the payload length.

        Reference: RFC 2132 §2 (DHCP option TLV format).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionUnknown(  # type: ignore[call-arg]
                type=Dhcp4OptionType.from_int(254),
                len=5,
                data=b"data",
            )
