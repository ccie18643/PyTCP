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
Module contains tests for the unknown DHCPv6 option code.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__unknown.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_proto import (
    DHCP6__OPTION__LEN,
    UINT_16__MAX,
    Dhcp6IntegrityError,
    Dhcp6OptionType,
    Dhcp6OptionUnknown,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp6OptionUnknownAsserts(TestCase):
    """
    The unknown DHCPv6 option constructor argument assert tests.
    """

    def test__dhcp6__option__unknown__type_not_Dhcp6OptionType(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'type'
        argument is not a Dhcp6OptionType.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        value = "not a Dhcp6OptionType"

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionUnknown(type=value, data=b"012345")  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Dhcp6OptionType. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message.",
        )

    def test__dhcp6__option__unknown__type_rejects_raw_int(self) -> None:
        """
        Ensure the constructor rejects a raw int — a Dhcp6OptionType is
        required.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        value = 254

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionUnknown(type=value, data=b"012345")  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Dhcp6OptionType. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message for int.",
        )

    def test__dhcp6__option__unknown__type_known_value(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'type'
        argument is a known Dhcp6OptionType — the unknown option must cover
        only unassigned codes.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        for code in Dhcp6OptionType.get_known_values():
            value = Dhcp6OptionType(code)

            with self.assertRaises(AssertionError) as error:
                Dhcp6OptionUnknown(type=value, data=b"012345")

            self.assertEqual(
                str(error.exception),
                f"The 'type' field must not be a known Dhcp6OptionType. Got: {value!r}",
                msg=f"Unexpected known-type assert message for code {code}.",
            )

    def test__dhcp6__option__unknown__len_16bit_integer(self) -> None:
        """
        Ensure the option's computed 'len' field's data portion is a 16-bit
        unsigned integer — the data payload cannot exceed 65535 bytes.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionUnknown(
                type=Dhcp6OptionType.from_int(254),
                data=b"X" * (UINT_16__MAX + 1),
            )

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be a 16-bit unsigned integer. Got: {UINT_16__MAX + DHCP6__OPTION__LEN + 1}",
            msg="Unexpected 16-bit-len assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv6 option (16-byte payload).",
            "_kwargs": {
                "type": Dhcp6OptionType.from_int(254),
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 20,
                "__str__": "unk-254-20",
                "__repr__": (
                    f"Dhcp6OptionUnknown(type={Dhcp6OptionType.from_int(254)!r}, " f"len=20, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # Unknown DHCPv6 option [RFC 8415 §21.1 format]
                    #   Code : 0x00fe (254, unknown)
                    #   Len  : 0x0010 (16, payload length)
                    #   Data : 30 31 32 33 34 35 36 37
                    #          38 39 41 42 43 44 45 46
                    #          ('0123456789ABCDEF')
                    b"\x00\xfe\x00\x10\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Dhcp6OptionType.from_int(254),
                "len": 20,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "The unknown DHCPv6 option (empty payload).",
            "_kwargs": {
                "type": Dhcp6OptionType.from_int(200),
                "data": b"",
            },
            "_results": {
                "__len__": 4,
                "__str__": "unk-200-4",
                "__repr__": f"Dhcp6OptionUnknown(type={Dhcp6OptionType.from_int(200)!r}, len=4, data=b'')",
                "__bytes__": (
                    # Unknown DHCPv6 option
                    #   Code : 0x00c8 (200, unknown)
                    #   Len  : 0x0000 (0, empty payload)
                    #   Data : (empty)
                    b"\x00\xc8\x00\x00"
                ),
                "type": Dhcp6OptionType.from_int(200),
                "len": 4,
                "data": b"",
            },
        },
        {
            "_description": "The unknown DHCPv6 option (single-byte payload).",
            "_kwargs": {
                "type": Dhcp6OptionType.from_int(100),
                "data": b"\x42",
            },
            "_results": {
                "__len__": 5,
                "__str__": "unk-100-5",
                "__repr__": f"Dhcp6OptionUnknown(type={Dhcp6OptionType.from_int(100)!r}, len=5, data=b'B')",
                "__bytes__": (
                    # Unknown DHCPv6 option
                    #   Code : 0x0064 (100, unknown)
                    #   Len  : 0x0001 (1, single-byte payload)
                    #   Data : 42 ('B')
                    b"\x00\x64\x00\x01\x42"
                ),
                "type": Dhcp6OptionType.from_int(100),
                "len": 5,
                "data": b"\x42",
            },
        },
    ]
)
class TestDhcp6OptionUnknownAssembler(TestCase):
    """
    The unknown DHCPv6 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the unknown DHCPv6 option object with testcase arguments.
        """

        self._option = Dhcp6OptionUnknown(**self._kwargs)

    def test__dhcp6__option__unknown__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + payload bytes.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp6__option__unknown__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical 'unk-{type}-{len}' form.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp6__option__unknown__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp6__option__unknown__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp6__option__unknown__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp6__option__unknown__type(self) -> None:
        """
        Ensure the 'type' field reflects the constructor argument.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp6__option__unknown__len_field(self) -> None:
        """
        Ensure the 'len' field matches __len__().

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp6__option__unknown__data(self) -> None:
        """
        Ensure the 'data' field reflects the constructor argument.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
            msg=f"Unexpected 'data' for case: {self._description}",
        )

    def test__dhcp6__option__unknown__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            Dhcp6OptionUnknown.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown DHCPv6 option (16-byte payload).",
            "_args": [b"\x00\xfe\x00\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46" + b"ZH0PA"],
            "_results": {
                "option": Dhcp6OptionUnknown(
                    type=Dhcp6OptionType.from_int(254),
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "The unknown DHCPv6 option (empty payload).",
            "_args": [b"\x00\xc8\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp6OptionUnknown(
                    type=Dhcp6OptionType.from_int(200),
                    data=b"",
                ),
            },
        },
        {
            "_description": "The unknown DHCPv6 option (single-byte payload).",
            "_args": [b"\x00\x64\x00\x01\x42" + b"ZH0PA"],
            "_results": {
                "option": Dhcp6OptionUnknown(
                    type=Dhcp6OptionType.from_int(100),
                    data=b"\x42",
                ),
            },
        },
    ]
)
class TestDhcp6OptionUnknownParser(TestCase):
    """
    The unknown DHCPv6 option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp6__option__unknown__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        option = Dhcp6OptionUnknown.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp6OptionUnknownParserErrors(TestCase):
    """
    The unknown DHCPv6 option parser error tests.
    """

    def test__dhcp6__option__unknown__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionUnknown.from_buffer(b"\x00\xfe\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the unknown DHCPv6 option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__unknown__rejects_known_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is a known
        Dhcp6OptionType (Client Identifier, 1).

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionUnknown.from_buffer(b"\x00\x01\x00\x02\x41\x42")

        self.assertEqual(
            str(error.exception),
            f"The unknown DHCPv6 option type must not be known. Got: {Dhcp6OptionType.CLIENT_ID!r}",
            msg="Unexpected known-type assert message for Client Identifier.",
        )

    def test__dhcp6__option__unknown__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionUnknown.from_buffer(
                b"\x00\xfe\x00\x10\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45"
            )

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The unknown DHCPv6 option length value must be "
            "less than or equal to the length of provided bytes (19). Got: 20",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionUnknownBehavior(TestCase):
    """
    The unknown DHCPv6 option behavioral tests.
    """

    def test__dhcp6__option__unknown__equality(self) -> None:
        """
        Ensure two options with equal fields compare equal.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data"),
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data"),
            msg="Options with identical fields must compare equal.",
        )

    def test__dhcp6__option__unknown__inequality_type(self) -> None:
        """
        Ensure two options with different 'type' compare unequal.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertNotEqual(
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data"),
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(253), data=b"data"),
            msg="Options with different type must not compare equal.",
        )

    def test__dhcp6__option__unknown__inequality_data(self) -> None:
        """
        Ensure two options with different 'data' compare unequal.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertNotEqual(
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data-a"),
            Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data-b"),
            msg="Options with different data must not compare equal.",
        )

    def test__dhcp6__option__unknown__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        option = Dhcp6OptionUnknown(type=Dhcp6OptionType.from_int(254), data=b"data")

        with self.assertRaises(FrozenInstanceError):
            option.data = b"other"  # type: ignore[misc]

    def test__dhcp6__option__unknown__len_cannot_be_overridden(self) -> None:
        """
        Ensure 'len' cannot be supplied via the constructor (init=False); it
        is always derived from the payload length.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(TypeError):
            Dhcp6OptionUnknown(  # type: ignore[call-arg]
                type=Dhcp6OptionType.from_int(254),
                len=5,
                data=b"data",
            )
