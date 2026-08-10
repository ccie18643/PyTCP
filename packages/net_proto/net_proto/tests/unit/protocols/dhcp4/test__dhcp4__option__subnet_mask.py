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
Module contains tests for the DHCPv4 Subnet Mask option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__subnet_mask.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Mask
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionSubnetMask,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__subnet_mask import (
    DHCP4__OPTION__SUBNET_MASK__LEN,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionSubnetMaskAsserts(TestCase):
    """
    The DHCPv4 Subnet Mask option constructor argument assert tests.
    """

    def test__dhcp4__option__subnet_mask__not_Ip4Mask(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'subnet_mask' argument is not an Ip4Mask.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        value = "255.255.255.0"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'subnet_mask' field must be an Ip4Mask. Got: {type(value)!r}",
            msg="Unexpected 'subnet_mask' type assert message.",
        )

    def test__dhcp4__option__subnet_mask__rejects_int(self) -> None:
        """
        Ensure the constructor rejects a bare int — Ip4Mask instances are
        required.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        value = 0xFFFFFF00

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'subnet_mask' field must be an Ip4Mask. Got: {type(value)!r}",
            msg="Unexpected 'subnet_mask' type assert message for int.",
        )

    def test__dhcp4__option__subnet_mask__rejects_bytes(self) -> None:
        """
        Ensure the constructor rejects raw bytes — Ip4Mask instances are
        required.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        value = b"\xff\xff\xff\x00"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'subnet_mask' field must be an Ip4Mask. Got: {type(value)!r}",
            msg="Unexpected 'subnet_mask' type assert message for bytes.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Subnet Mask option (/24).",
            "_args": [Ip4Mask("255.255.255.0")],
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /24",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/24'))",
                "__bytes__": (
                    # DHCPv4 Subnet Mask option [RFC 2132]
                    #   Code : 0x01 (1, Subnet Mask)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff ff 00   (255.255.255.0, /24)
                    b"\x01\x04\xff\xff\xff\x00"
                ),
                "subnet_mask": Ip4Mask("255.255.255.0"),
                "type": Dhcp4OptionType.SUBNET_MASK,
                "len": DHCP4__OPTION__SUBNET_MASK__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/16).",
            "_args": [Ip4Mask("255.255.0.0")],
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /16",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/16'))",
                "__bytes__": (
                    # DHCPv4 Subnet Mask option [RFC 2132]
                    #   Code : 0x01 (1, Subnet Mask)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff 00 00   (255.255.0.0, /16)
                    b"\x01\x04\xff\xff\x00\x00"
                ),
                "subnet_mask": Ip4Mask("255.255.0.0"),
                "type": Dhcp4OptionType.SUBNET_MASK,
                "len": DHCP4__OPTION__SUBNET_MASK__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/8).",
            "_args": [Ip4Mask("255.0.0.0")],
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /8",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/8'))",
                "__bytes__": (
                    # DHCPv4 Subnet Mask option [RFC 2132]
                    #   Code : 0x01 (1, Subnet Mask)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff 00 00 00   (255.0.0.0, /8)
                    b"\x01\x04\xff\x00\x00\x00"
                ),
                "subnet_mask": Ip4Mask("255.0.0.0"),
                "type": Dhcp4OptionType.SUBNET_MASK,
                "len": DHCP4__OPTION__SUBNET_MASK__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/32).",
            "_args": [Ip4Mask("255.255.255.255")],
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /32",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/32'))",
                "__bytes__": (
                    # DHCPv4 Subnet Mask option [RFC 2132]
                    #   Code : 0x01 (1, Subnet Mask)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff ff ff   (255.255.255.255, /32)
                    b"\x01\x04\xff\xff\xff\xff"
                ),
                "subnet_mask": Ip4Mask("255.255.255.255"),
                "type": Dhcp4OptionType.SUBNET_MASK,
                "len": DHCP4__OPTION__SUBNET_MASK__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/0).",
            "_args": [Ip4Mask("0.0.0.0")],
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /0",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/0'))",
                "__bytes__": (
                    # DHCPv4 Subnet Mask option [RFC 2132]
                    #   Code : 0x01 (1, Subnet Mask)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 00 00 00   (0.0.0.0, /0)
                    b"\x01\x04\x00\x00\x00\x00"
                ),
                "subnet_mask": Ip4Mask("0.0.0.0"),
                "type": Dhcp4OptionType.SUBNET_MASK,
                "len": DHCP4__OPTION__SUBNET_MASK__LEN,
            },
        },
    ]
)
class TestDhcp4OptionSubnetMaskAssembler(TestCase):
    """
    The DHCPv4 Subnet Mask option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Subnet Mask option object with testcase
        arguments.
        """

        self._option = Dhcp4OptionSubnetMask(*self._args)

    def test__dhcp4__option__subnet_mask__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 6-byte option length.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__field(self) -> None:
        """
        Ensure the 'subnet_mask' field reflects the constructor argument.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            self._option.subnet_mask,
            self._results["subnet_mask"],
            msg=f"Unexpected 'subnet_mask' for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__type(self) -> None:
        """
        Ensure the 'type' field is always SUBNET_MASK (1).

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__len_field(self) -> None:
        """
        Ensure the 'len' field equals DHCP4__OPTION__SUBNET_MASK__LEN.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__subnet_mask__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            Dhcp4OptionSubnetMask.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Subnet Mask option (/24).",
            "_args": [b"\x01\x04\xff\xff\xff\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/16).",
            "_args": [b"\x01\x04\xff\xff\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionSubnetMask(Ip4Mask("255.255.0.0")),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/8).",
            "_args": [b"\x01\x04\xff\x00\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionSubnetMask(Ip4Mask("255.0.0.0")),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/32).",
            "_args": [b"\x01\x04\xff\xff\xff\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.255")),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/0).",
            "_args": [b"\x01\x04\x00\x00\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionSubnetMask(Ip4Mask("0.0.0.0")),
            },
        },
    ]
)
class TestDhcp4OptionSubnetMaskParser(TestCase):
    """
    The DHCPv4 Subnet Mask option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__subnet_mask__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        option = Dhcp4OptionSubnetMask.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionSubnetMaskParserErrors(TestCase):
    """
    The DHCPv4 Subnet Mask option parser error tests.
    """

    def test__dhcp4__option__subnet_mask__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask.from_buffer(b"\x01")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Subnet Mask option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__subnet_mask__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 1.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask.from_buffer(b"\xfe\x04\xff\xff\xff\x00")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Subnet Mask option type must be {Dhcp4OptionType.SUBNET_MASK!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__subnet_mask__bad_length_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length is not exactly 4 bytes.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionSubnetMask.from_buffer(b"\x01\x03\xff\xff\xff")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Subnet Mask option length value must be 6 bytes. Got: 5",
            msg="Unexpected bad-length-field integrity error message.",
        )

    def test__dhcp4__option__subnet_mask__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionSubnetMask.from_buffer(b"\x01\x04")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Subnet Mask option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 6",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp4OptionSubnetMaskBehavior(TestCase):
    """
    The DHCPv4 Subnet Mask option behavioral tests.
    """

    def test__dhcp4__option__subnet_mask__equality(self) -> None:
        """
        Ensure two options with equal 'subnet_mask' compare equal.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertEqual(
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            msg="Options with identical subnet_mask must compare equal.",
        )

    def test__dhcp4__option__subnet_mask__inequality(self) -> None:
        """
        Ensure two options with different 'subnet_mask' compare unequal.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        self.assertNotEqual(
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
            Dhcp4OptionSubnetMask(Ip4Mask("255.255.0.0")),
            msg="Options with different subnet_mask must not compare equal.",
        )

    def test__dhcp4__option__subnet_mask__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        option = Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0"))

        with self.assertRaises(FrozenInstanceError):
            option.subnet_mask = Ip4Mask("255.255.0.0")  # type: ignore[misc]

    def test__dhcp4__option__subnet_mask__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §3.3 (Subnet Mask option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionSubnetMask(  # type: ignore[call-arg]
                Ip4Mask("255.255.255.0"),
                type=Dhcp4OptionType.SUBNET_MASK,
            )


class TestDhcp4OptionSubnetMaskWrongType(TestCase):
    """
    The DHCPv4 Subnet Mask option wrong-code-byte parser tests.
    """

    def test__dhcp4__option__subnet_mask__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code byte equals
        Dhcp4OptionType.SUBNET_MASK and rejects a code byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 2132 §3.3 (Subnet Mask option code 1).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionSubnetMask.from_buffer(b"\x00\x04\xff\xff\xff\x00")

    def test__dhcp4__option__subnet_mask__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code byte above
        Dhcp4OptionType.SUBNET_MASK, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 2132 §3.3 (Subnet Mask option code 1).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionSubnetMask.from_buffer(b"\xff\x04\xff\xff\xff\x00")
