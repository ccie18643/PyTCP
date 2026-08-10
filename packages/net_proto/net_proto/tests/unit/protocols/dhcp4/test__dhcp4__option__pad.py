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
Module contains tests for the DHCPv4 Pad option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__pad.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase

from net_proto import DHCP4__OPTION__PAD__LEN, Dhcp4OptionPad, Dhcp4OptionType


class TestDhcp4OptionPadAssembler(TestCase):
    """
    The DHCPv4 Pad option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Pad option object.
        """

        self._option = Dhcp4OptionPad()

    def test__dhcp4__option__pad__len(self) -> None:
        """
        Ensure '__len__()' returns the one-byte Pad marker length.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            len(self._option),
            1,
            msg="Pad option length must be 1 byte.",
        )

    def test__dhcp4__option__pad__str(self) -> None:
        """
        Ensure '__str__()' returns the canonical 'pad' log string.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            str(self._option),
            "pad",
            msg="Pad option __str__ must be 'pad'.",
        )

    def test__dhcp4__option__pad__repr(self) -> None:
        """
        Ensure '__repr__()' returns the dataclass form.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            repr(self._option),
            "Dhcp4OptionPad()",
            msg="Pad option __repr__ must be 'Dhcp4OptionPad()'.",
        )

    def test__dhcp4__option__pad__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the single 0x00 Pad marker byte.

        DHCPv4 Pad option [RFC 2132]:
          Code : 0x00 (0, Pad)

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00",
            msg="Pad option wire image must be b'\\x00'.",
        )

    def test__dhcp4__option__pad__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            b"\x00",
            msg="Pad option memoryview must equal b'\\x00'.",
        )

    def test__dhcp4__option__pad__type(self) -> None:
        """
        Ensure the 'type' field is Dhcp4OptionType.PAD.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            self._option.type,
            Dhcp4OptionType.PAD,
            msg="Pad option 'type' must be Dhcp4OptionType.PAD.",
        )

    def test__dhcp4__option__pad__len_field(self) -> None:
        """
        Ensure the 'len' field equals DHCP4__OPTION__PAD__LEN.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            self._option.len,
            DHCP4__OPTION__PAD__LEN,
            msg="Pad option 'len' must equal DHCP4__OPTION__PAD__LEN.",
        )


class TestDhcp4OptionPadParser(TestCase):
    """
    The DHCPv4 Pad option parser tests.
    """

    def test__dhcp4__option__pad__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' parses a buffer starting with 0x00 and ignores
        any trailing bytes.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        option = Dhcp4OptionPad.from_buffer(b"\x00" + b"ZH0PA")

        self.assertEqual(
            option,
            Dhcp4OptionPad(),
            msg="Parser must return a Pad option equal to Dhcp4OptionPad().",
        )

    def test__dhcp4__option__pad__from_buffer_exact(self) -> None:
        """
        Ensure 'from_buffer()' succeeds on a buffer containing only 0x00.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        option = Dhcp4OptionPad.from_buffer(b"\x00")

        self.assertEqual(
            option,
            Dhcp4OptionPad(),
            msg="A single-byte 0x00 buffer must parse as Dhcp4OptionPad().",
        )

    def test__dhcp4__option__pad__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts on an empty buffer.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionPad.from_buffer(b"")

        self.assertEqual(
            str(error.exception),
            f"The minimum length of the DHCPv4 Pad option must be {DHCP4__OPTION__PAD__LEN} byte. Got: 0",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__pad__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 0x00.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionPad.from_buffer(b"\xfe")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Pad option type must be {Dhcp4OptionType.PAD!r}. " f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )


class TestDhcp4OptionPadBehavior(TestCase):
    """
    The DHCPv4 Pad option behavioral tests.
    """

    def test__dhcp4__option__pad__equality(self) -> None:
        """
        Ensure two Pad options compare equal.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        self.assertEqual(
            Dhcp4OptionPad(),
            Dhcp4OptionPad(),
            msg="All Pad options must compare equal.",
        )

    def test__dhcp4__option__pad__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §3.1 (Pad option).
        """

        option = Dhcp4OptionPad()

        self.assertEqual(
            Dhcp4OptionPad.from_buffer(bytes(option)),
            option,
            msg="Roundtrip must preserve equality.",
        )

    def test__dhcp4__option__pad__rejects_type_override(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §3.1 (Pad option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionPad(type=Dhcp4OptionType.PAD)  # type: ignore[call-arg]

    def test__dhcp4__option__pad__rejects_len_override(self) -> None:
        """
        Ensure 'len' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §3.1 (Pad option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionPad(len=DHCP4__OPTION__PAD__LEN)  # type: ignore[call-arg]
