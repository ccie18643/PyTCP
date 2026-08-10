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
Module contains tests for the DHCPv4 End option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__end.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_proto import DHCP4__OPTION__END__LEN, Dhcp4OptionEnd, Dhcp4OptionType


class TestDhcp4OptionEndAssembler(TestCase):
    """
    The DHCPv4 End option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 End option object.
        """

        self._option = Dhcp4OptionEnd()

    def test__dhcp4__option__end__len(self) -> None:
        """
        Ensure '__len__()' returns the one-byte End marker length.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            len(self._option),
            1,
            msg="End option length must be 1 byte.",
        )

    def test__dhcp4__option__end__str(self) -> None:
        """
        Ensure '__str__()' returns the canonical 'end' log string.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            str(self._option),
            "end",
            msg="End option __str__ must be 'end'.",
        )

    def test__dhcp4__option__end__repr(self) -> None:
        """
        Ensure '__repr__()' returns the dataclass form.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            repr(self._option),
            "Dhcp4OptionEnd()",
            msg="End option __repr__ must be 'Dhcp4OptionEnd()'.",
        )

    def test__dhcp4__option__end__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the single 0xff End marker byte.

        DHCPv4 End option [RFC 2132]:
          Code : 0xff (255, End)

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\xff",
            msg="End option wire image must be b'\\xff'.",
        )

    def test__dhcp4__option__end__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            b"\xff",
            msg="End option memoryview must equal b'\\xff'.",
        )

    def test__dhcp4__option__end__type(self) -> None:
        """
        Ensure the 'type' field is Dhcp4OptionType.END.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            self._option.type,
            Dhcp4OptionType.END,
            msg="End option 'type' must be Dhcp4OptionType.END.",
        )

    def test__dhcp4__option__end__len_field(self) -> None:
        """
        Ensure the 'len' field equals DHCP4__OPTION__END__LEN.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            self._option.len,
            DHCP4__OPTION__END__LEN,
            msg="End option 'len' must equal DHCP4__OPTION__END__LEN.",
        )


class TestDhcp4OptionEndParser(TestCase):
    """
    The DHCPv4 End option parser tests.
    """

    def test__dhcp4__option__end__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' parses a buffer starting with 0xff and ignores
        any trailing bytes.

        Reference: RFC 2132 §3.2 (End option).
        """

        option = Dhcp4OptionEnd.from_buffer(b"\xff" + b"ZH0PA")

        self.assertEqual(
            option,
            Dhcp4OptionEnd(),
            msg="Parser must return an End option equal to Dhcp4OptionEnd().",
        )

    def test__dhcp4__option__end__from_buffer_exact(self) -> None:
        """
        Ensure 'from_buffer()' succeeds on a buffer containing only 0xff.

        Reference: RFC 2132 §3.2 (End option).
        """

        option = Dhcp4OptionEnd.from_buffer(b"\xff")

        self.assertEqual(
            option,
            Dhcp4OptionEnd(),
            msg="A single-byte 0xff buffer must parse as Dhcp4OptionEnd().",
        )

    def test__dhcp4__option__end__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts on an empty buffer.

        Reference: RFC 2132 §3.2 (End option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionEnd.from_buffer(b"")

        self.assertEqual(
            str(error.exception),
            f"The minimum length of the DHCPv4 End option must be {DHCP4__OPTION__END__LEN} byte. Got: 0",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__end__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 0xff.

        Reference: RFC 2132 §3.2 (End option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionEnd.from_buffer(b"\xfe")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 End option type must be {Dhcp4OptionType.END!r}. " f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )


class TestDhcp4OptionEndBehavior(TestCase):
    """
    The DHCPv4 End option behavioral tests.
    """

    def test__dhcp4__option__end__equality(self) -> None:
        """
        Ensure two End options compare equal.

        Reference: RFC 2132 §3.2 (End option).
        """

        self.assertEqual(
            Dhcp4OptionEnd(),
            Dhcp4OptionEnd(),
            msg="All End options must compare equal.",
        )

    def test__dhcp4__option__end__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §3.2 (End option).
        """

        option = Dhcp4OptionEnd()

        self.assertEqual(
            Dhcp4OptionEnd.from_buffer(bytes(option)),
            option,
            msg="Roundtrip must preserve equality.",
        )

    def test__dhcp4__option__end__rejects_type_override(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §3.2 (End option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionEnd(type=Dhcp4OptionType.END)  # type: ignore[call-arg]

    def test__dhcp4__option__end__rejects_len_override(self) -> None:
        """
        Ensure 'len' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §3.2 (End option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionEnd(len=DHCP4__OPTION__END__LEN)  # type: ignore[call-arg]
