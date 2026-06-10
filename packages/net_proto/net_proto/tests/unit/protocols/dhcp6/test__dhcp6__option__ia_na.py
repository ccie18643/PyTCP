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
Module contains tests for the DHCPv6 IA_NA option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__ia_na.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    UINT_32__MAX,
    Dhcp6IntegrityError,
    Dhcp6OptionIaAddr,
    Dhcp6OptionIaNa,
    Dhcp6OptionType,
)


class TestDhcp6OptionIaNaAsserts(TestCase):
    """
    The DHCPv6 IA_NA option constructor assert tests.
    """

    def test__dhcp6__option__ia_na__iaid_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 'iaid' exceeds the
        32-bit maximum.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa(iaid=value, t1=0, t2=0)

        self.assertEqual(
            str(error.exception),
            f"The 'iaid' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected iaid assert message.",
        )

    def test__dhcp6__option__ia_na__t1_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 't1' exceeds the
        32-bit maximum.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa(iaid=0, t1=value, t2=0)

        self.assertEqual(
            str(error.exception),
            f"The 't1' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected t1 assert message.",
        )

    def test__dhcp6__option__ia_na__t2_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 't2' exceeds the
        32-bit maximum.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa(iaid=0, t1=0, t2=value)

        self.assertEqual(
            str(error.exception),
            f"The 't2' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected t2 assert message.",
        )

    def test__dhcp6__option__ia_na__options_not_bytes(self) -> None:
        """
        Ensure the constructor raises an exception when 'options' is not bytes.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa(iaid=0, t1=0, t2=0, options="not bytes")  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be bytes. Got: {type('x')!r}",
            msg="Unexpected options assert message.",
        )


class TestDhcp6OptionIaNaAssembler(TestCase):
    """
    The DHCPv6 IA_NA option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 IA_NA option (no sub-options).
        """

        self._option = Dhcp6OptionIaNa(iaid=1, t1=1800, t2=2880)

    def test__dhcp6__option__ia_na__len(self) -> None:
        """
        Ensure '__len__()' returns the 16-byte header+data with no sub-options.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(len(self._option), 16, msg="Unexpected option length.")

    def test__dhcp6__option__ia_na__str(self) -> None:
        """
        Ensure '__str__()' renders the IAID and timers.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(str(self._option), "ia_na iaid 1 t1 1800 t2 2880", msg="Unexpected log string.")

    def test__dhcp6__option__ia_na__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 IA_NA option [RFC 8415]:
          option-code : 0x0003 (OPTION_IA_NA)
          option-len  : 0x000c (12)
          IAID        : 0x00000001
          T1          : 0x00000708 (1800)
          T2          : 0x00000b40 (2880)

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x03\x00\x0c\x00\x00\x00\x01\x00\x00\x07\x08\x00\x00\x0b\x40",
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__ia_na__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_IA_NA.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertIs(self._option.type, Dhcp6OptionType.IA_NA, msg="Unexpected option type.")

    def test__dhcp6__option__ia_na__fields(self) -> None:
        """
        Ensure the IAID and timer fields reflect the constructor arguments.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(self._option.iaid, 1, msg="Unexpected iaid.")
        self.assertEqual(self._option.t1, 1800, msg="Unexpected t1.")
        self.assertEqual(self._option.t2, 2880, msg="Unexpected t2.")
        self.assertEqual(self._option.options, b"", msg="Unexpected options.")

    def test__dhcp6__option__ia_na__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(
            Dhcp6OptionIaNa.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )

    def test__dhcp6__option__ia_na__nested_ia_addr_preserved(self) -> None:
        """
        Ensure an IA_NA carrying an IA Address as its IA_NA-options sub-block
        roundtrips with the nested option recoverable via the codec.

        Reference: RFC 8415 §21.4 (IA_NA option; IA_NA-options).
        """

        ia_addr = Dhcp6OptionIaAddr(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=3600,
            valid_lifetime=7200,
        )
        ia_na = Dhcp6OptionIaNa(iaid=42, t1=1800, t2=2880, options=bytes(ia_addr))

        rebuilt = Dhcp6OptionIaNa.from_buffer(bytes(ia_na))

        self.assertEqual(rebuilt, ia_na, msg="IA_NA roundtrip must preserve the sub-option block.")
        self.assertEqual(
            Dhcp6OptionIaAddr.from_buffer(rebuilt.options),
            ia_addr,
            msg="The nested IA Address must be recoverable from the IA_NA sub-option block.",
        )


class TestDhcp6OptionIaNaParserErrors(TestCase):
    """
    The DHCPv6 IA_NA option parser error tests.
    """

    def test__dhcp6__option__ia_na__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa.from_buffer(b"\x00\x03\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 IA_NA option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__ia_na__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_IA_NA.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaNa.from_buffer(b"\x00\x05\x00\x0c" + b"\x00" * 12)

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 IA_NA option type must be {Dhcp6OptionType.IA_NA!r}. " f"Got: {Dhcp6OptionType.IA_ADDR!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__ia_na__data_too_short(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is below the 12-octet IAID + T1 + T2.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionIaNa.from_buffer(b"\x00\x03\x00\x08" + b"\x00" * 8)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 IA_NA option must carry the 12-octet "
            "IAID + T1 + T2 (RFC 8415 §21.4). Got: 8",
            msg="Unexpected data-too-short integrity error message.",
        )

    def test__dhcp6__option__ia_na__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionIaNa.from_buffer(b"\x00\x03\x00\x0c" + b"\x00" * 8)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 IA_NA option length value must be less "
            "than or equal to the length of provided bytes (12). Got: 16",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionIaNaBehavior(TestCase):
    """
    The DHCPv6 IA_NA option behavioral tests.
    """

    def test__dhcp6__option__ia_na__equality(self) -> None:
        """
        Ensure two options with equal fields compare equal.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(
            Dhcp6OptionIaNa(iaid=1, t1=2, t2=3),
            Dhcp6OptionIaNa(iaid=1, t1=2, t2=3),
            msg="Options with identical fields must compare equal.",
        )

    def test__dhcp6__option__ia_na__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        option = Dhcp6OptionIaNa(iaid=1, t1=2, t2=3)

        with self.assertRaises(FrozenInstanceError):
            option.iaid = 99  # type: ignore[misc]


class TestDhcp6OptionIaNaWrongType(TestCase):
    """
    The DHCPv6 Identity Association for Non-temporary Addresses option wrong-code-word parser tests.
    """

    def test__dhcp6__option__ia_na__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code word equals
        Dhcp6OptionType.IA_NA and rejects a code below it, pinning the
        equality check against a '<=' relaxation.

        Reference: RFC 8415 §21.4 (IA_NA option code 3).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionIaNa.from_buffer(b"\x00\x00\x00\x0c\x11\x22\x33\x44\x00\x00\x03\xe8\x00\x00\x07\xd0")

    def test__dhcp6__option__ia_na__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code word above
        Dhcp6OptionType.IA_NA, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 8415 §21.4 (IA_NA option code 3).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionIaNa.from_buffer(b"\xff\xff\x00\x0c\x11\x22\x33\x44\x00\x00\x03\xe8\x00\x00\x07\xd0")
