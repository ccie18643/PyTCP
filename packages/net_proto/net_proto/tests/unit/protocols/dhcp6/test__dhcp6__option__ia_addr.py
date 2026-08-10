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
Module contains tests for the DHCPv6 IA Address option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__ia_addr.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    UINT_32__MAX,
    Dhcp6IntegrityError,
    Dhcp6OptionIaAddr,
    Dhcp6OptionType,
)


class TestDhcp6OptionIaAddrAsserts(TestCase):
    """
    The DHCPv6 IA Address option constructor assert tests.
    """

    def _kwargs(self) -> dict[str, object]:
        """
        Return a reference valid IA Address kwargs set.
        """

        return {
            "address": Ip6Address("2001:db8::100"),
            "preferred_lifetime": 3600,
            "valid_lifetime": 7200,
        }

    def test__dhcp6__option__ia_addr__address_not_ip6(self) -> None:
        """
        Ensure the constructor raises an exception when 'address' is not an
        Ip6Address.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        kwargs = self._kwargs() | {"address": "not an Ip6Address"}

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'address' field must be an Ip6Address. Got: {type('x')!r}",
            msg="Unexpected address assert message.",
        )

    def test__dhcp6__option__ia_addr__preferred_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 'preferred_lifetime'
        exceeds the 32-bit maximum.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        value = UINT_32__MAX + 1
        kwargs = self._kwargs() | {"preferred_lifetime": value}

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected preferred_lifetime assert message.",
        )

    def test__dhcp6__option__ia_addr__valid_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 'valid_lifetime'
        exceeds the 32-bit maximum.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        value = UINT_32__MAX + 1
        kwargs = self._kwargs() | {"valid_lifetime": value}

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected valid_lifetime assert message.",
        )

    def test__dhcp6__option__ia_addr__options_not_bytes(self) -> None:
        """
        Ensure the constructor raises an exception when 'options' is not bytes.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        kwargs = self._kwargs() | {"options": "not bytes"}

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr(**kwargs)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be bytes. Got: {type('x')!r}",
            msg="Unexpected options assert message.",
        )


class TestDhcp6OptionIaAddrAssembler(TestCase):
    """
    The DHCPv6 IA Address option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 IA Address option (no sub-options).
        """

        self._option = Dhcp6OptionIaAddr(
            address=Ip6Address("2001:db8::100"),
            preferred_lifetime=3600,
            valid_lifetime=7200,
        )

    def test__dhcp6__option__ia_addr__len(self) -> None:
        """
        Ensure '__len__()' returns the 28-byte header+data with no sub-options.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(len(self._option), 28, msg="Unexpected option length.")

    def test__dhcp6__option__ia_addr__str(self) -> None:
        """
        Ensure '__str__()' renders the address and lifetimes.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            str(self._option),
            "ia_addr 2001:db8::100 pref 3600 valid 7200",
            msg="Unexpected log string.",
        )

    def test__dhcp6__option__ia_addr__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 IA Address option [RFC 8415]:
          option-code        : 0x0005 (OPTION_IAADDR)
          option-len         : 0x0018 (24)
          IPv6-address       : 2001:db8::100
          preferred-lifetime : 0x00000e10 (3600)
          valid-lifetime     : 0x00001c20 (7200)

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x05\x00\x18" + bytes(Ip6Address("2001:db8::100")) + b"\x00\x00\x0e\x10\x00\x00\x1c\x20",
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__ia_addr__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_IAADDR.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertIs(self._option.type, Dhcp6OptionType.IA_ADDR, msg="Unexpected option type.")

    def test__dhcp6__option__ia_addr__fields(self) -> None:
        """
        Ensure the address and lifetime fields reflect the constructor
        arguments.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(self._option.address, Ip6Address("2001:db8::100"), msg="Unexpected address.")
        self.assertEqual(self._option.preferred_lifetime, 3600, msg="Unexpected preferred_lifetime.")
        self.assertEqual(self._option.valid_lifetime, 7200, msg="Unexpected valid_lifetime.")
        self.assertEqual(self._option.options, b"", msg="Unexpected options.")

    def test__dhcp6__option__ia_addr__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            Dhcp6OptionIaAddr.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )

    def test__dhcp6__option__ia_addr__roundtrip_with_suboptions(self) -> None:
        """
        Ensure an IA Address carrying an opaque IAaddr-options sub-block
        roundtrips with the sub-block preserved.

        Reference: RFC 8415 §21.6 (IA Address option; IAaddr-options).
        """

        option = Dhcp6OptionIaAddr(
            address=Ip6Address("2001:db8::1"),
            preferred_lifetime=100,
            valid_lifetime=200,
            options=b"\x00\x0d\x00\x02\x00\x00",
        )

        self.assertEqual(
            Dhcp6OptionIaAddr.from_buffer(bytes(option)),
            option,
            msg="IAaddr-options sub-block must be preserved through a roundtrip.",
        )


class TestDhcp6OptionIaAddrParserErrors(TestCase):
    """
    The DHCPv6 IA Address option parser error tests.
    """

    def test__dhcp6__option__ia_addr__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr.from_buffer(b"\x00\x05\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 IA Address option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__ia_addr__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_IAADDR.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionIaAddr.from_buffer(b"\x00\x03\x00\x18" + b"\x00" * 24)

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 IA Address option type must be {Dhcp6OptionType.IA_ADDR!r}. "
            f"Got: {Dhcp6OptionType.IA_NA!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__ia_addr__wrong_type_above(self) -> None:
        """
        Ensure 'from_buffer()' also rejects an option code word ABOVE
        OPTION_IAADDR, pinning the code-equality assert against a '>='
        relaxation (the existing wrong-type case only exercises a code
        below it).

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionIaAddr.from_buffer(b"\xff\xff\x00\x18" + b"\x00" * 24)

    def test__dhcp6__option__ia_addr__data_too_short(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is below the 24-octet address + lifetimes.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionIaAddr.from_buffer(b"\x00\x05\x00\x10" + b"\x00" * 16)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 IA Address option must carry the 24-octet "
            "address + lifetimes (RFC 8415 §21.6). Got: 16",
            msg="Unexpected data-too-short integrity error message.",
        )

    def test__dhcp6__option__ia_addr__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionIaAddr.from_buffer(b"\x00\x05\x00\x18" + b"\x00" * 16)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 IA Address option length value must be less "
            "than or equal to the length of provided bytes (20). Got: 28",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionIaAddrBehavior(TestCase):
    """
    The DHCPv6 IA Address option behavioral tests.
    """

    def test__dhcp6__option__ia_addr__equality(self) -> None:
        """
        Ensure two options with equal fields compare equal.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::1"), preferred_lifetime=1, valid_lifetime=2),
            Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::1"), preferred_lifetime=1, valid_lifetime=2),
            msg="Options with identical fields must compare equal.",
        )

    def test__dhcp6__option__ia_addr__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        option = Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::1"), preferred_lifetime=1, valid_lifetime=2)

        with self.assertRaises(FrozenInstanceError):
            option.preferred_lifetime = 99  # type: ignore[misc]
