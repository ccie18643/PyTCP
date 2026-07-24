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
Module contains tests for the DHCPv6 Server Identifier option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__server_id.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionServerId,
    Dhcp6OptionType,
)


class TestDhcp6OptionServerIdAsserts(TestCase):
    """
    The DHCPv6 Server Identifier option constructor assert tests.
    """

    def test__dhcp6__option__server_id__duid_not_bytes(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'duid'
        argument is not bytes.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        value = "not bytes"

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionServerId(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'duid' field must be bytes. Got: {type(value)!r}",
            msg="Unexpected 'duid' type assert message.",
        )

    def test__dhcp6__option__server_id__duid_empty(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'duid'
        argument is empty (below the 1-octet minimum).

        Reference: RFC 8415 §11.1 (DUID length bounds).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionServerId(b"")

        self.assertEqual(
            str(error.exception),
            "The 'duid' field length must be 1..130 bytes. Got: 0 bytes",
            msg="Unexpected empty-duid assert message.",
        )

    def test__dhcp6__option__server_id__duid_over_max(self) -> None:
        """
        Ensure the constructor raises an exception when the provided 'duid'
        argument exceeds the 130-octet maximum.

        Reference: RFC 8415 §11.1 (DUID length bounds).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionServerId(b"\xff" * 131)

        self.assertEqual(
            str(error.exception),
            "The 'duid' field length must be 1..130 bytes. Got: 131 bytes",
            msg="Unexpected over-max-duid assert message.",
        )


class TestDhcp6OptionServerIdAssembler(TestCase):
    """
    The DHCPv6 Server Identifier option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 Server Identifier option (DUID-LL form).
        """

        # DUID-LL (type 3) + hw-type 1 + MAC 02:00:00:00:00:09.
        self._duid = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x09"
        self._option = Dhcp6OptionServerId(self._duid)

    def test__dhcp6__option__server_id__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + DUID bytes.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(len(self._option), 14, msg="Unexpected option length.")

    def test__dhcp6__option__server_id__str(self) -> None:
        """
        Ensure '__str__()' renders the hex DUID.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(
            str(self._option),
            f"server_id {self._duid.hex()}",
            msg="Unexpected option log string.",
        )

    def test__dhcp6__option__server_id__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 Server Identifier option [RFC 8415]:
          option-code : 0x0002 (OPTION_SERVERID)
          option-len  : 0x000a (10, DUID length)
          DUID        : 00 03 00 01 02 00 00 00 00 09

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x02\x00\x0a" + self._duid,
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__server_id__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_SERVERID.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertIs(
            self._option.type,
            Dhcp6OptionType.SERVER_ID,
            msg="Unexpected option type.",
        )

    def test__dhcp6__option__server_id__duid_field(self) -> None:
        """
        Ensure the 'duid' field reflects the constructor argument.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(self._option.duid, self._duid, msg="Unexpected DUID.")

    def test__dhcp6__option__server_id__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(
            Dhcp6OptionServerId.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )


class TestDhcp6OptionServerIdParserErrors(TestCase):
    """
    The DHCPv6 Server Identifier option parser error tests.
    """

    def test__dhcp6__option__server_id__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionServerId.from_buffer(b"\x00\x02\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 Server Identifier option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__server_id__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_SERVERID.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionServerId.from_buffer(b"\x00\x01\x00\x01\x41")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 Server Identifier option type must be {Dhcp6OptionType.SERVER_ID!r}. "
            f"Got: {Dhcp6OptionType.CLIENT_ID!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__server_id__wrong_type_above(self) -> None:
        """
        Ensure 'from_buffer()' also rejects an option code word ABOVE
        OPTION_SERVERID, pinning the code-equality assert against a '>='
        relaxation (the existing wrong-type case only exercises a code
        below it).

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionServerId.from_buffer(b"\xff\xff\x00\x01\x41")

    def test__dhcp6__option__server_id__zero_length_duid(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        DUID length is below the 1-octet minimum.

        Reference: RFC 8415 §11.1 (DUID length bounds).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionServerId.from_buffer(b"\x00\x02\x00\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Server Identifier option DUID minimum "
            "length is 1 (RFC 8415 §11.1). Got: 0",
            msg="Unexpected zero-length-duid integrity error message.",
        )

    def test__dhcp6__option__server_id__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionServerId.from_buffer(b"\x00\x02\x00\x0a\x41\x42")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Server Identifier option length value must "
            "be less than or equal to the length of provided bytes (6). Got: 14",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionServerIdBehavior(TestCase):
    """
    The DHCPv6 Server Identifier option behavioral tests.
    """

    def test__dhcp6__option__server_id__equality(self) -> None:
        """
        Ensure two options with equal DUIDs compare equal.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(
            Dhcp6OptionServerId(b"\x00\x03\x01"),
            Dhcp6OptionServerId(b"\x00\x03\x01"),
            msg="Options with identical DUIDs must compare equal.",
        )

    def test__dhcp6__option__server_id__inequality(self) -> None:
        """
        Ensure two options with different DUIDs compare unequal.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertNotEqual(
            Dhcp6OptionServerId(b"\x00\x03\x01"),
            Dhcp6OptionServerId(b"\x00\x03\x02"),
            msg="Options with different DUIDs must not compare equal.",
        )

    def test__dhcp6__option__server_id__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        option = Dhcp6OptionServerId(b"\x00\x03\x01")

        with self.assertRaises(FrozenInstanceError):
            option.duid = b"other"  # type: ignore[misc]
