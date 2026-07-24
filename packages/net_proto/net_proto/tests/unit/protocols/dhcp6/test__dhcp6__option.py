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
This module contains tests for the DHCPv6 option base codepoint enum.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import Dhcp6OptionType


class TestDhcp6OptionType(TestCase):
    """
    The DHCPv6 16-bit option-code enum width tests.
    """

    def test__dhcp6__option_type__bytes_is_two_octets(self) -> None:
        """
        Ensure 'bytes()' on a DHCPv6 option code yields the 2-octet wire form
        — the option-code is 16-bit, unlike the 8-bit DHCPv4 option code.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            bytes(Dhcp6OptionType.CLIENT_ID),
            b"\x00\x01",
            msg="A DHCPv6 option code must serialise as two octets.",
        )

    def test__dhcp6__option_type__from_bytes_reads_two_octets(self) -> None:
        """
        Ensure 'from_bytes()' decodes the 2-octet wire form of a DHCPv6 option
        code.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertIs(
            Dhcp6OptionType.from_bytes(b"\x00\x17"),
            Dhcp6OptionType.DNS_SERVERS,
            msg="A DHCPv6 option code must decode from two octets.",
        )

    def test__dhcp6__option_type__from_bytes_unknown(self) -> None:
        """
        Ensure 'from_bytes()' materialises an unknown 2-octet option code as an
        UNKNOWN ProtoEnum member preserving the wire value.

        Reference: RFC 8415 §16 (unknown options discarded by the receiver).
        """

        option_type = Dhcp6OptionType.from_bytes(b"\xab\xcd")

        self.assertTrue(option_type.is_unknown, msg="Unknown option code must materialise as UNKNOWN.")
        self.assertEqual(int(option_type), 0xABCD, msg="Unknown option code must preserve its wire value.")
