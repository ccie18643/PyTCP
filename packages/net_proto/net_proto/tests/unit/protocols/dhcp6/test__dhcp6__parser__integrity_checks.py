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
Module contains integrity-check tests for the DHCPv6 packet parser.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__parser__integrity_checks.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto import Dhcp6IntegrityError, Dhcp6Parser


class TestDhcp6ParserIntegrityChecks(TestCase):
    """
    The DHCPv6 packet parser integrity-check tests.
    """

    def test__dhcp6__parser__integrity__too_short(self) -> None:
        """
        Ensure a frame shorter than the 4-byte header is rejected.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6Parser(memoryview(b"\x01\x00"))

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The minimum packet length must be 4 bytes. Got: 2 bytes.",
            msg="Unexpected too-short integrity error message.",
        )

    def test__dhcp6__parser__integrity__truncated_option_header(self) -> None:
        """
        Ensure a trailing fragment shorter than a 4-byte option header is
        rejected by the option-block integrity walker.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6Parser(memoryview(b"\x01\x00\x00\x01\x00\x01\x00"))

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 option is missing its 4-byte code+len header. "
            "Got: offset=4, hlen=7",
            msg="Unexpected truncated-option integrity error message.",
        )

    def test__dhcp6__parser__integrity__option_overruns_frame(self) -> None:
        """
        Ensure an option whose advertised length extends past the frame is
        rejected by the option-block integrity walker.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6Parser(memoryview(b"\x01\x00\x00\x01\x00\x01\x00\x10\x41\x42"))

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 option length must not extend past the "
            "message length. Got: offset=24, hlen=10",
            msg="Unexpected option-overrun integrity error message.",
        )


class TestDhcp6ParserIntegrityBoundary(TestCase):
    """
    The DHCPv6 packet parser boundary-accepted tests.

    Guards against a future tightening that would reject the shortest
    valid DHCPv6 message (a bare 4-byte header with no options).
    """

    def test__dhcp6__parser__integrity__minimum_valid(self) -> None:
        """
        Ensure the shortest valid DHCPv6 message (4-byte header, no options)
        parses.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        parser = Dhcp6Parser(memoryview(b"\x01\xaa\xbb\xcc"))

        self.assertEqual(len(parser), 4, msg="A bare header message must be 4 bytes.")
