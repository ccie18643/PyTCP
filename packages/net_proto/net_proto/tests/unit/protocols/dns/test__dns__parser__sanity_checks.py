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
This module contains tests for the DNS message parser sanity checks.

net_proto/tests/unit/protocols/dns/test__dns__parser__sanity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.protocols.dns.dns__errors import DnsSanityError
from net_proto.protocols.dns.dns__parser import DnsParser


class TestDnsParserSanity(TestCase):
    """
    The DNS message parser sanity-check tests.
    """

    def test__dns__parser__rejects_trailing_octets(self) -> None:
        """
        Ensure a message whose record sections do not consume every octet —
        a trailing octet after the additional section — is rejected.

        Reference: RFC 1035 §4.1 (Message format).
        """

        # A valid header-only message (all counts zero) with one extra octet.
        frame = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(DnsSanityError):
            DnsParser(memoryview(frame))
