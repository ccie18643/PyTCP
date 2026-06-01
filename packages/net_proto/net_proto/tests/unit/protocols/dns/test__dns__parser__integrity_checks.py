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
This module contains tests for the DNS message parser integrity checks.

net_proto/tests/unit/protocols/dns/test__dns__parser__integrity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.protocols.dns.dns__errors import DnsIntegrityError
from net_proto.protocols.dns.dns__parser import DnsParser


@parameterized_class(
    [
        {
            "_description": "A message shorter than the 12-octet header.",
            "_frame": b"\x12\x34\x81\x80\x00\x00",
        },
        {
            "_description": "A question label that runs past the message end.",
            # Header qd=1; a label declaring 7 octets with only 3 present.
            "_frame": b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07abc",
        },
        {
            "_description": "A question name compression pointer that loops.",
            # Header qd=1; a pointer at offset 12 targeting offset 12.
            "_frame": b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c",
        },
        {
            "_description": "An answer RDATA length that overruns the message.",
            # Header an=1; root-name answer, A, IN, ttl 0, rdlen 255, no rdata.
            "_frame": (
                b"\x12\x34\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00" b"\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\xff"
            ),
        },
    ]
)
class TestDnsParserIntegrity(TestCase):
    """
    The DNS message parser integrity-check tests.
    """

    _description: str
    _frame: bytes

    def test__dns__parser__rejects_malformed_message(self) -> None:
        """
        Ensure a structurally malformed DNS message — too short, a label or
        pointer running past the end, or an overrunning RDATA length — is
        rejected with a DNS integrity error.

        Reference: RFC 1035 §4.1 (Message format).
        """

        with self.assertRaises(DnsIntegrityError):
            DnsParser(memoryview(self._frame))


class TestDnsParserIntegrityBoundary(TestCase):
    """
    The DNS message parser integrity boundary tests.
    """

    def test__dns__parser__accepts_empty_header_only_message(self) -> None:
        """
        Ensure the shortest valid DNS message — a 12-octet header with all
        record counts zero — parses without error.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        parser = DnsParser(memoryview(b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"))

        self.assertEqual(
            (parser.questions, parser.answers),
            ((), ()),
            msg="A header-only message must parse to empty question and answer sections.",
        )
