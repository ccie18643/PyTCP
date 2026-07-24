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
This module contains tests for the DNS message parser operation.

net_proto/tests/unit/protocols/dns/test__dns__parser__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordClass, DnsRecordType
from net_proto.protocols.dns.dns__parser import DnsParser
from net_proto.protocols.dns.dns__question import DnsQuestion

# A standard A-record response for "example.com" (93.184.216.34), the
# answer name carried as a compression pointer to the question name:
#   Bytes 0-11  : header — id 0x1234, flags 0x8180 (QR/RD/RA), qd=1, an=1
#   Bytes 12-28 : question — example.com, A, IN
#   Bytes 29-44 : answer — name ptr->12, A, IN, ttl 300, rdlen 4, 93.184.216.34
_A_RESPONSE = (
    b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
    b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22"
)

# An AAAA-record response for "example.com" (2001:db8::1), the answer name
# carried as a compression pointer to the question name:
#   Bytes 0-11  : header — id 0x1235, flags 0x8180, qd=1, an=1
#   Bytes 12-28 : question — example.com, AAAA, IN
#   Bytes 29-56 : answer — name ptr->12, AAAA, IN, ttl 300, rdlen 16, 2001:db8::1
_AAAA_RESPONSE = (
    b"\x12\x35\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x1c\x00\x01"
    b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10"
    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
)


class TestDnsParserOperation(TestCase):
    """
    The DNS message parser operation tests.
    """

    def test__dns__parser__a_response_header(self) -> None:
        """
        Ensure the parser decodes the response header — QR set, one
        question, one answer.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        parser = DnsParser(memoryview(_A_RESPONSE))

        self.assertEqual(
            (parser.id, parser.qr, parser.qdcount, parser.ancount),
            (0x1234, True, 1, 1),
            msg="The parser must decode the response header fields.",
        )

    def test__dns__parser__a_response_question(self) -> None:
        """
        Ensure the parser decodes the echoed question record.

        Reference: RFC 1035 §4.1.2 (Question section format).
        """

        parser = DnsParser(memoryview(_A_RESPONSE))

        self.assertEqual(
            parser.questions,
            (DnsQuestion(qname="example.com", qtype=DnsRecordType.A, qclass=DnsRecordClass.IN),),
            msg="The parser must decode the echoed question record.",
        )

    def test__dns__parser__a_response_answer_address(self) -> None:
        """
        Ensure the parser decodes the A answer, resolving its compressed
        name and exposing the IPv4 address and TTL.

        Reference: RFC 1035 §3.4.1 (A RDATA format).
        """

        parser = DnsParser(memoryview(_A_RESPONSE))
        answer = parser.answers[0]

        self.assertEqual(
            (answer.name, answer.rtype, answer.ttl, answer.address),
            ("example.com", DnsRecordType.A, 300, Ip4Address("93.184.216.34")),
            msg="The parser must decode the A answer name, TTL, and IPv4 address.",
        )

    def test__dns__parser__aaaa_response_answer_address(self) -> None:
        """
        Ensure the parser decodes the AAAA answer, resolving its
        compressed name and exposing the IPv6 address.

        Reference: RFC 3596 §2.2 (AAAA RDATA format).
        """

        parser = DnsParser(memoryview(_AAAA_RESPONSE))
        answer = parser.answers[0]

        self.assertEqual(
            (answer.rtype, answer.address),
            (DnsRecordType.AAAA, Ip6Address("2001:db8::1")),
            msg="The parser must decode the AAAA answer's IPv6 address.",
        )
