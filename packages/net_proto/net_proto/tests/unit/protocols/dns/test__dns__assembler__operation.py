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
This module contains tests for the DNS message assembler operation.

net_proto/tests/unit/protocols/dns/test__dns__assembler__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.protocols.dns.dns__assembler import DnsAssembler
from net_proto.protocols.dns.dns__enums import DnsRecordClass, DnsRecordType
from net_proto.protocols.dns.dns__question import DnsQuestion


class TestDnsAssemblerOperation(TestCase):
    """
    The DNS message assembler operation tests.
    """

    def test__dns__assembler__builds_standard_query(self) -> None:
        """
        Ensure the assembler builds a standard recursive A query: a header
        with QR=0, opcode=Query, RD=1, qdcount=1, followed by the encoded
        question.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        assembler = DnsAssembler(
            dns__id=0x1234,
            dns__questions=(DnsQuestion(qname="example.com", qtype=DnsRecordType.A, qclass=DnsRecordClass.IN),),
        )

        self.assertEqual(
            bytes(assembler),
            # id 0x1234; flags 0x0100 (RD=1); qd=1, an/ns/ar=0;
            # question example.com A IN.
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" b"\x07example\x03com\x00\x00\x01\x00\x01",
            msg="The assembler must build a standard recursive A query.",
        )

    def test__dns__assembler__recursion_desired_clearable(self) -> None:
        """
        Ensure the RD (recursion desired) flag can be cleared, producing a
        non-recursive query with a zero flag word.

        Reference: RFC 1035 §4.1.1 (RD — recursion desired).
        """

        assembler = DnsAssembler(
            dns__id=0x0001,
            dns__recursion_desired=False,
            dns__questions=(DnsQuestion(qname="a", qtype=DnsRecordType.A, qclass=DnsRecordClass.IN),),
        )

        self.assertEqual(
            bytes(assembler)[2:4],
            b"\x00\x00",
            msg="Clearing recursion-desired must zero the flag word.",
        )

    def test__dns__assembler__aaaa_question_type(self) -> None:
        """
        Ensure an AAAA query encodes the AAAA (28) QTYPE in the question.

        Reference: RFC 3596 §2.1 (AAAA resource record type).
        """

        assembler = DnsAssembler(
            dns__id=0x0002,
            dns__questions=(DnsQuestion(qname="ipv6.example", qtype=DnsRecordType.AAAA, qclass=DnsRecordClass.IN),),
        )

        self.assertEqual(
            bytes(assembler)[-4:],
            b"\x00\x1c\x00\x01",
            msg="An AAAA query must encode QTYPE 28 and QCLASS IN.",
        )

    def test__dns__assembler__rejects_empty_questions(self) -> None:
        """
        Ensure building a query with no questions is rejected.

        Reference: RFC 1035 §4.1.2 (Question section format).
        """

        with self.assertRaises(AssertionError):
            DnsAssembler(dns__id=0x0003, dns__questions=())

    def test__dns__assembler__assemble_not_implemented(self) -> None:
        """
        Ensure the buffer-list 'assemble' method is not implemented for the
        L7 DNS protocol (it is emitted as a UDP payload).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = DnsAssembler(
            dns__id=0x0004,
            dns__questions=(DnsQuestion(qname="example.com", qtype=DnsRecordType.A, qclass=DnsRecordClass.IN),),
        )

        with self.assertRaises(NotImplementedError):
            assembler.assemble([])
