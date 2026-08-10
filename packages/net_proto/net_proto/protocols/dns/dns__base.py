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
This module contains the DNS protocol base class.

The base serializes to the uncompressed canonical wire form (queries,
which carry no answers, round-trip exactly; a parsed response re-encodes
without compression — DNS message compression is not round-trip
preserving, and the host resolver never re-emits a parsed response).

net_proto/protocols/dns/dns__base.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.proto import Proto
from net_proto.protocols.dns.dns__header import DnsHeader, DnsHeaderProperties
from net_proto.protocols.dns.dns__question import DnsQuestion
from net_proto.protocols.dns.dns__resource_record import DnsResourceRecord


class Dns(Proto, DnsHeaderProperties):
    """
    The DNS protocol base.
    """

    _header: DnsHeader
    _questions: tuple[DnsQuestion, ...]
    _answers: tuple[DnsResourceRecord, ...]

    @override
    def __len__(self) -> int:
        """
        Get the DNS message length (uncompressed wire form).
        """

        return (
            len(self._header)
            + sum(len(question) for question in self._questions)
            + sum(len(answer) for answer in self._answers)
        )

    @override
    def __str__(self) -> str:
        """
        Get the DNS message log string.
        """

        kind = "response" if self._header.qr else "query"
        questions = ", ".join(f"{question.qname}/{question.qtype}" for question in self._questions)
        answers = ", ".join(f"{answer.name}/{answer.rtype}" for answer in self._answers)

        return (
            f"DNS {kind} id {self._header.id:#06x}, {self._header.rcode}"
            f"{f', q [{questions}]' if questions else ''}"
            f"{f', a [{answers}]' if answers else ''}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the DNS message representation string.
        """

        return (
            f"{type(self).__name__}(header={self._header!r}, "
            f"questions={self._questions!r}, answers={self._answers!r})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DNS message as a memoryview (uncompressed canonical form).
        """

        buffer = bytearray(self._header)
        for question in self._questions:
            buffer += bytearray(question)
        for answer in self._answers:
            buffer += bytearray(answer)

        return memoryview(buffer)

    @property
    def header(self) -> DnsHeader:
        """
        Get the DNS message '_header' attribute.
        """

        return self._header

    @property
    def questions(self) -> tuple[DnsQuestion, ...]:
        """
        Get the DNS message '_questions' attribute.
        """

        return self._questions

    @property
    def answers(self) -> tuple[DnsResourceRecord, ...]:
        """
        Get the DNS message '_answers' attribute.
        """

        return self._answers
