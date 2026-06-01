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
This module contains the DNS message parser class.

Variable-section integrity (label bounds, compression-pointer loops,
RDATA bounds) is enforced during '_parse' by the 'decode_name' /
'from_frame' helpers, which raise 'DnsIntegrityError' — the same
from_buffer-can-raise pattern net_proto uses for DHCPv4 (see
net_proto.md §7). '_validate_sanity' then rejects a message with trailing
octets after the four record sections.

net_proto/protocols/dns/dns__parser.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.dns.dns__base import Dns
from net_proto.protocols.dns.dns__errors import DnsIntegrityError, DnsSanityError
from net_proto.protocols.dns.dns__header import DNS__HEADER__LEN, DnsHeader
from net_proto.protocols.dns.dns__question import DnsQuestion
from net_proto.protocols.dns.dns__resource_record import DnsResourceRecord


class DnsParser(Dns, ProtoParser):
    """
    The DNS message parser.
    """

    _parsed_len: int

    def __init__(self, data_rx: memoryview) -> None:
        """
        Initialize the DNS message parser.
        """

        self._frame = data_rx

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the DNS message before parsing it.
        """

        # RFC 1035 §4.1.1 — the header section is a fixed 12 octets.
        if len(self._frame) < DNS__HEADER__LEN:
            raise DnsIntegrityError(
                f"The minimum message length must be {DNS__HEADER__LEN} octets. Got: {len(self._frame)} octets."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the DNS message header and record sections.
        """

        self._header = DnsHeader.from_buffer(self._frame)

        offset = DNS__HEADER__LEN

        questions: list[DnsQuestion] = []
        for _ in range(self._header.qdcount):
            question, offset = DnsQuestion.from_frame(self._frame, offset)
            questions.append(question)

        answers: list[DnsResourceRecord] = []
        for _ in range(self._header.ancount):
            answer, offset = DnsResourceRecord.from_frame(self._frame, offset)
            answers.append(answer)

        # Walk the authority and additional sections to validate framing
        # and locate the message end; the host resolver keeps only the
        # answer section, so these records are parsed and discarded.
        for _ in range(self._header.nscount + self._header.arcount):
            _record, offset = DnsResourceRecord.from_frame(self._frame, offset)

        self._questions = tuple(questions)
        self._answers = tuple(answers)
        self._parsed_len = offset

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the DNS message after parsing it.
        """

        # The four record sections must account for every octet; trailing
        # data after the additional section is a malformed message.
        if (value := self._parsed_len) != len(self._frame):
            raise DnsSanityError(
                f"The record sections must consume the whole message. " f"Got: {value=}, {len(self._frame)=}",
            )
