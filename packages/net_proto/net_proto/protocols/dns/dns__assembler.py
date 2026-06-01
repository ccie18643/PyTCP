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
This module contains the DNS message assembler class.

The host resolver builds a standard recursive query: one or more question
records, no answer / authority / additional records. As an L7 protocol it
is emitted as a UDP payload (via 'bytes(...)'), so 'assemble()' is not
implemented — see the DHCPv6 assembler for the same pattern.

net_proto/protocols/dns/dns__assembler.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.dns.dns__base import Dns
from net_proto.protocols.dns.dns__enums import DnsOpcode, DnsResponseCode
from net_proto.protocols.dns.dns__header import DnsHeader
from net_proto.protocols.dns.dns__question import DnsQuestion


class DnsAssembler(Dns, ProtoAssembler):
    """
    The DNS message assembler.
    """

    def __init__(
        self,
        *,
        dns__id: int,
        dns__questions: tuple[DnsQuestion, ...],
        dns__recursion_desired: bool = True,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the DNS message assembler as a standard query.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        # RFC 1035 §4.1.2 — a query carries at least one question.
        assert len(dns__questions) >= 1, "A DNS query must carry at least one question."

        self._header = DnsHeader(
            id=dns__id,
            qr=False,
            opcode=DnsOpcode.QUERY,
            aa=False,
            tc=False,
            rd=dns__recursion_desired,
            ra=False,
            z=0,
            rcode=DnsResponseCode.NOERROR,
            qdcount=len(dns__questions),
            ancount=0,
            nscount=0,
            arcount=0,
        )

        self._questions = tuple(dns__questions)
        self._answers = ()

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the DNS message into list of buffers.
        """

        raise NotImplementedError("The 'assemble()' method is not implemented for L7 protocols. Use Sockets instead.")
