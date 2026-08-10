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
This module contains the TCP packet parser.

net_proto/protocols/tcp/tcp__parser.py

ver 3.0.10
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.tcp.options.tcp__options import TcpOptions
from net_proto.protocols.tcp.tcp__base import Tcp
from net_proto.protocols.tcp.tcp__errors import (
    TcpIntegrityError,
    TcpSanityError,
)
from net_proto.protocols.tcp.tcp__header import TCP__HEADER__LEN, TcpHeader


class TcpParser(Tcp, ProtoParser):
    """
    The TCP packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the TCP packet parser.
        """

        self._frame = packet_rx.frame
        self._ip__payload_len = packet_rx.ip.payload_len
        self._ip__pshdr_sum = packet_rx.ip.pshdr_sum

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.tcp = self
        packet_rx.frame = packet_rx.frame[self._header.hlen :]

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the TCP packet before parsing it.
        """

        # RFC 9293 §3.1 — the TCP header is at least 20 octets
        # (the fixed prefix); the upper bound is the declared IP
        # payload length, which itself MUST NOT exceed the
        # received frame.
        if not (TCP__HEADER__LEN <= self._ip__payload_len <= len(self._frame)):
            raise TcpIntegrityError(
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {TCP__HEADER__LEN=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}",
            )

        # RFC 9293 §3.1 — Data Offset is a 4-bit field giving the
        # TCP header length in 32-bit words; minimum value is 5
        # (20 octets) and the header MUST fit within the IP-
        # declared payload.
        hlen = (self._frame[12] & 0b11110000) >> 2
        if not (TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= len(self._frame)):
            raise TcpIntegrityError(
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {TCP__HEADER__LEN=}, {hlen=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}"
            )

        # RFC 9293 §3.1 — "The checksum field is the 16 bit one's
        # complement of the one's complement sum of all 16 bit
        # words in the header and text. ... The checksum also
        # covers a pseudo header conceptually prefixed to the TCP
        # header." Algorithm: RFC 1071 one's-complement sum.
        if inet_cksum(self._frame[: self._ip__payload_len], init=self._ip__pshdr_sum):
            raise TcpIntegrityError(
                "The packet checksum must be valid.",
            )

        # RFC 9293 §3.2 (Case-2 TLV options) — walk the per-option
        # Length bytes and confirm every option fits inside the
        # declared TCP header region.
        TcpOptions.validate_integrity(frame=self._frame, hlen=hlen)

    @override
    def _parse(self) -> None:
        """
        Parse the TCP packet.
        """

        self._header = TcpHeader.from_buffer(self._frame)

        self._options = TcpOptions.from_buffer(self._frame[len(self._header) : self._header.hlen])

        self._payload = self._frame[self._header.hlen : self._ip__payload_len]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the TCP packet after parsing it.
        """

        # RFC 9293 §3.1 + RFC 6335 §6 — IANA reserves port 0 and
        # explicitly states it MUST NOT be assigned. A segment
        # carrying port 0 in either direction is invalid.
        if (value := self._header.sport) == 0:
            raise TcpSanityError(
                f"The 'sport' field must be greater than 0. Got: {value!r}",
            )

        # RFC 9293 §3.1 + RFC 6335 §6 — same as above for the
        # destination port.
        if (value := self._header.dport) == 0:
            raise TcpSanityError(
                f"The 'dport' field must be greater than 0. Got: {value!r}",
            )

        # RFC 9293 §3.1 — SYN initiates a connection (consuming
        # an ISN), FIN closes it; the two semantics are mutually
        # exclusive within a single segment.
        if self._header.flag_syn and self._header.flag_fin:
            raise TcpSanityError(
                "The 'flag_syn' and 'flag_fin' must not be set simultaneously.",
            )

        # RFC 9293 §3.1 / RFC 5961 §4 — SYN initiates, RST aborts;
        # the two semantics are mutually exclusive. RFC 5961 §4
        # specifically hardens the in-window-SYN handling.
        if self._header.flag_syn and self._header.flag_rst:
            raise TcpSanityError(
                "The 'flag_syn' and 'flag_rst' must not be set simultaneously.",
            )

        # RFC 9293 §3.1 — FIN is an orderly close, RST is an
        # abrupt abort; combining them is meaningless.
        if self._header.flag_fin and self._header.flag_rst:
            raise TcpSanityError(
                "The 'flag_fin' and 'flag_rst' must not be set simultaneously.",
            )

        # RFC 9293 §3.10.4 / RFC 9293 §3.1 — once a connection
        # is established, "the ACK bit ... is always sent" on
        # every subsequent segment; FIN is by definition sent on
        # an established connection so it MUST carry ACK.
        if self._header.flag_fin and not self._header.flag_ack:
            raise TcpSanityError(
                "The 'flag_ack' must be set when 'flag_fin' is set.",
            )
