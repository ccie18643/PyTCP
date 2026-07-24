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
This module contains the ICMPv4 packet parser.

net_proto/protocols/icmp4/icmp4__parser.py

ver 3.0.9
"""

from typing import override

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.icmp4.icmp4__base import Icmp4
from net_proto.protocols.icmp4.icmp4__errors import Icmp4IntegrityError
from net_proto.protocols.icmp4.message.icmp4__message import (
    ICMP4__HEADER__LEN,
    Icmp4Message,
    Icmp4Type,
)
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4MessageDestinationUnreachable,
)
from net_proto.protocols.icmp4.message.icmp4__message__echo_reply import (
    Icmp4MessageEchoReply,
)
from net_proto.protocols.icmp4.message.icmp4__message__echo_request import (
    Icmp4MessageEchoRequest,
)
from net_proto.protocols.icmp4.message.icmp4__message__parameter_problem import (
    Icmp4MessageParameterProblem,
)
from net_proto.protocols.icmp4.message.icmp4__message__time_exceeded import (
    Icmp4MessageTimeExceeded,
)
from net_proto.protocols.icmp4.message.icmp4__message__unknown import (
    Icmp4MessageUnknown,
)


class Icmp4Parser(Icmp4, ProtoParser):
    """
    The ICMPv4 packet parser.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the ICMPv4 packet parser.
        """

        self._frame = packet_rx.frame
        self._ip4__payload_len = packet_rx.ip4.payload_len

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.icmp4 = self
        packet_rx.frame = packet_rx.frame[len(self) :]

    def _message_class(self) -> type[Icmp4Message]:
        """
        Resolve the concrete Icmp4Message subclass that matches the frame's
        type byte. Falls back to Icmp4MessageUnknown for unrecognised types.
        """

        match Icmp4Type.from_int(self._frame[0]):
            case Icmp4Type.ECHO_REPLY:
                return Icmp4MessageEchoReply
            case Icmp4Type.DESTINATION_UNREACHABLE:
                return Icmp4MessageDestinationUnreachable
            case Icmp4Type.ECHO_REQUEST:
                return Icmp4MessageEchoRequest
            case Icmp4Type.TIME_EXCEEDED:
                return Icmp4MessageTimeExceeded
            case Icmp4Type.PARAMETER_PROBLEM:
                return Icmp4MessageParameterProblem
            case _:
                return Icmp4MessageUnknown

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the ICMPv4 packet before parsing it.
        """

        # RFC 792 §"Message Formats" — the common 4-byte header (type / code /
        # checksum) is the structural minimum; the IPv4 payload-length boundary
        # comes from the encapsulating IP layer (RFC 791).
        if not (ICMP4__HEADER__LEN <= self._ip4__payload_len <= len(self._frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__HEADER__LEN <= self._ip4__payload_len <= "
                f"len(self._frame)' must be met. Got: {ICMP4__HEADER__LEN=}, "
                f"{self._ip4__payload_len=}, {len(self._frame)=}"
            )

        # RFC 792 — each message type has a fixed-size header (Echo {Req,Reply}
        # = 8 bytes; Destination Unreachable / Time Exceeded / Parameter
        # Problem all carry the 4-byte common header + a 4-byte type-specific
        # word). The per-message validator enforces that floor against the
        # encapsulating IPv4 payload length.
        self._message_class().validate_integrity(frame=self._frame, ip4__payload_len=self._ip4__payload_len)

        # RFC 792 — "Checksum is the 16-bit ones's complement of the one's
        # complement sum of the ICMP message starting with the ICMP Type. For
        # computing the checksum, the checksum field should be zero." A frame
        # whose ones'-complement sum is not zero has a corrupt checksum.
        if inet_cksum(self._frame[: self._ip4__payload_len]):
            raise Icmp4IntegrityError(
                "The packet checksum must be valid.",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the ICMPv4 packet.
        """

        self._message = self._message_class().from_buffer(self._frame)

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 packet after parsing it.
        """

        self._message.validate_sanity()
