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
This module contains the IGMP packet parser.

net_proto/protocols/igmp/igmp__parser.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.igmp.igmp__base import Igmp
from net_proto.protocols.igmp.igmp__errors import IgmpIntegrityError
from net_proto.protocols.igmp.message.igmp__message import (
    IGMP__MESSAGE__MIN_LEN,
    IgmpMessage,
    IgmpType,
)
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from net_proto.protocols.igmp.message.igmp__message__unknown import (
    IgmpMessageUnknown,
)
from net_proto.protocols.igmp.message.igmp__message__v1_report import (
    IgmpMessageV1Report,
)
from net_proto.protocols.igmp.message.igmp__message__v2_leave import (
    IgmpMessageV2Leave,
)
from net_proto.protocols.igmp.message.igmp__message__v2_report import (
    IgmpMessageV2Report,
)
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)


class IgmpParser(Igmp, ProtoParser):
    """
    The IGMP packet parser.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IGMP packet parser.
        """

        self._frame = packet_rx.frame
        self._ip4__payload_len = packet_rx.ip4.payload_len

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.igmp = self
        packet_rx.frame = packet_rx.frame[self._ip4__payload_len :]

    def _message_class(self) -> type[IgmpMessage]:
        """
        Resolve the concrete IgmpMessage subclass that matches the
        frame's type byte. Falls back to IgmpMessageUnknown for
        unrecognised types (RFC 3376 §4 — silently ignored).
        """

        match IgmpType.from_int(self._frame[0]):
            case IgmpType.MEMBERSHIP_QUERY:
                return IgmpMessageQuery
            case IgmpType.V3_MEMBERSHIP_REPORT:
                return IgmpMessageV3Report
            case IgmpType.V2_MEMBERSHIP_REPORT:
                return IgmpMessageV2Report
            case IgmpType.V2_LEAVE_GROUP:
                return IgmpMessageV2Leave
            case IgmpType.V1_MEMBERSHIP_REPORT:
                return IgmpMessageV1Report
            case _:
                return IgmpMessageUnknown

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IGMP packet before parsing it.
        """

        # RFC 3376 §4 — every IGMP message is at least 8 octets; the
        # IPv4 payload-length boundary comes from the encapsulating IP
        # layer (RFC 791).
        if not (IGMP__MESSAGE__MIN_LEN <= self._ip4__payload_len <= len(self._frame)):
            raise IgmpIntegrityError(
                "The condition 'IGMP__MESSAGE__MIN_LEN <= self._ip4__payload_len <= "
                f"len(self._frame)' must be met. Got: {IGMP__MESSAGE__MIN_LEN=}, "
                f"{self._ip4__payload_len=}, {len(self._frame)=}"
            )

        self._message_class().validate_integrity(frame=self._frame, ip4__payload_len=self._ip4__payload_len)

        # RFC 3376 §4.1.2 — the checksum is the 16-bit one's complement
        # of the one's complement sum of the whole IGMP message (the
        # entire IP payload, including any §4.1.10 additional octets).
        if inet_cksum(self._frame[: self._ip4__payload_len]):
            raise IgmpIntegrityError(
                "The packet checksum must be valid.",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IGMP packet.
        """

        # Slice to the declared message length so the Query parser can
        # key its RFC 3376 §7.1 version discrimination off len(buffer).
        self._message = self._message_class().from_buffer(self._frame[: self._ip4__payload_len])

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMP packet after parsing it.
        """

        self._message.validate_sanity()
