#!/usr/bin/env python3

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
Module contains the ICMPv4 packet parser.

pytcp/protocols/icmp4/icmp4__parser.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.icmp4.icmp4__base import Icmp4
from pytcp.protocols.icmp4.icmp4__errors import Icmp4IntegrityError
from pytcp.protocols.icmp4.message.icmp4_message import (
    ICMP4__HEADER__LEN,
    Icmp4Type,
)
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    Icmp4EchoReplyMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestMessage,
)
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Icmp4Parser(Icmp4, ProtoParser):
    """
    The ICMPv4 packet parser.
    """

    def __init__(self, *, packet_rx: PacketRx) -> None:
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

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the ICMPv4 packet before parsing it.
        """

        if not (
            ICMP4__HEADER__LEN <= self._ip4__payload_len <= len(self._frame)
        ):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__HEADER__LEN <= self._ip4__payload_len <= "
                f"len(self._frame)' must be met. Got: {ICMP4__HEADER__LEN=}, "
                f"{self._ip4__payload_len=}, {len(self._frame)=}"
            )

        match Icmp4Type.from_int(self._frame[0]):
            case Icmp4Type.ECHO_REPLY:
                Icmp4EchoReplyMessage.validate_integrity(
                    frame=self._frame, ip4__payload_len=self._ip4__payload_len
                )

            case Icmp4Type.DESTINATION_UNREACHABLE:
                Icmp4DestinationUnreachableMessage.validate_integrity(
                    frame=self._frame, ip4__payload_len=self._ip4__payload_len
                )

            case Icmp4Type.ECHO_REQUEST:
                Icmp4EchoRequestMessage.validate_integrity(
                    frame=self._frame, ip4__payload_len=self._ip4__payload_len
                )

            case _:
                Icmp4UnknownMessage.validate_integrity(
                    frame=self._frame, ip4__payload_len=self._ip4__payload_len
                )

        if inet_cksum(self._frame[: self._ip4__payload_len]):
            raise Icmp4IntegrityError(
                "The packet checksum must be valid.",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the ICMPv4 packet.
        """

        match Icmp4Type.from_bytes(self._frame[0:1]):
            case Icmp4Type.ECHO_REPLY:
                self._message = Icmp4EchoReplyMessage.from_bytes(self._frame)

            case Icmp4Type.DESTINATION_UNREACHABLE:
                self._message = Icmp4DestinationUnreachableMessage.from_bytes(
                    self._frame
                )

            case Icmp4Type.ECHO_REQUEST:
                self._message = Icmp4EchoRequestMessage.from_bytes(self._frame)

            case _:
                self._message = Icmp4UnknownMessage.from_bytes(self._frame)

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the ICMPv4 packet after parsing it.
        """

        self._message.validate_sanity()
