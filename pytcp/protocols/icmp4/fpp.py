#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable = line-too-long
# pylint: disable = too-many-instance-attributes
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parser support class for the ICMPv4 protocol.

pytcp/protocols/icmp4/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib.errors import PacketIntegrityError, PacketSanityError
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.icmp4.ps import (
    ICMP4_HEADER_LEN,
    ICMP4_MESSAGE_LEN__ECHO_REPLY,
    ICMP4_MESSAGE_LEN__ECHO_REQUEST,
    ICMP4_MESSAGE_LEN__UNREACHABLE,
    Icmp4,
    Icmp4Code,
    Icmp4EchoReplyMessage,
    Icmp4EchoRequestMessage,
    Icmp4PortUnreachableMessage,
    Icmp4Type,
    Icmp4UnknownMessage,
    Icmp4UnreachableCode,
    Icmp4UnreachableMessage,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Icmp4IntegrityError(PacketIntegrityError):
    """
    Exception raised when ICMPv4 packet integrity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ICMPv4] " + message)


class Icmp4SanityError(PacketSanityError):
    """
    Exception raised when ICMPv4 packet sanity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ICMPv4] " + message)


class Icmp4Parser(Icmp4):
    """
    ICMPv4 packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip4.dlen
        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.icmp4 = self
        packet_rx.frame = packet_rx.frame[len(self) :]

    def __len__(self) -> int:
        """
        Get number of bytes remaining in the frame.
        """

        return len(self._frame)

    '''
    @property
    def __copy__(self) -> bytes:
        """
        Get the packet copy.
        """

        return bytes(self._frame[: self.plen])

    @property
    def plen(self) -> int:
        """
        Get packet length.
        """
        return self._plen
    '''

    def _validate_integrity(self) -> None:
        """
        Validate integrity of incoming packet.
        """

        if inet_cksum(self._frame[: self._plen]):
            raise Icmp4IntegrityError(
                "Wrong packet checksum.",
            )

        if not ICMP4_HEADER_LEN <= self._plen <= len(self):
            raise Icmp4IntegrityError(
                "Wrong packet length (I).",
            )

        match self._frame[0]:
            case Icmp4Type.ECHO_REPLY:
                if not ICMP4_MESSAGE_LEN__ECHO_REPLY <= self._plen <= len(self):
                    raise Icmp4IntegrityError(
                        "Wrong packet length (II)",
                    )

            case Icmp4Type.UNREACHABLE:
                if (
                    not ICMP4_MESSAGE_LEN__UNREACHABLE
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp4IntegrityError(
                        "Wrong packet length (II)",
                    )

            case Icmp4Type.ECHO_REQUEST:
                if (
                    not ICMP4_MESSAGE_LEN__ECHO_REQUEST
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp4IntegrityError(
                        "Wrong packet length (II)",
                    )

    def _parse(self) -> None:
        """
        Parse incoming packet.
        """

        match Icmp4Type.from_frame(self._frame):
            case Icmp4Type.ECHO_REPLY:
                self._message = Icmp4EchoReplyMessageParser(self._frame)

            case Icmp4Type.UNREACHABLE:
                match Icmp4UnreachableCode.from_frame(self._frame):
                    case Icmp4UnreachableCode.PORT:
                        self._message = Icmp4UnreachablePortMessageParser(
                            self._frame
                        )

            case Icmp4Type.ECHO_REQUEST:
                self._message = Icmp4EchoRequestMessageParser(self._frame)

            case _:
                self._message = Icmp4UnknownMessageParser(self._frame)

    def _validate_sanity(self) -> None:
        """
        Validate sanity of incoming packet.
        """

        if isinstance(self._message, Icmp4EchoReplyMessage):
            return

        if isinstance(self._message, Icmp4UnreachableMessage):
            return

        if isinstance(self._message, Icmp4EchoRequestMessage):
            return

        if isinstance(self._message, Icmp4UnknownMessage):
            return


#
#  The ICMPv4 message parser classes.
#


class Icmp4EchoReplyMessageParser(Icmp4EchoReplyMessage):
    """
    Message parser class for ICMPv4 Echo Reply packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Class constructor.
        """

        self._id: int = struct.unpack("! H", frame[4:6])[0]
        self._seq: int = struct.unpack("! H", frame[6:8])[0]
        self._data: bytes = frame[8:]


class Icmp4UnreachablePortMessageParser(Icmp4PortUnreachableMessage):
    """
    Message parser class for ICMPv4 Unreachable Port packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Class constructor.
        """

        self._data: bytes = frame[8:]


class Icmp4EchoRequestMessageParser(Icmp4EchoRequestMessage):
    """
    Message parser class for ICMPv4 Echo Request packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Class constructor.
        """

        self._id: int = struct.unpack("! H", frame[4:6])[0]
        self._seq: int = struct.unpack("! H", frame[6:8])[0]
        self._data: bytes = frame[8:]


class Icmp4UnknownMessageParser(Icmp4UnknownMessage):
    """
    Parser class for ICMPv4 unknown message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._type = Icmp4Type.from_frame(frame)
        self._code = Icmp4Code.from_frame(frame)
