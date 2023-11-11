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

# pylint: disable = redefined-builtin

"""
Module contains Fast Packet Assembler support class for the ICMPv4 protocol.

pytcp/protocols/icmp4/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp4.ps import (
    ICMP4_MESSAGE_LEN__ECHO_REPLY,
    ICMP4_MESSAGE_LEN__ECHO_REQUEST,
    ICMP4_MESSAGE_LEN__UNREACHABLE,
    ICMP4_UNREACHABLE_ORIGINAL_DATAGRAM_LEN,
    Icmp4,
    Icmp4EchoReplyMessage,
    Icmp4EchoRequestMessage,
    Icmp4Message,
    Icmp4PortUnreachableMessage,
)
from pytcp.protocols.ip4.ps import IP4_HEADER_LEN


class Icmp4Assembler(Icmp4):
    """
    ICMPv4 packet assembler support class.
    """

    def __init__(
        self,
        *,
        message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Create the ICMPv4 packet assembler object.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._message = message

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        return len(self._message)

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """

        return self._tracker

    def assemble(self, /, frame: memoryview, _: int = 0) -> None:
        """
        Write packet into the provided frame.
        """

        struct.pack_into(f"{len(self)}s", frame, 0, bytes(self))
        struct.pack_into("! H", frame, 2, inet_cksum(frame))


#
#  The ICMPv4 message assembler classes.
#


class Icmp4EchoReplyMessageAssembler(Icmp4EchoReplyMessage):
    """
    Assembler class for the ICMPv4 Echo Reply message.
    """

    def __init__(
        self,
        *,
        id: int = 0,
        seq: int = 0,
        data: bytes = b"",
    ) -> None:
        """
        Create the ICMPv4 Echo Reply message assembler object.
        """

        assert 0 <= id <= 0xFFFF
        assert 0 <= seq <= 0xFFFF
        assert (
            len(data) <= 0xFFFF - IP4_HEADER_LEN - ICMP4_MESSAGE_LEN__ECHO_REPLY
        )

        self._id = id
        self._seq = seq
        self._data = data


class Icmp4PortUnreachableMessageAssembler(Icmp4PortUnreachableMessage):
    """
    Assembler class for the ICMPv4 Port Unreachable message.
    """

    def __init__(self, *, data: bytes = b"") -> None:
        """
        Create the ICMPv4 Port Unreachable message assembler object.
        """

        assert (
            len(data)
            <= 0xFFFF - IP4_HEADER_LEN - ICMP4_MESSAGE_LEN__UNREACHABLE
        )

        self._data = data[:ICMP4_UNREACHABLE_ORIGINAL_DATAGRAM_LEN]


class Icmp4EchoRequestMessageAssembler(Icmp4EchoRequestMessage):
    """
    Assembler class for the ICMPv4 Echo Request message.
    """

    def __init__(
        self,
        *,
        id: int = 0,
        seq: int = 0,
        data: bytes = b"",
    ) -> None:
        """
        Create the ICMPv4 Echo Request message assembler object.
        """

        assert 0 <= id <= 0xFFFF
        assert 0 <= seq <= 0xFFFF
        assert (
            len(data)
            <= 0xFFFF - IP4_HEADER_LEN - ICMP4_MESSAGE_LEN__ECHO_REQUEST
        )

        self._id = id
        self._seq = seq
        self._data = data
