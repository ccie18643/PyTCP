#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# protocols/icmp4/fpa.py - Fast Packet Assembler support class for ICMPv4 protocol
#


from __future__ import annotations

import struct

from lib.tracker import Tracker
from misc.ip_helper import inet_cksum
from protocols.icmp4.ps import (
    ICMP4_ECHO_REPLY,
    ICMP4_ECHO_REPLY_LEN,
    ICMP4_ECHO_REQUEST,
    ICMP4_ECHO_REQUEST_LEN,
    ICMP4_UNREACHABLE,
    ICMP4_UNREACHABLE__PORT,
    ICMP4_UNREACHABLE_LEN,
)
from protocols.ip4.ps import IP4_PROTO_ICMP4


class Icmp4Assembler:
    """ICMPv4 packet assembler support class"""

    ip4_proto = IP4_PROTO_ICMP4

    def __init__(
        self,
        *,
        type: int = 0,
        code: int = 0,
        ec_id: int = 0,
        ec_seq: int = 0,
        ec_data: bytes = b"",
        un_data: bytes = b"",
        echo_tracker: Tracker | None = None,
    ) -> None:
        """Class constructor"""

        assert 0 <= ec_id <= 0xFFFF
        assert 0 <= ec_seq <= 0xFFFF

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._type: int = type
        self._code: int = code

        if self._type == ICMP4_ECHO_REPLY and self._code == 0:
            self._ec_id = ec_id
            self._ec_seq = ec_seq
            self._ec_data = ec_data
            return

        if self._type == ICMP4_UNREACHABLE and self._code == ICMP4_UNREACHABLE__PORT:
            self._un_data = un_data[:520]
            return

        if self._type == ICMP4_ECHO_REQUEST and self._code == 0:
            self._ec_id = ec_id
            self._ec_seq = ec_seq
            self._ec_data = ec_data
            return

        assert False, "Unknown ICMPv4 Type/Code"

    def __len__(self) -> int:
        """Length of the packet"""

        if self._type == ICMP4_ECHO_REPLY:
            return ICMP4_ECHO_REPLY_LEN + len(self._ec_data)

        if self._type == ICMP4_UNREACHABLE and self._code == ICMP4_UNREACHABLE__PORT:
            return ICMP4_UNREACHABLE_LEN + len(self._un_data)

        if self._type == ICMP4_ECHO_REQUEST:
            return ICMP4_ECHO_REQUEST_LEN + len(self._ec_data)

        assert False, "Unknown ICMPv4 Type/Code"

    def __str__(self) -> str:
        """Packet log string"""

        if self._type == ICMP4_ECHO_REPLY and self._code == 0:
            return f"ICMPv4 {self._type}/{self._code} (echo_reply), id {self._ec_id}, seq {self._ec_seq}, dlen {len(self._ec_data)}"

        if self._type == ICMP4_UNREACHABLE and self._code == ICMP4_UNREACHABLE__PORT:
            return f"ICMPv4 {self._type}/{self._code} (unreachable_port), dlen {len(self._un_data)}"

        if self._type == ICMP4_ECHO_REQUEST and self._code == 0:
            return f"ICMPv4 {self._type}/{self._code} (echo_request), id {self._ec_id}, seq {self._ec_seq}, dlen {len(self._ec_data)}"

        assert False, "Unknown ICMPv4 Type/Code"

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    def assemble(self, frame: memoryview, _: int = 0) -> None:
        """Assemble packet into the raw form"""

        if self._type == ICMP4_ECHO_REPLY and self._code == 0:
            struct.pack_into(f"! BBH HH {len(self._ec_data)}s", frame, 0, self._type, self._code, 0, self._ec_id, self._ec_seq, bytes(self._ec_data))
            struct.pack_into("! H", frame, 2, inet_cksum(frame))
            return

        if self._type == ICMP4_UNREACHABLE and self._code == ICMP4_UNREACHABLE__PORT:
            struct.pack_into(f"! BBH L {len(self._un_data)}s", frame, 0, self._type, self._code, 0, 0, bytes(self._un_data))
            struct.pack_into("! H", frame, 2, inet_cksum(frame))
            return

        if self._type == ICMP4_ECHO_REQUEST and self._code == 0:
            struct.pack_into(f"! BBH HH {len(self._ec_data)}s", frame, 0, self._type, self._code, 0, self._ec_id, self._ec_seq, bytes(self._ec_data))
            struct.pack_into("! H", frame, 2, inet_cksum(frame))
            return

        assert False, "Unknown ICMPv4 Type/Code"
