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
# icmp4/fpa.py - Fast Packet Assembler support class for ICMPv4 protocol
#


import struct
from typing import Optional

import icmp4.ps
import ip4.ps
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker


class Assembler:
    """ICMPv4 packet assembler support class"""

    ip4_proto = ip4.ps.PROTO_ICMP4

    def __init__(
        self,
        type: int,
        code: int = 0,
        ec_id: Optional[int] = None,
        ec_seq: Optional[int] = None,
        ec_data: Optional[bytes] = None,
        un_data: Optional[bytes] = None,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        assert type in {icmp4.ps.ECHO_REQUEST, icmp4.ps.UNREACHABLE, icmp4.ps.ECHO_REPLY}

        self.tracker = Tracker("TX", echo_tracker)
        self.type = type
        self.code = code

        if self.type == icmp4.ps.ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = b"" if ec_data is None else ec_data

        elif self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            self.un_data = b"" if un_data is None else un_data[:520]

        elif self.type == icmp4.ps.ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = b"" if ec_data is None else ec_data

    def __len__(self) -> int:
        """Length of the packet"""

        if self.type == icmp4.ps.ECHO_REPLY:
            return icmp4.ps.ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            return icmp4.ps.UNREACHABLE_LEN + len(self.un_data)

        if self.type == icmp4.ps.ECHO_REQUEST:
            return icmp4.ps.ECHO_REQUEST_LEN + len(self.ec_data)

        return 0

    from icmp4.ps import __str__

    def assemble(self, frame: bytearray, hptr: int, _: int) -> None:
        """Assemble packet into the raw form"""

        if self.type == icmp4.ps.ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, 0, self.un_data)

        elif self.type == icmp4.ps.ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        struct.pack_into("! H", frame, hptr + 2, inet_cksum(frame, hptr, len(self)))
