#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

import icmp4.ps
import ip4.ps
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker


class Assembler(icmp4.ps.Base):
    """ ICMPv4 packet assembler support class """

    ip4_proto = ip4.ps.PROTO_ICMP4

    def __init__(
        self,
        type,
        code=0,
        ec_id=None,
        ec_seq=None,
        ec_data=b"",
        un_data=b"",
        echo_tracker=None,
    ):
        """ Class constructor """

        self.tracker = Tracker("TX", echo_tracker)

        self.type = type
        self.code = code

        if self.type == icmp4.ps.ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            self.un_data = un_data[:520]

        elif self.type == icmp4.ps.ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

    def __len__(self):
        """ Length of the packet """

        if self.type == icmp4.ps.ECHO_REPLY:
            return icmp4.ps.ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            return icmp4.ps.UNREACHABLE_LEN + len(self.un_data)

        if self.type == icmp4.ps.ECHO_REQUEST:
            return icmp4.ps.ECHO_REQUEST_LEN + len(self.ec_data)

    def assemble(self, frame, hptr, _):
        """ Assemble packet into the raw form """

        if self.type == icmp4.ps.ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp4.ps.UNREACHABLE and self.code == icmp4.ps.UNREACHABLE__PORT:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, 0, self.un_data)

        elif self.type == icmp4.ps.ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        struct.pack_into("! H", frame, hptr + 2, inet_cksum(frame, hptr, len(self)))
