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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpa/icmp4.py - Fast Packet Assembler support class for ICMPv4 protocol
#


import struct

import ps.icmp4
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker


class Assembler(ps.icmp4.Base):
    """ ICMPv4 packet assembler support class """

    protocol = "ICMP4"

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

        if self.type == ps.icmp4.ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == ps.icmp4.UNREACHABLE and self.code == ps.icmp4.UNREACHABLE__PORT:
            self.un_data = un_data[:520]

        elif self.type == ps.icmp4.ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

    def __len__(self):
        """ Length of the packet """

        if self.type == ps.icmp4.ECHO_REPLY:
            return ps.icmp4.ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == ps.icmp4.UNREACHABLE and self.code == ps.icmp4.UNREACHABLE__PORT:
            return ps.icmp4.UNREACHABLE_LEN + len(self.un_data)

        if self.type == ps.icmp4.ECHO_REQUEST:
            return ps.icmp4.ECHO_REQUEST_LEN + len(self.ec_data)

    def assemble(self, frame, hptr, _):
        """ Assemble packet into the raw form """

        if self.type == ps.icmp4.ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == ps.icmp4.UNREACHABLE and self.code == ps.icmp4.UNREACHABLE__PORT:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, 0, self.un_data)

        elif self.type == ps.icmp4.ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        struct.pack_into("! H", frame, hptr + 2, inet_cksum(frame, hptr, len(self)))
