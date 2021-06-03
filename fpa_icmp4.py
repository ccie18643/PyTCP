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
# fpa_icmp4.py - Fast Packet Assembler support class for ICMPv4 protocol
#


import struct

from ip_helper import inet_cksum
from tracker import Tracker

# Echo reply message (0/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4_ECHO_REPLY = 0
ICMP4_ECHO_REPLY_LEN = 8
ICMP4_UNREACHABLE = 3
ICMP4_UNREACHABLE_LEN = 8
ICMP4_UNREACHABLE__NET = 0
ICMP4_UNREACHABLE__HOST = 1
ICMP4_UNREACHABLE__PROTOCOL = 2
ICMP4_UNREACHABLE__PORT = 3
ICMP4_UNREACHABLE__FAGMENTATION = 4
ICMP4_UNREACHABLE__SOURCE_ROUTE_FAILED = 5
ICMP4_ECHO_REQUEST = 8
ICMP4_ECHO_REQUEST_LEN = 8


class Icmp4Packet:
    """ICMPv4 packet support class"""

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
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)

        self.type = type
        self.code = code

        if self.type == ICMP4_ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            self.un_data = un_data[:520]

        elif self.type == ICMP4_ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

    def __str__(self):
        """Packet log string"""

        log = f"ICMPv4 type {self.type}, code {self.code}"

        if self.type == ICMP4_ECHO_REPLY:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            pass

        elif self.type == ICMP4_ECHO_REQUEST:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        return log

    def __len__(self):
        """Length of the packet"""

        if self.type == ICMP4_ECHO_REPLY:
            return ICMP4_ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            return ICMP4_UNREACHABLE_LEN + len(self.un_data)

        if self.type == ICMP4_ECHO_REQUEST:
            return ICMP4_ECHO_REQUEST_LEN + len(self.ec_data)

    def assemble_packet(self, frame, hptr, _):
        """Assemble packet into the raw form"""

        if self.type == ICMP4_ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, 0, self.un_data)

        elif self.type == ICMP4_ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        struct.pack_into("! H", frame, hptr + 2, inet_cksum(frame, hptr, len(self)))
