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
# ps_icmp4.py - protocol support library for ICMPv4
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
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
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
ICMP4_UNREACHABLE = 3
ICMP4_UNREACHABLE__NET = 0
ICMP4_UNREACHABLE__HOST = 1
ICMP4_UNREACHABLE__PROTOCOL = 2
ICMP4_UNREACHABLE__PORT = 3
ICMP4_UNREACHABLE__FAGMENTATION = 4
ICMP4_UNREACHABLE__SOURCE_ROUTE_FAILED = 5
ICMP4_ECHO_REQUEST = 8


class Icmp4Packet:
    """ ICMPv4 packet support class """

    protocol = "ICMPv4"

    def __init__(
        self,
        icmp4_type=None,
        icmp4_code=0,
        icmp4_ec_id=None,
        icmp4_ec_seq=None,
        icmp4_ec_data=b"",
        icmp4_un_data=b"",
        echo_tracker=None,
    ):
        """ Class constructor """

        self.tracker = Tracker("TX", echo_tracker)

        self.icmp4_type = icmp4_type
        self.icmp4_code = icmp4_code
        self.icmp4_cksum = 0

        if self.icmp4_type == ICMP4_ECHO_REPLY:
            self.icmp4_ec_id = icmp4_ec_id
            self.icmp4_ec_seq = icmp4_ec_seq
            self.icmp4_ec_data = icmp4_ec_data

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            self.icmp4_un_reserved = 0
            self.icmp4_un_data = icmp4_un_data[:520]

        elif self.icmp4_type == ICMP4_ECHO_REQUEST:
            self.icmp4_ec_id = icmp4_ec_id
            self.icmp4_ec_seq = icmp4_ec_seq
            self.icmp4_ec_data = icmp4_ec_data

    def __str__(self):
        """ Packet log string """

        log = f"ICMPv4 type {self.icmp4_type}, code {self.icmp4_code}"

        if self.icmp4_type == ICMP4_ECHO_REPLY:
            log += f", id {self.icmp4_ec_id}, seq {self.icmp4_ec_seq}"

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            pass

        elif self.icmp4_type == ICMP4_ECHO_REQUEST:
            log += f", id {self.icmp4_ec_id}, seq {self.icmp4_ec_seq}"

        return log

    def __len__(self):
        """ Length of the packet """

        if self.icmp4_type == ICMP4_ECHO_REPLY:
            return 8 + len(self.icmp4_ec_data)

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            return 12 + len(self.icmp4_un_data)

        elif self.icmp4_type == ICMP4_ECHO_REQUEST:
            return 8 + len(self.icmp4_ec_data)

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        if self.icmp4_type == ICMP4_ECHO_REPLY:
            raw_packet = struct.pack("! BBH HH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_ec_id, self.icmp4_ec_seq) + self.icmp4_ec_data

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            raw_packet = struct.pack("! BBH L", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_un_reserved) + self.icmp4_un_data

        elif self.icmp4_type == ICMP4_ECHO_REQUEST:
            raw_packet = struct.pack("! BBH HH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_ec_id, self.icmp4_ec_seq) + self.icmp4_ec_data

        else:
            raw_packet = struct.pack("! BBH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum) + self.unknown_message

        return raw_packet

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmp4_cksum = inet_cksum(self.raw_packet)

        return self.raw_packet
