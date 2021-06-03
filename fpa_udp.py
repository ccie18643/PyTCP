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
# fpa_udp.py - Fast Packet Assembler support class for UDP protocol
#


import struct

from ip_helper import inet_cksum
from tracker import Tracker

# UDP packet header (RFC 768)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source port          |        Destination port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Packet length         |            Checksum           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


UDP_HEADER_LEN = 8


class UdpPacket:
    """UDP packet support class"""

    protocol = "UDP"

    def __init__(self, sport, dport, data=b"", echo_tracker=None):
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)

        self.sport = sport
        self.dport = dport
        self.data = data
        self.plen = UDP_HEADER_LEN + len(self.data)

    def __str__(self):
        """Packet log string"""

        return f"UDP {self.sport} > {self.dport}, len {self.plen}"

    def __len__(self):
        """Length of the packet"""

        return self.plen

    def assemble_packet(self, frame, hptr, pshdr_sum):
        """Assemble packet into the raw form"""

        struct.pack_into(f"! HH HH {len(self.data)}s", frame, hptr, self.sport, self.dport, self.plen, 0, self.data)
        struct.pack_into("! H", frame, hptr + 6, inet_cksum(frame, hptr, self.plen, pshdr_sum))
