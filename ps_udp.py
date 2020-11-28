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
# ps_udp.py - protocol support libary for UDP
#


import struct

import inet_cksum
from tracker import Tracker

# UDP packet header (RFC 768)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source port          |        Destination port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |             Length            |            Checksum           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


UDP_HEADER_LEN = 8


class UdpPacket:
    """ UDP packet support class """

    protocol = "UDP"

    def __init__(self, parent_packet=None, udp_sport=None, udp_dport=None, raw_data=None, echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:UDP_HEADER_LEN]

            self.raw_data = raw_packet[UDP_HEADER_LEN : struct.unpack("!H", raw_header[4:6])[0]]
            self.ip_pseudo_header = parent_packet.ip_pseudo_header

            self.udp_sport = struct.unpack("!H", raw_header[0:2])[0]
            self.udp_dport = struct.unpack("!H", raw_header[2:4])[0]
            self.udp_plen = struct.unpack("!H", raw_header[4:6])[0]
            self.udp_cksum = struct.unpack("!H", raw_header[6:8])[0]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.udp_sport = udp_sport
            self.udp_dport = udp_dport
            self.udp_plen = UDP_HEADER_LEN + len(raw_data)
            self.udp_cksum = 0

            self.raw_data = raw_data

    def __str__(self):
        """ Short packet log string """

        return f"UDP {self.udp_sport} > {self.udp_dport}, len {self.udp_plen}"

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack("! HH HH", self.udp_sport, self.udp_dport, self.udp_plen, self.udp_cksum)

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_data

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.udp_cksum = inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet)

        return self.raw_packet

    def validate_cksum(self, ip_pseudo_header):
        """ Validate packet checksum """

        # Return valid checksum if checksum is not used
        if not self.udp_cksum:
            return True

        return not bool(inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet))
