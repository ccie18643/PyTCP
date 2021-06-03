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
# ps_ethernet.py - protocol suppot library for Ethernet
#


import struct

import loguru

import config
from tracker import Tracker

# Ethernet packet header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           EtherType           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ETHER_HEADER_LEN = 14

ETHER_TYPE_MIN = 0x0600
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP4 = 0x0800
ETHER_TYPE_IP6 = 0x86DD


ETHER_TYPE_TABLE = {ETHER_TYPE_ARP: "ARP", ETHER_TYPE_IP4: "IPv4", ETHER_TYPE_IP6: "IPv6"}


class EtherPacket:
    """Ethernet packet support class"""

    protocol = "ETHER"

    def __init__(self, raw_packet=None, ether_src="00:00:00:00:00:00", ether_dst="00:00:00:00:00:00", child_packet=None):
        """Class constructor"""

        if __debug__:
            self._logger = loguru.logger.bind(object_name="ps_ether.")
        self.sanity_check_failed = False

        # Packet parsing
        if raw_packet:
            self.tracker = Tracker("RX")

            if not self.__pre_parse_sanity_check(raw_packet):
                self.sanity_check_failed = True
                return

            raw_header = raw_packet[:ETHER_HEADER_LEN]

            self.raw_data = raw_packet[ETHER_HEADER_LEN:]
            self.ether_dst = ":".join([f"{_:0>2x}" for _ in raw_header[0:6]])
            self.ether_src = ":".join([f"{_:0>2x}" for _ in raw_header[6:12]])
            self.ether_type = struct.unpack("!H", raw_header[12:14])[0]

            if not self.__post_parse_sanity_check():
                self.sanity_check_failed = True

        # Packet building
        else:
            self.tracker = child_packet.tracker

            self.ether_dst = ether_dst
            self.ether_src = ether_src

            assert child_packet.protocol in {"IPv6", "IPv4", "ARP"}, f"Not supported protocol: {child_packet.protocol}"

            if child_packet.protocol == "IPv6":
                self.ether_type = ETHER_TYPE_IP6

            if child_packet.protocol == "IPv4":
                self.ether_type = ETHER_TYPE_IP4

            if child_packet.protocol == "ARP":
                self.ether_type = ETHER_TYPE_ARP

            self.raw_data = child_packet.get_raw_packet()

    def __str__(self):
        """Short packet log string"""

        return f"ETHER {self.ether_src} > {self.ether_dst}, 0x{self.ether_type:0>4x} ({ETHER_TYPE_TABLE.get(self.ether_type, '???')})"

    def __len__(self):
        """Length of the packet"""

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """Packet header in raw format"""

        return struct.pack("! 6s 6s H", bytes.fromhex(self.ether_dst.replace(":", "")), bytes.fromhex(self.ether_src.replace(":", "")), self.ether_type)

    @property
    def raw_packet(self):
        """Packet in raw format"""

        return self.raw_header + self.raw_data

    def get_raw_packet(self):
        """Get packet in raw format ready to be sent out"""

        return self.raw_packet

    def __pre_parse_sanity_check(self, raw_packet):
        """Preliminary sanity check to be run on raw Ethernet packet prior to packet parsing"""

        if not config.pre_parse_sanity_check:
            return True

        if len(raw_packet) < 14:
            if __debug__:
                self._logger.critical(f"{self.tracker} - Ethernet sanity check fail - wrong packet length (I)")
            return False

        return True

    def __post_parse_sanity_check(self):
        """Sanity check to be run on parsed Ethernet packet"""

        if not config.post_parse_sanity_check:
            return True

        if self.ether_type < ETHER_TYPE_MIN:
            if __debug__:
                self._logger.critical(f"{self.tracker} - Ethernet sanity check fail - value of ether_type < 0x0600")
            return False

        return True
