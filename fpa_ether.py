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
# fpa_ether.py - Fast Packet Assembler support class for Ethernet protocol
#


import struct

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

    def __init__(self, child_packet, src="00:00:00:00:00:00", dst="00:00:00:00:00:00"):
        """Class constructor"""

        assert child_packet.protocol in {"IP6", "IP4", "ARP"}, f"Not supported protocol: {child_packet.protocol}"
        self._child_packet = child_packet

        self.tracker = self._child_packet.tracker

        self.dst = dst
        self.src = src

        if self._child_packet.protocol == "IP6":
            self.type = ETHER_TYPE_IP6

        if self._child_packet.protocol == "IP4":
            self.type = ETHER_TYPE_IP4

        if self._child_packet.protocol == "ARP":
            self.type = ETHER_TYPE_ARP

    def __str__(self):
        """Packet log string"""

        return f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} ({ETHER_TYPE_TABLE.get(self.type, '???')})"

    def __len__(self):
        """Length of the packet"""

        return ETHER_HEADER_LEN + len(self._child_packet)

    def assemble_packet(self, frame, hptr):
        """Assemble packet into the raw form"""

        struct.pack_into("! 6s 6s H", frame, hptr, bytes.fromhex(self.dst.replace(":", "")), bytes.fromhex(self.src.replace(":", "")), self.type)

        self._child_packet.assemble_packet(frame, hptr + ETHER_HEADER_LEN)
