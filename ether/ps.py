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
# ether/ps.py - protocol support for Ethernet
#


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


def __str__(self) -> str:
    """Packet log string"""

    return f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} ({ETHER_TYPE_TABLE.get(self.type, '???')})"
