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
# packet.py - module contains class representing packet
#

from typing import Optional

from misc.tracker import Tracker


class PacketRx:
    """Base packet class"""

    def __init__(self, frame: bytes) -> None:
        """Class constructor"""

        self.frame = frame
        self.hptr = 0
        self.tracker = Tracker("RX")
        self.parse_failed = Optional[str]

        self.ether: object = None
        self.arp: object = None
        self.ip: object = None
        self.ip4: object = None
        self.ip6: object = None
        self.ip6_ext_frag: object = None
        self.icmp4: object = None
        self.icmp6: object = None
        self.tcp: object = None
        self.udp: object = None

    def __len__(self) -> int:
        """Returns length of raw frame"""

        return len(self.frame)
