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
# packet.py - module contains class representing packet
#

from misc.tracker import Tracker


class PacketRx:
    """ Base packet class """

    def __init__(self, frame):
        """ Class constructor """

        self.frame = frame
        self.hptr = 0
        self.tracker = Tracker("RX")
        self.parse_failed = None

        self.ether = None
        self.arp = None
        self.ip = None
        self.ip4 = None
        self.ip6 = None
        self.ip6_ext_frag = None
        self.icmp4 = None
        self.icmp6 = None
        self.tcp = None
        self.udp = None

    def __len__(self):
        """ Returns length of raw frame """

        return len(self.frame)
