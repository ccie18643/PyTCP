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
# fpa/arp.py - Fast Packet Assembler support class for ARP protocol
#


import struct

import arp.ps
from misc.ipv4_address import IPv4Address
from misc.tracker import Tracker


class Assembler(arp.ps.Base):
    """ ARP packet assembler support class """

    protocol = "ARP"

    def __init__(self, sha, spa, tpa, tha="00:00:00:00:00:00", oper=arp.ps.OP_REQUEST, echo_tracker=None):
        """ Class constructor """

        self.tracker = Tracker("TX", echo_tracker)

        self.hrtype = 1
        self.prtype = 0x0800
        self.hrlen = 6
        self.prlen = 4
        self.oper = oper
        self.sha = sha
        self.spa = IPv4Address(spa)
        self.tha = tha
        self.tpa = IPv4Address(tpa)

    def __len__(self):
        """ Length of the packet """

        return arp.ps.HEADER_LEN

    def assemble(self, frame, hptr):
        """ Assemble packet into the raw form """

        return struct.pack_into(
            "!HH BBH 6s 4s 6s 4s",
            frame,
            hptr,
            self.hrtype,
            self.prtype,
            self.hrlen,
            self.prlen,
            self.oper,
            bytes.fromhex(self.sha.replace(":", "")),
            IPv4Address(self.spa).packed,
            bytes.fromhex(self.tha.replace(":", "")),
            IPv4Address(self.tpa).packed,
        )
