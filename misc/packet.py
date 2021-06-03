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

from __future__ import annotations  # Required by Python ver < 3.10

from typing import TYPE_CHECKING, Optional, Union

from misc.tracker import Tracker

if TYPE_CHECKING:
    from arp.fpp import ArpParser
    from ether.fpp import EtherParser
    from icmp4.fpp import Icmp4Parser
    from icmp6.fpp import Icmp6Parser
    from ip4.fpp import Ip4Parser
    from ip6.fpp import Ip6Parser
    from ip6_ext_frag.fpp import Ip6ExtFragParser
    from tcp.fpp import TcpParser
    from udp.fpp import UdpParser


class PacketRx:
    """Base packet class"""

    def __init__(self, frame: bytes) -> None:
        """Class constructor"""

        self.frame = frame
        self.hptr = 0
        self.tracker = Tracker("RX")
        self.parse_failed = Optional[str]

        self.ether: Optional[EtherParser] = None
        self.arp: Optional[ArpParser] = None
        self.ip: Optional[Union[Ip6Parser, Ip4Parser]] = None
        self.ip4: Optional[Ip4Parser] = None
        self.ip6: Optional[Ip6Parser] = None
        self.ip6_ext_frag: Optional[Ip6ExtFragParser] = None
        self.icmp4: Optional[Icmp4Parser] = None
        self.icmp6: Optional[Icmp6Parser] = None
        self.tcp: Optional[TcpParser] = None
        self.udp: Optional[UdpParser] = None

    def __len__(self) -> int:
        """Returns length of raw frame"""

        return len(self.frame)
