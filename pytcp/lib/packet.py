#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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


# pylint: disable = invalid-name
# pylint: disable = too-many-instance-attributes
# pylint: disable = too-few-public-methods

"""
Module contains class representing packet.

pytcp/lib/packet.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.tracker import Tracker

if TYPE_CHECKING:
    from pytcp.protocols.arp.fpp import ArpParser
    from pytcp.protocols.ether.fpp import EtherParser
    from pytcp.protocols.icmp4.fpp import Icmp4Parser
    from pytcp.protocols.icmp6.fpp import Icmp6Parser
    from pytcp.protocols.ip4.fpp import Ip4Parser
    from pytcp.protocols.ip6.fpp import Ip6Parser
    from pytcp.protocols.ip6_ext_frag.fpp import Ip6ExtFragParser
    from pytcp.protocols.tcp.fpp import TcpParser
    from pytcp.protocols.udp.fpp import UdpParser


class PacketRx:
    """
    Base packet RX class.
    """

    def __init__(self, frame: bytes) -> None:
        """
        Class constructor.
        """

        self.frame: memoryview = memoryview(frame)
        self.tracker: Tracker = Tracker(prefix="RX")
        self.parse_failed: str = ""

        self.ether: EtherParser
        self.arp: ArpParser
        self.ip: Ip6Parser | Ip4Parser
        self.ip4: Ip4Parser
        self.ip6: Ip6Parser
        self.ip6_ext_frag: Ip6ExtFragParser
        self.icmp4: Icmp4Parser
        self.icmp6: Icmp6Parser
        self.tcp: TcpParser
        self.udp: UdpParser

    def __len__(self) -> int:
        """
        Return length of raw frame.
        """
        return len(self.frame)
