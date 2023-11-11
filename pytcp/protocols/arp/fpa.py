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

# pylint: disable = too-many-instance-attributes

"""
Module contains Fast Packet Assembler support class for the ARP protocol.

pytcp/protocols/arp/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.arp.ps import (
    ARP_HEADER_LEN,
    Arp,
    ArpHardwareLength,
    ArpHardwareType,
    ArpOperation,
    ArpProtocolLength,
    ArpProtocolType,
)


class ArpAssembler(Arp, ProtoAssembler):
    """
    ARP packet assembler class.
    """

    def __init__(
        self,
        *,
        arp__oper: ArpOperation = ArpOperation.REQUEST,
        arp__sha: MacAddress = MacAddress(0),
        arp__spa: Ip4Address = Ip4Address(0),
        arp__tha: MacAddress = MacAddress(0),
        arp__tpa: Ip4Address = Ip4Address(0),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Create the ARP packet assembler object.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._hrtype = ArpHardwareType.ETHERNET
        self._prtype = ArpProtocolType.IP4
        self._hrlen = ArpHardwareLength.ETHERNET
        self._prlen = ArpProtocolLength.IP4

        self._oper = arp__oper
        self._sha = arp__sha
        self._spa = arp__spa
        self._tha = arp__tha
        self._tpa = arp__tpa

    def __len__(self) -> int:
        """
        Get the packet length.
        """

        return ARP_HEADER_LEN

    def assemble(self, /, frame: memoryview) -> None:
        """
        Write packet into the provided frame.
        """

        packet = bytes(self)

        struct.pack_into(f"{len(packet)}s", frame, 0, packet)
