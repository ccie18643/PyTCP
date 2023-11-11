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


"""
Module contains Fast Packet Assembler support class for the Ethernet protocol.

pytcp/protocols/ethernet/fpa.py

ver 2.7
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import ProtoAssembler
from pytcp.protocols.ethernet.ps import ETHERNET_HEADER_LEN, Ethernet
from pytcp.protocols.raw.fpa import RawAssembler

if TYPE_CHECKING:
    from pytcp.protocols.ethernet.ps import EthernetPayload


class EthernetAssembler(Ethernet, ProtoAssembler):
    """
    Ethernet packet assembler support class.
    """

    def __init__(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(0),
        ethernet__dst: MacAddress = MacAddress(0),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> None:
        """
        Class constructor.
        """

        self._payload = ethernet__payload
        self._tracker = self._payload.tracker

        self._dst = ethernet__dst
        self._src = ethernet__src
        self._type = self._payload.ethernet_type

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        return ETHERNET_HEADER_LEN + len(self._payload)

    @property
    def payload(self) -> EthernetPayload:
        """
        Get the '_payload' attribute.
        """

        return self._payload

    def assemble(self, frame: memoryview) -> None:
        """
        Write packet into the provided frame.
        """

        packet = bytes(self)

        struct.pack_into(f"{len(packet)}s", frame, 0, packet)

        self._payload.assemble(frame[ETHERNET_HEADER_LEN:])
