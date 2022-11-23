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
Module contains Fast Packet Assembler support class for the UDP protocol.

pytcp/protocols/udp/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ip4.ps import IP4_PROTO_UDP
from pytcp.protocols.ip6.ps import IP6_NEXT_UDP
from pytcp.protocols.udp.ps import UDP_HEADER_LEN


class UdpAssembler:
    """
    UDP packet assembler support class.
    """

    ip4_proto = IP4_PROTO_UDP
    ip6_next = IP6_NEXT_UDP

    def __init__(
        self,
        *,
        sport: int = 0,
        dport: int = 0,
        data: bytes | None = None,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Class constructor.
        """

        assert 0 <= sport <= 0xFFFF, f"{sport=}"
        assert 0 <= dport <= 0xFFFF, f"{dport=}"

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._sport: int = sport
        self._dport: int = dport
        self._data: bytes = b"" if data is None else data
        self._plen: int = UDP_HEADER_LEN + len(self._data)

    def __len__(self) -> int:
        """
        Length of the packet.
        """
        return self._plen

    def __str__(self) -> str:
        """
        Packet log string.
        """
        return f"UDP {self._sport} > {self._dport}, len {self._plen}"

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    def assemble(self, frame: memoryview, pshdr_sum: int) -> None:
        """
        Assemble packet into the raw form.
        """

        # memoryview: bytes conversion required
        struct.pack_into(
            f"! HH HH {len(self._data)}s",
            frame,
            0,
            self._sport,
            self._dport,
            self._plen,
            0,
            bytes(self._data),
        )
        struct.pack_into("! H", frame, 6, inet_cksum(frame, pshdr_sum))
