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
# pylint: disable = redefined-builtin

"""
Module contains Fast Packet Assembler support class for the IPv6 fragment
extension header.

pytcp/protocols/ip6_ext_frag/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.tracker import Tracker
from pytcp.protocols.ip6.ps import (
    IP6_NEXT_EXT_FRAG,
    IP6_NEXT_ICMP6,
    IP6_NEXT_RAW,
    IP6_NEXT_TCP,
    IP6_NEXT_UDP,
)
from pytcp.protocols.ip6_ext_frag.ps import (
    IP6_EXT_FRAG_HEADER_LEN,
    IP6_EXT_FRAG_NEXT_HEADER_TABLE,
)


class Ip6ExtFragAssembler:
    """
    IPv6 fragment extension header assembler support class.
    """

    ip6_next = IP6_NEXT_EXT_FRAG

    def __init__(
        self,
        *,
        next: int,
        offset: int,
        flag_mf: bool,
        id: int,
        data: bytes,
    ):
        """
        Class constructor.
        """

        assert next in {
            IP6_NEXT_ICMP6,
            IP6_NEXT_UDP,
            IP6_NEXT_TCP,
            IP6_NEXT_RAW,
        }

        self._tracker: Tracker = Tracker(prefix="TX")
        self._next: int = next
        self._offset: int = offset
        self._flag_mf: bool = flag_mf
        self._id: int = id
        self._dataa: bytes = data
        self._dlen: int = len(data)
        self._plen: int = len(self)

    def __len__(self) -> int:
        """Length of the packet"""

        return IP6_EXT_FRAG_HEADER_LEN + len(self._dataa)

    def __str__(self) -> str:
        """Packet log string"""

        return (
            f"IPv6_FRAG id {self._id}{', MF' if self._flag_mf else ''}, "
            f"offset {self._offset}, next {self._next} "
            f"({IP6_EXT_FRAG_NEXT_HEADER_TABLE.get(self._next, '???')})"
        )

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    def assemble(self, frame: memoryview, _: int) -> None:
        """
        Assemble packet into the the raw form.
        """
        struct.pack_into(
            f"! BBH L {self._dlen}s",
            frame,
            0,
            self._next,
            0,
            self._offset | self._flag_mf,
            self._id,
            bytes(self._dataa),  # memoryview: translation to bytes necessary
        )
