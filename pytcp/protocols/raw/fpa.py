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
Module contains Fast Packet Assembler support class for the raw protocol.

pytcp/protocols/raw/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.tracker import Tracker
from pytcp.protocols.ether.ps import ETHER_TYPE_RAW
from pytcp.protocols.ip4.ps import IP4_PROTO_RAW
from pytcp.protocols.ip6.ps import IP6_NEXT_RAW


class RawAssembler:
    """
    Raw packet assembler support class.
    """

    ip4_proto = IP4_PROTO_RAW
    ip6_next = IP6_NEXT_RAW
    ether_type = ETHER_TYPE_RAW

    def __init__(
        self, *, data: bytes | None = None, echo_tracker: Tracker | None = None
    ) -> None:
        """
        Class constructor.
        """
        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._data: bytes = b"" if data is None else data
        self._plen: int = len(self._data)

    def __len__(self) -> int:
        """
        Length of the packet.
        """
        return self._plen

    def __str__(self) -> str:
        """
        Packet log string.
        """
        return f"Raw, len {self._plen}"

    def __repr__(self) -> str:
        """
        Object representation.
        """
        return f"RawAssembler(data={self._data!r})"

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    def assemble(self, frame: memoryview, _: int = 0) -> None:
        """
        Assemble packet into the raw form.
        """
        struct.pack_into(f"! {len(self._data)}s", frame, 0, bytes(self._data))
