################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the SNAP packet assembler. PyTCP does
not currently generate 802.3+LLC+SNAP outbound traffic (TX
path is Ethernet II only); the assembler is provided for
round-trip testing.

net_proto/protocols/snap/snap__assembler.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.snap.snap__base import Snap
from net_proto.protocols.snap.snap__header import SnapHeader


class SnapAssembler(Snap, ProtoAssembler):
    """
    The SNAP packet assembler.
    """

    def __init__(
        self,
        *,
        snap__oui: int = 0,
        snap__pid: int = 0,
        snap__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the SNAP packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._payload = snap__payload
        self._header = SnapHeader(
            oui=snap__oui,
            pid=snap__pid,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the SNAP packet into list of buffers.
        """

        buffers.append(bytearray(self._header))
        buffers.append(self._payload)
