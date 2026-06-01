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
This module contains the IEEE 802.2 LLC U-frame packet
assembler. PyTCP does not currently generate 802.3+LLC
outbound traffic (TX path is Ethernet II only); the
assembler is provided for round-trip testing and for
consumers that may want to build LLC frames in user code.

net_proto/protocols/llc/llc__assembler.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.llc.llc__base import Llc
from net_proto.protocols.llc.llc__enums import LlcControl, LlcSap
from net_proto.protocols.llc.llc__header import LlcHeader


class LlcAssembler(Llc, ProtoAssembler):
    """
    The IEEE 802.2 LLC U-frame assembler.
    """

    def __init__(
        self,
        *,
        llc__dsap: LlcSap = LlcSap.NULL,
        llc__ssap: LlcSap = LlcSap.NULL,
        llc__control: LlcControl = LlcControl.UI,
        llc__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the LLC packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)
        self._payload = llc__payload
        self._header = LlcHeader(
            dsap=llc__dsap,
            ssap=llc__ssap,
            control=llc__control,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the LLC packet into list of buffers.
        """

        buffers.append(bytearray(self._header))
        buffers.append(self._payload)
