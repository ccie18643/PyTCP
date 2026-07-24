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
This module contains the IGMP packet assembler.

net_proto/protocols/igmp/igmp__assembler.py

ver 3.0.9
"""

from typing import cast, override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.igmp.igmp__base import Igmp
from net_proto.protocols.igmp.message.igmp__message import IgmpMessage


class IgmpAssembler(Igmp, ProtoAssembler):
    """
    The IGMP packet assembler.
    """

    def __init__(
        self,
        *,
        igmp__message: IgmpMessage,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the IGMP packet assembler.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._message = igmp__message

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMP packet into list of buffers.
        """

        start = len(buffers)
        self._message.assemble(buffers)

        # The message may append one buffer (the legacy 8-octet form) or
        # two (the V3 Report header + records). The checksum is computed
        # over every appended buffer and injected into the first one,
        # which always carries the type / checksum header (RFC 3376
        # §4.1.2).
        message_buffers = buffers[start:]
        cast(bytearray, message_buffers[0])[2:4] = inet_cksum(*message_buffers).to_bytes(2)
