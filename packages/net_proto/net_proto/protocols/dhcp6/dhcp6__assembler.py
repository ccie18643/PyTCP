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
This module contains the DHCPv6 packet assembler class.

net_proto/protocols/dhcp6/dhcp6__assembler.py

ver 3.0.10
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.dhcp6.dhcp6__base import Dhcp6
from net_proto.protocols.dhcp6.dhcp6__enums import Dhcp6MessageType
from net_proto.protocols.dhcp6.dhcp6__header import Dhcp6Header
from net_proto.protocols.dhcp6.options.dhcp6__options import Dhcp6Options


class Dhcp6Assembler(Dhcp6, ProtoAssembler):
    """
    The DHCPv6 packet assembler.
    """

    def __init__(
        self,
        *,
        dhcp6__msg_type: Dhcp6MessageType,
        dhcp6__xid: int,
        dhcp6__options: Dhcp6Options = Dhcp6Options(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the DHCPv6 packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        # RFC 8415 §7.3 — Dhcp6MessageType is extensible at parse time
        # via ProtoEnum '_missing_' so the RX path can materialise
        # unknown wire codepoints for '_validate_sanity' to reject. The
        # TX path is strict: refuse to emit a frame with an unknown
        # message type that strict receivers cannot interpret.
        assert not dhcp6__msg_type.is_unknown, (
            "The 'dhcp6__msg_type' field must be a known Dhcp6MessageType member. " f"Got: {dhcp6__msg_type!r}"
        )

        # RFC 8415 §9 — a host client never builds the relay-agent/server
        # RELAY-FORW / RELAY-REPL messages (they use a different header
        # format); refuse to construct one through the client/server
        # assembler.
        assert dhcp6__msg_type not in (Dhcp6MessageType.RELAY_FORW, Dhcp6MessageType.RELAY_REPL), (
            "The 'dhcp6__msg_type' field must be a client/server message type, not a relay "
            f"message (RFC 8415 §9). Got: {dhcp6__msg_type!r}"
        )

        self._header = Dhcp6Header(
            msg_type=dhcp6__msg_type,
            xid=dhcp6__xid,
        )

        self._options = dhcp6__options

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the DHCPv6 packet into list of buffers.
        """

        raise NotImplementedError("The 'assemble()' method is not implemented for L7 protocols. Use Sockets instead.")
