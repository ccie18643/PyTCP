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
This module contains the DHCPv6 packet parser class.

net_proto/protocols/dhcp6/dhcp6__parser.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.dhcp6.dhcp6__base import Dhcp6
from net_proto.protocols.dhcp6.dhcp6__enums import Dhcp6MessageType
from net_proto.protocols.dhcp6.dhcp6__errors import (
    Dhcp6IntegrityError,
    Dhcp6SanityError,
)
from net_proto.protocols.dhcp6.dhcp6__header import (
    DHCP6__HEADER__LEN,
    Dhcp6Header,
)
from net_proto.protocols.dhcp6.options.dhcp6__options import Dhcp6Options


class Dhcp6Parser(Dhcp6, ProtoParser):
    """
    The DHCPv6 packet parser.
    """

    def __init__(self, data_rx: memoryview) -> None:
        """
        Initialize the DHCPv6 packet parser.
        """

        self._frame = data_rx

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the DHCPv6 packet before parsing it.
        """

        # RFC 8415 §8 — the client/server message header is a 1-byte
        # msg-type + 3-byte transaction-id = 4-byte floor.
        if len(self._frame) < DHCP6__HEADER__LEN:
            raise Dhcp6IntegrityError(
                f"The minimum packet length must be {DHCP6__HEADER__LEN} bytes. Got: {len(self._frame)} bytes."
            )

        # RFC 8415 §21.1 — variable-length options must self-bound (TLV).
        Dhcp6Options.validate_integrity(frame=self._frame, hlen=len(self._frame))

    @override
    def _parse(self) -> None:
        """
        Parse the DHCPv6 packet.
        """

        self._header = Dhcp6Header.from_buffer(self._frame)
        self._options = Dhcp6Options.from_buffer(self._frame[len(self._header) :])

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the DHCPv6 packet after parsing it.
        """

        # --- msg-type (client/server message types) ---
        # RFC 8415 §7.3 defines the message-type registry; ProtoEnum
        # '_missing_' materialises any other wire value as UNKNOWN_n.
        if self._header.msg_type.is_unknown:
            raise Dhcp6SanityError(
                f"The 'msg_type' field value must be one of {Dhcp6MessageType.get_known_values()}. "
                f"Got: {int(self._header.msg_type)}."
            )

        # RFC 8415 §9 — Relay-forward (12) and Relay-reply (13) use the
        # relay-agent/server message format (a different header: msg-type
        # + hop-count + link-address + peer-address), not the §8
        # client/server format this parser decodes. A client/server
        # endpoint never receives a bare relay message, so reject it
        # rather than mis-interpreting the relay header's first bytes as
        # a transaction-id.
        if self._header.msg_type in (Dhcp6MessageType.RELAY_FORW, Dhcp6MessageType.RELAY_REPL):
            raise Dhcp6SanityError(
                "DHCPv6 relay messages (RELAY-FORW / RELAY-REPL) use the relay-agent/server "
                f"message format (RFC 8415 §9), not the client/server format. Got: {self._header.msg_type}."
            )
