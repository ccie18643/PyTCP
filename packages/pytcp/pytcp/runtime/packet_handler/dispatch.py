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
This module contains the per-interface RX protocol-dispatch registry.

pytcp/runtime/packet_handler/dispatch.py

ver 3.0.8
"""

from collections.abc import Callable

from net_proto import PacketRx


class DispatchRegistry[K]:
    """
    A per-interface codepoint-keyed RX dispatch table.

    Maps a wire codepoint (an 'EtherType' for the link-layer demux, an
    'IpProto' for the IPv4 / IPv6 transport demux) to the interface
    delegator that handles it. The interface populates one registry per
    demux at construction so membership encodes the interface's layer
    and protocol-support policy directly: an L3 (TUN) interface never
    registers the ARP handler, an IPv6-disabled stack never registers
    the IPv6 handler, and the demux site simply treats a lookup miss as
    "this interface does not handle that codepoint" — no separate
    support-flag guard at the dispatch point.
    """

    def __init__(self) -> None:
        """
        Initialize an empty dispatch registry.
        """

        self._table: dict[K, Callable[[PacketRx], None]] = {}

    def register(self, codepoint: K, handler: Callable[[PacketRx], None], /) -> None:
        """
        Register the handler that dispatches the given codepoint.
        """

        self._table[codepoint] = handler

    def get(self, codepoint: K, /) -> Callable[[PacketRx], None] | None:
        """
        Get the handler for the given codepoint, or None when unregistered.
        """

        return self._table.get(codepoint)
