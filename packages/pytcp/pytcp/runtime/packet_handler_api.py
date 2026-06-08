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
This module contains structural Protocol seams for the packet handler.

Each Protocol declares the narrow subset of a concrete 'PacketHandler'
surface that one collaborator (the ARP cache, the ND cache, ...) calls,
so the collaborator annotates against this leaf module instead of
importing the concrete handler — which imports the collaborator back.
The seam breaks that runtime import cycle without a 'TYPE_CHECKING'
guard, and the concrete handler satisfies the Protocol structurally
(verified by mypy at the 'attach_owner' call site in 'stack.init').

pytcp/runtime/packet_handler_api.py

ver 3.0.8
"""

from typing import Protocol

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.runtime.tx_ring import TxRing


class ArpCacheOwner(Protocol):
    """
    The owning-interface-handler surface the ARP cache requires — the
    subset of 'PacketHandlerL2' the cache's solicit / flush callbacks
    call.
    """

    @property
    def tx_ring(self) -> TxRing | None:
        """
        Get the owning handler's TX ring.
        """

        ...

    def send_arp_request(self, *, arp__tpa: Ip4Address) -> None:
        """
        Enqueue a broadcast ARP Request via the owning handler.
        """

        ...

    def send_arp_unicast_request(
        self,
        *,
        arp__tpa: Ip4Address,
        ethernet__dst: MacAddress,
        arp__spa: Ip4Address | None = None,
    ) -> None:
        """
        Enqueue a unicast ARP Request via the owning handler.
        """

        ...


class NdCacheOwner(Protocol):
    """
    The owning-interface-handler surface the ND cache requires — the
    subset of 'PacketHandlerL2' / 'PacketHandlerL3' the cache's solicit
    / flush callbacks call.
    """

    @property
    def tx_ring(self) -> TxRing | None:
        """
        Get the owning handler's TX ring.
        """

        ...

    def send_icmp6_neighbor_solicitation(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a multicast ICMPv6 ND Neighbor Solicitation via the owning handler.
        """

        ...

    def send_icmp6_neighbor_solicitation_unicast(self, *, icmp6_ns_target_address: Ip6Address) -> None:
        """
        Enqueue a unicast ICMPv6 ND Neighbor Solicitation via the owning handler.
        """

        ...
