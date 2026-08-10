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

ver 3.0.10
"""

from collections.abc import Callable
from typing import Protocol

from net_addr import Buffer, Ip4Address, Ip6Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.options.ip4__options import Ip4Options
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

    def deliver_tx_to_packet_sockets(self, ethernet_packet_tx: EthernetAssembler, /) -> None:
        """
        Fan a queued-then-flushed frame to bound AF_PACKET sockets so it is
        observed on egress (the flush path bypasses '__send_out_packet').
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

    def deliver_tx_to_packet_sockets(self, ethernet_packet_tx: EthernetAssembler, /) -> None:
        """
        Fan a queued-then-flushed frame to bound AF_PACKET sockets so it is
        observed on egress (the flush path bypasses '__send_out_packet').
        """

        ...


class UdpEgressOwner(Protocol):
    """
    The egress-interface-handler surface the UDP socket requires — the
    subset of 'PacketHandlerL2' / 'PacketHandlerL3' the socket's send
    path calls to enqueue an outbound datagram.
    """

    def send_udp_packet(
        self,
        *,
        ip__local_address: Ip6Address | Ip4Address,
        ip__remote_address: Ip6Address | Ip4Address,
        udp__local_port: int,
        udp__remote_port: int,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        ip__ttl: int | None = None,
        ip__ecn: int = 0,
        ip__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """
        Enqueue an outbound UDP datagram via the egress handler.
        """

        ...
