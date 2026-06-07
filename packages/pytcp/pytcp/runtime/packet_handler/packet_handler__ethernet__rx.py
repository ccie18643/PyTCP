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

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains packet handler for the inbound Ethernet II packets.

pytcp/runtime/packet_handler/packet_handler__ethernet__rx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from net_addr import MacAddress
from net_proto import EthernetParser, PacketRx, PacketValidationError
from net_proto.lib.buffer import Buffer
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.packet__metadata import PacketMetadata
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class EthernetRxHandler:
    """
    Packet handler for the inbound Ethernet packets.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Initialize the Ethernet RX sub-handler.
        """

        self._if = interface

    def _phrx_ethernet(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound Ethernet packets.
        """

        self._if._packet_stats_rx.ethernet__pre_parse += 1

        # Capture the full-frame view BEFORE the parser advances
        # 'packet_rx.frame' past the Ethernet header — the AF_PACKET tap
        # below needs the complete link-layer frame. O(1): the parser
        # reassigns the attribute to a sub-slice; this reference still
        # spans the whole frame.
        frame = packet_rx.frame

        try:
            EthernetParser(packet_rx)

        except PacketValidationError as error:
            self._if._packet_stats_rx.ethernet__failed_parse__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ether", f"{packet_rx.tracker} - {packet_rx.ethernet}")

        # AF_PACKET tap — fan a copy of the parsed frame to every bound
        # packet socket whose filter matches, BEFORE the EtherType -> IP
        # demux. The tap is parallel to normal IP delivery (a packet
        # socket observes, it does not consume), so the rest of this
        # method is unaffected.
        self._deliver_to_packet_sockets(packet_rx, frame)

        # Check if received packet matches any of stack MAC addresses.
        if packet_rx.ethernet.dst not in {
            self._if._mac_unicast,
            *self._if._mac_multicast,
            self._if._mac_broadcast,
        }:
            self._if._packet_stats_rx.ethernet__dst_unknown__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Ethernet packet not destined for this " "stack, dropping",
            )
            return

        if packet_rx.ethernet.dst == self._if._mac_unicast:
            self._if._packet_stats_rx.ethernet__dst_unicast += 1

        if packet_rx.ethernet.dst in self._if._mac_multicast:
            self._if._packet_stats_rx.ethernet__dst_multicast += 1

        if packet_rx.ethernet.dst == self._if._mac_broadcast:
            self._if._packet_stats_rx.ethernet__dst_broadcast += 1

        # EtherType -> handler demux via the per-interface dispatch
        # registry. Membership encodes the support-flag gating that the
        # prior 'match' guards carried (an IPv4-disabled interface
        # registers neither ARP nor IPv4), so a registry miss is the
        # "unsupported protocol" drop.
        handler = self._if._ethertype_registry.get(packet_rx.ethernet.type)
        if handler is None:
            self._if._packet_stats_rx.ethernet__no_proto_support__drop += 1
            __debug__ and log(
                "ether",
                f"{packet_rx.tracker} - Unsupported protocol " f"{packet_rx.ethernet.type}, dropping.",
            )
            return
        handler(packet_rx)

    def _deliver_to_packet_sockets(self, packet_rx: PacketRx, frame: Buffer, /) -> None:
        """
        Fan a copy of the parsed frame to every AF_PACKET socket whose
        '(ifindex, ethertype)' filter matches. A cheap empty-registry
        check short-circuits the no-packet-socket hot path. Each socket
        gets a detached 'bytes' copy of the complete link-layer frame,
        never an alias of the RX-ring buffer.
        """

        if not stack.packet_sockets:
            return

        matches = stack.packet_sockets.matching(
            ifindex=self._if._ifindex,
            ethertype=packet_rx.ethernet.type,
        )
        if not matches:
            return

        sockaddr_ll = SockAddrLl(
            ifindex=self._if._ifindex,
            ethertype=packet_rx.ethernet.type,
            pkttype=self._classify_pkttype(packet_rx.ethernet.dst),
            mac=packet_rx.ethernet.src,
        )
        packet_rx_md = PacketMetadata(frame=bytes(frame), sockaddr_ll=sockaddr_ll)
        for sock in matches:
            sock.process_packet(packet_rx_md)

    def _classify_pkttype(self, dst: MacAddress, /) -> PacketType:
        """
        Classify an inbound frame's link-layer destination relative to
        this interface (Linux 'sll_pkttype'): the stack's own unicast
        MAC -> HOST; the link broadcast -> BROADCAST; any other
        multicast -> MULTICAST; otherwise -> OTHERHOST (a frame
        addressed to a different host that the interface still
        observed — e.g. captured by an ETH_P_ALL packet socket).
        """

        if dst == self._if._mac_unicast:
            return PacketType.PACKET_HOST
        if dst.is_broadcast:
            return PacketType.PACKET_BROADCAST
        if dst.is_multicast:
            return PacketType.PACKET_MULTICAST
        return PacketType.PACKET_OTHERHOST
