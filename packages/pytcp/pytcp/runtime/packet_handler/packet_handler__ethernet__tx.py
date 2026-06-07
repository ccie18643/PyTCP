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
This module contains packet handler for the outbound Ethernet II packets.

pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from net_addr import MacAddress
from net_proto import (
    EthernetAssembler,
    EthernetPayload,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
    RawAssembler,
)
from net_proto.lib.buffer import Buffer
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class EthernetTxHandler:
    """
    Packet handler for the outbound Ethernet packets.
    """

    _if: PacketHandlerL2

    def __init__(self, *, interface: PacketHandlerL2) -> None:
        """
        Initialize the Ethernet TX sub-handler.
        """

        self._if = interface

    def _phtx_ethernet(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(),
        ethernet__dst: MacAddress = MacAddress(),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound Ethernet packets.
        """

        self._if._packet_stats_tx.ethernet__pre_assemble += 1

        ethernet_packet_tx = EthernetAssembler(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=ethernet__payload,
        )

        # Check if packet contains valid source address, fill it out if needed.
        if ethernet_packet_tx.src.is_unspecified:
            self._if._packet_stats_tx.ethernet__src_unspec__fill += 1
            ethernet_packet_tx.src = self._if._mac_unicast
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Set source to stack MAC " f"{ethernet_packet_tx.src}",
            )
        else:
            self._if._packet_stats_tx.ethernet__src_spec += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Source MAC specified to " f"{ethernet_packet_tx.src}",
            )

        # Send out packet if it contains valid destination MAC address.
        if not ethernet_packet_tx.dst.is_unspecified:
            self._if._packet_stats_tx.ethernet__dst_spec__send += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Contains valid destination " "MAC address",
            )
            self.__send_out_packet(ethernet_packet_tx)
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        # Check if we can obtain destination MAC based on IPv6 header data.
        if isinstance(ethernet_packet_tx.payload, Ip6Assembler):
            self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup += 1

            ip6_dst = ethernet_packet_tx.payload.dst

            # Send packet out if its destined to multicast IPv6 address.
            if ip6_dst.is_multicast:
                self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__multicast__send += 1
                ethernet_packet_tx.dst = ip6_dst.multicast_mac
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv6 "
                    f"{ip6_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Resolve the next hop via the host-mode routing
            # table (FIB). Phase 2 of
            # docs/refactor/routing_table_host_mode.md: this is a
            # destination-keyed longest-prefix lookup that
            # replaces the prior source-address-coupled ifaddr
            # scan. Deliberate Linux-correct behaviour change
            # (RFC 1122 §3.3.4.1; RFC 4861 §5.2): a destination
            # on-link for ANY interface address is sent directly
            # even when the packet source belongs to a different
            # interface address. 'route.gateway is None' ⇒
            # on-link (connected route); non-None ⇒ off-link via
            # that gateway. The 'extnet__no_gw__drop' counter and
            # DST_NO_GATEWAY_IP6 status now mean "no route to
            # host" (a superset of the old "no gateway").
            # Phase 2: the forwarding plane (router-grade) calls
            # this same 'lookup' for transit packets.
            ip6_route = stack.ip6_fib.lookup(
                ip6_dst,
                connected=[(ip6_host.network, self._if._ifindex) for ip6_host in self._if._ip6_ifaddr],
            )
            if ip6_route is None:
                self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop += 1
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - <WARN>No route to " f"{ip6_dst}, dropping</>",
                )
                return TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6

            assert self._if._nd_cache is not None, "L2 handler resolving an IPv6 neighbor must have an ND cache."

            if ip6_route.gateway is not None:
                if mac_address := self._if._nd_cache.find_entry(ip6_address=ip6_route.gateway):
                    ethernet_packet_tx.dst = mac_address
                    self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send += 1
                    __debug__ and log(
                        "ether",
                        f"{ethernet_packet_tx.tracker} - Resolved destination "
                        f"IPv6 {ip6_dst}"
                        f" to Default Gateway MAC {ethernet_packet_tx.dst}",
                    )
                    self.__send_out_packet(ethernet_packet_tx)
                    return TxStatus.PASSED__ETHERNET__TO_TX_RING
                self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop += 1
                # RFC 1122 §2.3.2.2 (IPv6 mirror): save the
                # most recently dropped packet for delivery
                # once the gateway MAC has been resolved.
                self._if._nd_cache.enqueue_pending(
                    ip6_address=ip6_route.gateway,
                    ethernet_packet_tx=ethernet_packet_tx,
                )
                return TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS

            # On-link (connected route, no gateway): resolve the
            # destination MAC directly from the ICMPv6 ND cache.
            if mac_address := self._if._nd_cache.find_entry(
                ip6_address=ip6_dst,
            ):
                self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send += 1
                ethernet_packet_tx.dst = mac_address
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv6 "
                    f"{ip6_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            self._if._packet_stats_tx.ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - <WARN>No valid destination "
                f"MAC could be obtained from ND cache, dropping</>",
            )
            # RFC 1122 §2.3.2.2 (IPv6 mirror): save the most
            # recently dropped packet for delivery once the
            # destination MAC has been resolved.
            self._if._nd_cache.enqueue_pending(
                ip6_address=ip6_dst,
                ethernet_packet_tx=ethernet_packet_tx,
            )
            return TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS

        # Check if we can obtain destination MAC based on IPv4 header data.
        if isinstance(ethernet_packet_tx.payload, (Ip4Assembler, Ip4FragAssembler)):
            self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup += 1

            ip4_src = ethernet_packet_tx.payload.src
            ip4_dst = ethernet_packet_tx.payload.dst

            # Send packet out if its destined to multicast IPv4 address.
            if ip4_dst.is_multicast:
                self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__multicast__send += 1
                ethernet_packet_tx.dst = ip4_dst.multicast_mac
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if its destinied to limited broadcast addresses.
            if ip4_dst.is_limited_broadcast:
                self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__limited_broadcast__send += 1
                ethernet_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if its destinied to network broadcast or network
            # addresses (in relation to its source address).
            for ip4_host in self._if._ip4_ifaddr:
                if ip4_host.address == ip4_src:
                    if ip4_dst in {
                        ip4_host.network.address,
                        ip4_host.network.broadcast,
                    }:
                        self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__network_broadcast__send += 1
                        ethernet_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
                        __debug__ and log(
                            "ether",
                            f"{ethernet_packet_tx.tracker} - Resolved destination "
                            f"IPv4 {ip4_dst} to MAC {ethernet_packet_tx.dst}",
                        )
                        self.__send_out_packet(ethernet_packet_tx)
                        return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Resolve the next hop via the host-mode routing
            # table (FIB) — destination-keyed longest-prefix
            # lookup; see the IPv6 branch above for the Phase-2
            # rationale and the deliberate Linux-correct
            # behaviour change. The directed-broadcast / network-
            # address special-case above stays source-keyed
            # (link-scope, not routed). 'route.gateway is None' ⇒
            # on-link; the 'extnet__no_gw__drop' counter and
            # DST_NO_GATEWAY_IP4 status now mean "no route to
            # host".
            ip4_route = stack.ip4_fib.lookup(
                ip4_dst,
                connected=[(ip4_host.network, self._if._ifindex) for ip4_host in self._if._ip4_ifaddr],
            )
            if ip4_route is None:
                self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop += 1
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - <WARN>No route to " f"{ip4_dst}, dropping</>",
                )
                return TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4

            assert self._if._arp_cache is not None, "L2 handler resolving an IPv4 neighbor must have an ARP cache."

            if ip4_route.gateway is not None:
                if mac_address := self._if._arp_cache.find_entry(
                    ip4_address=ip4_route.gateway,
                ):
                    self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send += 1
                    ethernet_packet_tx.dst = mac_address
                    __debug__ and log(
                        "ether",
                        f"{ethernet_packet_tx.tracker} - Resolved destination "
                        f"IPv4 {ip4_dst} to Default Gateway MAC "
                        f"{ethernet_packet_tx.dst}",
                    )
                    self.__send_out_packet(ethernet_packet_tx)
                    return TxStatus.PASSED__ETHERNET__TO_TX_RING
                self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop += 1
                # RFC 1122 §2.3.2.2: save the most recently
                # dropped packet for delivery once the gateway
                # MAC has been resolved.
                self._if._arp_cache.enqueue_pending(
                    ip4_address=ip4_route.gateway,
                    ethernet_packet_tx=ethernet_packet_tx,
                )
                return TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS

            # On-link (connected route, no gateway): resolve the
            # destination MAC directly from the ARP cache, drop
            # otherwise.
            if mac_address := self._if._arp_cache.find_entry(
                ip4_address=ip4_dst,
            ):
                self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send += 1
                ethernet_packet_tx.dst = mac_address
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            self._if._packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - <WARN>No valid destination "
                "MAC could be obtained from ARP cache, dropping</>",
            )
            # RFC 1122 §2.3.2.2: save the most recently dropped
            # packet for delivery once the destination MAC has
            # been resolved.
            self._if._arp_cache.enqueue_pending(
                ip4_address=ip4_dst,
                ethernet_packet_tx=ethernet_packet_tx,
            )
            return TxStatus.DROPPED__ETHERNET__DST_ARP_CACHE_MISS

        # Drop packet in case we are not able to obtain valid destination MAC address.
        self._if._packet_stats_tx.ethernet__dst_unspec__drop += 1
        __debug__ and log(
            "ether",
            f"{ethernet_packet_tx.tracker} - <WARN>No valid destination MAC could " "be obtained, dropping</>",
        )
        return TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL

    def __send_out_packet(self, ethernet_packet_tx: EthernetAssembler) -> None:
        __debug__ and log("ether", f"{ethernet_packet_tx.tracker} - {ethernet_packet_tx}")
        assert self._if._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._if._tx_ring.enqueue(ethernet_packet_tx)

    def send_link_frame(self, frame: Buffer, /) -> None:
        """
        Enqueue a complete, pre-built link-layer frame for verbatim
        transmission on this interface — the AF_PACKET (SOCK_RAW)
        egress seam. Bypasses the assembler / IP layers entirely; the
        frame is written to the wire as-is, the destination MAC and
        ethertype taken from the caller-supplied bytes.
        """

        assert self._if._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._if._tx_ring.enqueue_raw_frame(frame)
