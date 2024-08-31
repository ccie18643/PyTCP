#!/usr/bin/env python3

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

# pylint: disable=line-too-long
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# pylint: disable=expression-not-assigned
# pylint: disable=no-else-return

"""
Module contains packet handler for the outbound Ethernet II packets.

pytcp/protocols/ethernet/ethernet__packet_handler_tx.py

ver 3.0.0
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp.protocols.ip4.ip4__assembler import Ip4Assembler, Ip4FragAssembler
from pytcp.protocols.ip6.ip6__assembler import Ip6Assembler
from pytcp.protocols.raw.raw__assembler import RawAssembler


class EthernetPacketHandlerTx(ABC):
    """
    Class implements packet handler for the outbound Ethernet packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip4_address import Ip4Host
        from pytcp.lib.ip6_address import Ip6Host
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.ethernet.ethernet__base import EthernetPayload

        packet_stats_tx: PacketStatsTx
        mac_unicast: MacAddress
        ip6_host: list[Ip6Host]
        ip4_host: list[Ip4Host]

    def _phtx_ethernet(
        self,
        *,
        ethernet__src: MacAddress = MacAddress(0),
        ethernet__dst: MacAddress = MacAddress(0),
        ethernet__payload: EthernetPayload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound Ethernet packets.
        """

        self.packet_stats_tx.ethernet__pre_assemble += 1

        ethernet_packet_tx = EthernetAssembler(
            ethernet__src=ethernet__src,
            ethernet__dst=ethernet__dst,
            ethernet__payload=ethernet__payload,
        )

        # Check if packet contains valid source address, fill it out if needed
        if ethernet_packet_tx.src.is_unspecified:
            self.packet_stats_tx.ethernet__src_unspec__fill += 1
            ethernet_packet_tx.src = self.mac_unicast
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Set source to stack MAC "
                f"{ethernet_packet_tx.src}",
            )
        else:
            self.packet_stats_tx.ethernet__src_spec += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Source MAC specified to "
                f"{ethernet_packet_tx.src}",
            )

        # Send out packet if it contains valid destination MAC address
        if not ethernet_packet_tx.dst.is_unspecified:
            self.packet_stats_tx.ethernet__dst_spec__send += 1
            __debug__ and log(
                "ether",
                f"{ethernet_packet_tx.tracker} - Contains valid destination "
                "MAC address",
            )
            self.__send_out_packet(ethernet_packet_tx)
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        # Check if we can obtain destination MAC based on IPv6 header data
        if isinstance(ethernet_packet_tx.payload, Ip6Assembler):
            self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup += 1

            ip6_src = ethernet_packet_tx.payload.src
            ip6_dst = ethernet_packet_tx.payload.dst

            # Send packet out if its destined to multicast IPv6 address
            if ip6_dst.is_multicast:
                self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__multicast__send += (
                    1
                )
                ethernet_packet_tx.dst = ip6_dst.multicast_mac
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv6 "
                    f"{ip6_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if is destined to external network (in relation to
            # its source address) and we are able to obtain MAC of default gateway
            # from ND cache
            for ip6_host in self.ip6_host:
                if (
                    ip6_host.address == ip6_src
                    and ip6_dst not in ip6_host.network
                ):
                    if ip6_host.gateway is None:
                        self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop += (
                            1
                        )
                        __debug__ and log(
                            "ether",
                            f"<{ethernet_packet_tx.tracker} - <WARN>No default "
                            f"gateway set for {ip6_host} source address, "
                            "dropping</>",
                        )
                        return TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP6
                    if mac_address := stack.nd_cache.find_entry(
                        ip6_host.gateway
                    ):
                        ethernet_packet_tx.dst = mac_address
                        self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send += (
                            1
                        )
                        __debug__ and log(
                            "ether",
                            f"{ethernet_packet_tx.tracker} - Resolved destination "
                            f"IPv6 {ip6_dst}"
                            f" to Default Gateway MAC {ethernet_packet_tx.dst}",
                        )
                        self.__send_out_packet(ethernet_packet_tx)
                        return TxStatus.PASSED__ETHERNET__TO_TX_RING
                    self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop += (
                        1
                    )
                    return TxStatus.DROPED__ETHERNET__DST_GATEWAY_ND_CACHE_FAIL

            # Send out packet if we are able to obtain destination MAC
            # from ICMPv6 ND cache
            if mac_address := stack.nd_cache.find_entry(ip6_dst):
                self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send += (
                    1
                )
                ethernet_packet_tx.dst = mac_address
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv6 "
                    f"{ip6_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING
            else:
                self.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop += (
                    1
                )
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - <WARN>No valid destination "
                    f"MAC could be obtained from ND cache, dropping</>",
                )
                return TxStatus.DROPED__ETHERNET__DST_ND_CACHE_FAIL

        # Check if we can obtain destination MAC based on IPv4 header data
        if isinstance(
            ethernet_packet_tx.payload, (Ip4Assembler, Ip4FragAssembler)
        ):
            self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup += 1

            ip4_src = ethernet_packet_tx.payload.src
            ip4_dst = ethernet_packet_tx.payload.dst

            # Send packet out if its destined to multicast IPv4 address
            if ip4_dst.is_multicast:
                self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__multicast__send += (
                    1
                )
                ethernet_packet_tx.dst = ip4_dst.multicast_mac
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if its destinied to limited broadcast addresses
            if ip4_dst.is_limited_broadcast:
                self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__limited_broadcast__send += (
                    1
                )
                ethernet_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if its destinied to network broadcast or network
            # addresses (in relation to its source address)
            for ip4_host in self.ip4_host:
                if ip4_host.address == ip4_src:
                    if ip4_dst in {
                        ip4_host.network.address,
                        ip4_host.network.broadcast,
                    }:
                        self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__network_broadcast__send += (
                            1
                        )
                        ethernet_packet_tx.dst = MacAddress(0xFFFFFFFFFFFF)
                        __debug__ and log(
                            "ether",
                            f"{ethernet_packet_tx.tracker} - Resolved destination "
                            f"IPv4 {ip4_dst} to MAC {ethernet_packet_tx.dst}",
                        )
                        self.__send_out_packet(ethernet_packet_tx)
                        return TxStatus.PASSED__ETHERNET__TO_TX_RING

            # Send out packet if is destined to external network (in relation to
            # its source address) and we are able to obtain MAC of default gateway
            # from ARP cache
            for ip4_host in self.ip4_host:
                if (
                    ip4_host.address == ip4_src
                    and ip4_dst not in ip4_host.network
                ):
                    if ip4_host.gateway is None:
                        self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop += (
                            1
                        )
                        __debug__ and log(
                            "ether",
                            f"{ethernet_packet_tx.tracker} - <WARN>No default "
                            f"gateway set for {ip4_host} source address, "
                            "dropping</>",
                        )
                        return TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP4
                    if mac_address := stack.arp_cache.find_entry(
                        ip4_host.gateway
                    ):
                        self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send += (
                            1
                        )
                        ethernet_packet_tx.dst = mac_address
                        __debug__ and log(
                            "ether",
                            f"{ethernet_packet_tx.tracker} - Resolved destination "
                            f"IPv4 {ip4_dst} to Default Gateway MAC "
                            f"{ethernet_packet_tx.dst}",
                        )
                        self.__send_out_packet(ethernet_packet_tx)
                        return TxStatus.PASSED__ETHERNET__TO_TX_RING
                    self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop += (
                        1
                    )
                    return TxStatus.DROPED__ETHERNET__DST_GATEWAY_ARP_CACHE_FAIL

            # Send out packet if we are able to obtain destination MAC from
            # ARP cache, drop otherwise
            if mac_address := stack.arp_cache.find_entry(ip4_dst):
                self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send += (
                    1
                )
                ethernet_packet_tx.dst = mac_address
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - Resolved destination IPv4 "
                    f"{ip4_dst} to MAC {ethernet_packet_tx.dst}",
                )
                self.__send_out_packet(ethernet_packet_tx)
                return TxStatus.PASSED__ETHERNET__TO_TX_RING
            else:
                self.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop += (
                    1
                )
                __debug__ and log(
                    "ether",
                    f"{ethernet_packet_tx.tracker} - <WARN>No valid destination "
                    "MAC could be obtained from ARP cache, dropping</>",
                )
                return TxStatus.DROPED__ETHERNET__DST_ARP_CACHE_FAIL

        # Drop packet in case we are not able to obtain valid destination MAC address
        self.packet_stats_tx.ethernet__dst_unspec__drop += 1
        __debug__ and log(
            "ether",
            f"{ethernet_packet_tx.tracker} - <WARN>No valid destination MAC could "
            "be obtained, dropping</>",
        )
        return TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL

    @staticmethod
    def __send_out_packet(ethernet_packet_tx: EthernetAssembler) -> None:
        __debug__ and log(
            "ether", f"{ethernet_packet_tx.tracker} - {ethernet_packet_tx}"
        )
        stack.tx_ring.enqueue(ethernet_packet_tx)
