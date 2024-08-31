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

# pylint: disable=expression-not-assigned
# pylint: disable=missing-function-docstring
# pylint: disable=unused-argument

"""
Module contains packet handler for the inbound ARP packets.

pytcp/protocols/arp/arp__packet_handler_rx.py

ver 3.0.0
"""


from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.errors import PacketValidationError
from pytcp.lib.logger import log
from pytcp.protocols.arp.arp__header import ArpOperation
from pytcp.protocols.arp.arp__parser import ArpParser


class ArpPacketHandlerRx(ABC):
    """
    Class implementing packet handler for the inbound ARP packets.
    """

    if TYPE_CHECKING:
        from pytcp.lib.ip4_address import Ip4Address, Ip4Host
        from pytcp.lib.mac_address import MacAddress
        from pytcp.lib.packet import PacketRx
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tracker import Tracker
        from pytcp.lib.tx_status import TxStatus

        mac_unicast: MacAddress
        packet_stats_rx: PacketStatsRx
        ip4_host_candidate: list[Ip4Host]

        def _phtx_arp(
            self,
            *,
            ethernet__src: MacAddress,
            ethernet__dst: MacAddress,
            arp__oper: ArpOperation,
            arp__sha: MacAddress,
            arp__spa: Ip4Address,
            arp__tha: MacAddress,
            arp__tpa: Ip4Address,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        @property
        def ip4_unicast(self) -> list[Ip4Address]: ...

    def _phrx_arp(self, *, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP packets.
        """

        self.packet_stats_rx.arp__pre_parse += 1

        try:
            ArpParser(packet_rx=packet_rx)
        except PacketValidationError as error:
            self.packet_stats_rx.arp__failed_parse__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("arp", f"{packet_rx.tracker} - {packet_rx.arp}")

        match packet_rx.arp.oper:
            case ArpOperation.REQUEST:
                self.__phrx_arp__request(
                    packet_rx=packet_rx,
                )
            case ArpOperation.REPLY:
                self.__phrx_arp__reply(
                    packet_rx=packet_rx,
                )

    def __phrx_arp__request(self, *, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP request packets.
        """

        self.packet_stats_rx.arp__op_request += 1
        # Check if request contains our IP address in SPA field,
        # this indicates IP address conflict.
        if packet_rx.arp.spa in self.ip4_unicast:
            self.packet_stats_rx.arp__op_request__ip_conflict += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP ({packet_rx.arp.spa}) "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            return

        # Check if the request is for one of our IP addresses,
        # if so the craft ARP reply packet and send it out.
        if packet_rx.arp.tpa in self.ip4_unicast:
            self.packet_stats_rx.arp__op_request__tpa_stack__respond += 1
            self._phtx_arp(
                ethernet__src=self.mac_unicast,
                ethernet__dst=packet_rx.arp.sha,
                arp__oper=ArpOperation.REPLY,
                arp__sha=self.mac_unicast,
                arp__spa=packet_rx.arp.tpa,
                arp__tha=packet_rx.arp.sha,
                arp__tpa=packet_rx.arp.spa,
                echo_tracker=packet_rx.tracker,
            )

            # Update ARP cache with the mapping learned from the received
            # ARP request that was destined to this stack.
            if config.ARP__CACHE__UPDATE_FROM_DIRECT_REQUEST:
                self.packet_stats_rx.arp__op_request__update_arp_cache += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Adding/refreshing "
                    "ARP cache entry from direct request "
                    f"- {packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
                )
                stack.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return

        else:
            # Drop packet if TPA does not match one of our IP addresses.
            self.packet_stats_rx.arp__op_request__tpa_unknown__drop += 1
            return

    def __phrx_arp__reply(self, *, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP reply packets.
        """

        self.packet_stats_rx.arp__op_reply += 1
        # Check for ARP reply that is response to our ARP probe, this indicates
        # the IP address we trying to claim is in use.
        if packet_rx.ethernet.dst == self.mac_unicast:
            if (
                packet_rx.arp.spa
                in [_.address for _ in self.ip4_host_candidate]
                and packet_rx.arp.tha == self.mac_unicast
                and packet_rx.arp.tpa.is_unspecified
            ):
                self.packet_stats_rx.arp__op_reply__ip_conflict += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <WARN>ARP Probe detected "
                    f"conflict for IP {packet_rx.arp.spa} with host at "
                    f"{packet_rx.arp.sha}</>",
                )
                stack.arp_probe_unicast_conflict.add(packet_rx.arp.spa)
                return

        # Update ARP cache with mapping received as direct ARP reply.
        if packet_rx.ethernet.dst == self.mac_unicast:
            self.packet_stats_rx.arp__op_reply__update_arp_cache += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - Adding/refreshing ARP cache entry "
                f"from direct reply - {packet_rx.arp.spa} "
                f"-> {packet_rx.arp.sha}",
            )
            stack.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return

        # Update ARP cache with mapping received as gratuitous ARP reply.
        if (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and config.ARP__CACHE__UPDATE_FROM_GRATUITIOUS_REPLY
        ):
            self.packet_stats_rx.arp__op_reply__update_arp_cache_gratuitous += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - Adding/refreshing ARP cache entry "
                f"from gratuitous reply - {packet_rx.arp.spa} "
                f"-> {packet_rx.arp.sha}",
            )
            stack.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return
