#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


# pylint: disable = too-many-return-statements
# pylint: disable = expression-not-assigned
# pylint: disable = protected-access
# pylint: disable = no-else-return

"""
Module contains packet handler for the inbound ARP packets.

pytcp/protocols/arp/phrx.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.logger import log
from pytcp.protocols.arp.fpp import ArpParser
from pytcp.protocols.arp.ps import ARP_OP_REPLY, ARP_OP_REQUEST

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx
    from pytcp.subsystems.packet_handler import PacketHandler


def _phrx_arp(self: PacketHandler, packet_rx: PacketRx) -> None:
    """
    Handle inbound ARP packets.
    """

    self.packet_stats_rx.arp__pre_parse += 1

    ArpParser(packet_rx)

    if packet_rx.parse_failed:
        self.packet_stats_rx.arp__failed_parse__drop += 1
        __debug__ and log(
            "arp",
            f"{packet_rx.tracker} - <CRIT>{packet_rx.parse_failed}</>",
        )
        return

    __debug__ and log("arp", f"{packet_rx.tracker} - {packet_rx.arp}")

    if packet_rx.arp.oper == ARP_OP_REQUEST:
        self.packet_stats_rx.arp__op_request += 1
        # Check if request contains our IP address in SPA field,
        # this indicates IP address conflict
        if packet_rx.arp.spa in self.ip4_unicast:
            self.packet_stats_rx.arp__op_request__ip_conflict += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP ({packet_rx.arp.spa}) "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            return

        # Check if the request is for one of our IP addresses,
        # if so the craft ARP reply packet and send it out
        if packet_rx.arp.tpa in self.ip4_unicast:
            self.packet_stats_rx.arp__op_request__tpa_stack__respond += 1
            self._phtx_arp(
                ether_src=self.mac_unicast,
                ether_dst=packet_rx.arp.sha,
                arp_oper=ARP_OP_REPLY,
                arp_sha=self.mac_unicast,
                arp_spa=packet_rx.arp.tpa,
                arp_tha=packet_rx.arp.sha,
                arp_tpa=packet_rx.arp.spa,
                echo_tracker=packet_rx.tracker,
            )

            # Update ARP cache with the mapping learned from the received
            # ARP request that was destined to this stack
            if config.ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
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
            # Drop packet if TPA does not match one of our IP addresses
            self.packet_stats_rx.arp__op_request__tpa_unknown__drop += 1
            return

    # Handle ARP reply
    elif packet_rx.arp.oper == ARP_OP_REPLY:
        self.packet_stats_rx.arp__op_reply += 1
        # Check for ARP reply that is response to our ARP probe, this indicates
        # the IP address we trying to claim is in use
        if packet_rx.ether.dst == self.mac_unicast:
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

        # Update ARP cache with mapping received as direct ARP reply
        if packet_rx.ether.dst == self.mac_unicast:
            self.packet_stats_rx.arp__op_reply__update_arp_cache += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - Adding/refreshing ARP cache entry "
                f"from direct reply - {packet_rx.arp.spa} "
                f"-> {packet_rx.arp.sha}",
            )
            stack.arp_cache.add_entry(packet_rx.arp.spa, packet_rx.arp.sha)
            return

        # Update ARP cache with mapping received as gratuitous ARP reply
        if (
            packet_rx.ether.dst.is_broadcast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and config.ARP_CACHE_UPDATE_FROM_GRATUITIOUS_REPLY
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
