#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# icmp6/phrx.py - packet handler for inbound ICMPv6 packets
#


from typing import cast

import icmp6.fpa
import icmp6.fpp
import icmp6.ps
from icmp6.fpp import Parser as Icmp6Parser
from ip6.fpp import Parser as Ip6Parser
from misc.ipv6_address import IPv6Address
from misc.packet import PacketRx


def _phrx_icmp6(self, packet_rx: PacketRx) -> None:
    """Handle inbound ICMPv6 packets"""

    icmp6.fpp.Parser(packet_rx)

    if packet_rx.parse_failed:
        if __debug__:
            self._logger.critical(f"{packet_rx.tracker} - {packet_rx.parse_failed}")
        return

    if __debug__:
        self._logger.opt(ansi=True).info(f"<green>{packet_rx.tracker}</green> - {packet_rx.icmp6}")

    packet_rx.ip6 = cast(Ip6Parser, packet_rx.ip6)

    # ICMPv6 Neighbor Solicitation packet
    packet_rx.icmp6 = cast(Icmp6Parser, packet_rx.icmp6)
    if packet_rx.icmp6.type == icmp6.ps.NEIGHBOR_SOLICITATION:
        # Check if request is for one of stack's IPv6 unicast addresses
        if packet_rx.icmp6.ns_target_address not in self.ip6_unicast:
            if __debug__:
                self._logger.debug(
                    f"Received ICMPv6 Neighbor Solicitation packet from {packet_rx.ip6.src}, not matching any of stack's IPv6 unicast addresses, dropping..."
                )
            return

        if __debug__:
            self._logger.debug(f"Received ICMPv6 Neighbor Solicitation packet from {packet_rx.ip6.src}, sending reply")

        # Update ICMPv6 ND cache
        if not (packet_rx.ip6.src.is_unspecified or packet_rx.ip6.src.is_multicast) and packet_rx.icmp6.nd_opt_slla:
            self.icmp6_nd_cache.add_entry(packet_rx.ip6.src, packet_rx.icmp6.nd_opt_slla)

        # Determine if request is part of DAD request by examining its source address
        ip6_nd_dad = packet_rx.ip6.src.is_unspecified

        # Send response
        self._phtx_icmp6(
            ip6_src=packet_rx.icmp6.ns_target_address,
            ip6_dst=IPv6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src,  # use ff02::1 destination addriess when responding to DAD equest
            ip6_hop=255,
            icmp6_type=icmp6.ps.NEIGHBOR_ADVERTISEMENT,
            icmp6_na_flag_s=not ip6_nd_dad,  # no S flag when responding to DAD request
            icmp6_na_flag_o=ip6_nd_dad,  # O flag when respondidng to DAD request (this is not necessary but Linux uses it)
            icmp6_na_target_address=packet_rx.icmp6.ns_target_address,
            icmp6_nd_options=[icmp6.fpa.NdOptTLLA(self.mac_unicast)],
            echo_tracker=packet_rx.tracker,
        )
        return

    # ICMPv6 Neighbor Advertisement packet
    if packet_rx.icmp6.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
        if __debug__:
            packet_rx.icmp6 = cast(Icmp6Parser, packet_rx.icmp6)
            self._logger.debug(f"Received ICMPv6 Neighbor Advertisement packet for {packet_rx.icmp6.na_target_address} from {packet_rx.ip6.src}")

        # Run ND Duplicate Address Detection check
        if packet_rx.icmp6.na_target_address == self.ip6_unicast_candidate:
            self.icmp6_nd_dad_tlla = packet_rx.icmp6.nd_opt_tlla
            self.event_icmp6_nd_dad.release()
            return

        # Update ICMPv6 ND cache
        if packet_rx.icmp6.nd_opt_tlla:
            self.icmp6_nd_cache.add_entry(packet_rx.icmp6.na_target_address, packet_rx.icmp6.nd_opt_tlla)
            return

        return

    # ICMPv6 Router Solicitaion packet (this is not currently used by the stack)
    if packet_rx.icmp6.type == icmp6.ps.ROUTER_SOLICITATION:

        if __debug__:
            self._logger.debug(f"Received ICMPv6 Router Advertisement packet from {packet_rx.ip6.src}")
        return

    # ICMPv6 Router Advertisement packet
    if packet_rx.icmp6.type == icmp6.ps.ROUTER_ADVERTISEMENT:

        if __debug__:
            self._logger.debug(f"Received ICMPv6 Router Advertisement packet from {packet_rx.ip6.src}")

        # Make note of prefixes that can be used for address autoconfiguration
        self.icmp6_ra_prefixes = [(_, packet_rx.ip6.src) for _ in packet_rx.icmp6.nd_opt_pi]
        self.event_icmp6_ra.release()
        return

    # Respond to ICMPv6 Echo Request packet
    if packet_rx.icmp6.type == icmp6.ps.ECHO_REQUEST:
        if __debug__:
            self._logger.debug(f"Received ICMPv6 Echo Request packet from {packet_rx.ip6.src}, sending reply")

        self._phtx_icmp6(
            ip6_src=packet_rx.ip6.dst,
            ip6_dst=packet_rx.ip6.src,
            ip6_hop=255,
            icmp6_type=icmp6.ps.ECHO_REPLY,
            icmp6_ec_id=packet_rx.icmp6.ec_id,
            icmp6_ec_seq=packet_rx.icmp6.ec_seq,
            icmp6_ec_data=packet_rx.icmp6.ec_data,
            echo_tracker=packet_rx.tracker,
        )
        return
