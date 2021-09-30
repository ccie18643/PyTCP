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
# packet_stats.py - module contains class used to store packet handler statistics
#

from __future__ import annotations  # Required by Python ver < 3.10

from dataclasses import dataclass


@dataclass
class PacketStatsRx:
    """Data store for packet handler statistics"""

    ether_pre_parse: int = 0
    ether_failed_parse: int = 0
    ether_unknown_dst: int = 0
    ether_unicast: int = 0
    ether_multicast: int = 0
    ether_broadcast: int = 0

    arp_pre_parse: int = 0
    arp_failed_parse: int = 0
    arp_op_request: int = 0
    arp_op_request_ip_conflict: int = 0
    arp_op_request_update_cache: int = 0
    arp_op_reply: int = 0
    arp_op_reply_ip_conflict: int = 0
    arp_op_reply_update_cache: int = 0
    arp_op_reply_update_cache_gratuitous: int = 0

    ip4_pre_parse: int = 0
    ip4_failed_parse: int = 0
    ip4_unknown_dst: int = 0
    ip4_unicast: int = 0
    ip4_multicast: int = 0
    ip4_broadcast: int = 0
    ip4_frag: int = 0

    ip6_pre_parse: int = 0
    ip6_failed_parse: int = 0
    ip6_unknown_dst: int = 0
    ip6_unicast: int = 0
    ip6_multicast: int = 0

    icmp4_pre_parse: int = 0
    icmp4_failed_parse: int = 0
    icmp4_echo_request: int = 0
    icmp4_unreachable: int = 0

    icmp6_pre_parse: int = 0
    icmp6_failed_parse: int = 0
    icmp6_neighbor_solicitation: int = 0
    icmp6_neighbor_solicitation_unknown: int = 0
    icmp6_neighbor_solicitation_update_cache: int = 0
    icmp6_neighbor_advertisement: int = 0
    icmp6_neighbor_advertisement_run_dad: int = 0
    icmp6_neighbor_advertisement_update_cache: int = 0
    icmp6_router_colicitation: int = 0
    icmp6_router_advertisement: int = 0
    icmp6_echo_request: int = 0
    icmp6_unreachable: int = 0

    def __eq__(self, other):
        return repr(self) == repr(other)
