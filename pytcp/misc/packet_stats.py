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
    """Data store for rx packet handler statistics"""

    ether__pre_parse: int = 0
    ether__failed_parse__drop: int = 0
    ether__dst_unknown__drop: int = 0
    ether__dst_unicast: int = 0
    ether__dst_multicast: int = 0
    ether__dst_broadcast: int = 0

    arp__pre_parse: int = 0
    arp__failed_parse__drop: int = 0
    arp__op_request: int = 0
    arp__op_request__ip_conflict: int = 0
    arp__op_request__tpa_unknown__drop: int = 0
    arp__op_request__update_cache: int = 0
    arp__op_reply: int = 0
    arp__op_reply__ip_conflict: int = 0
    arp__op_reply__update_cache: int = 0
    arp__op_reply__update_cache_gratuitous: int = 0

    ip4__pre_parse: int = 0
    ip4__failed_parse__drop: int = 0
    ip4__dst_unknown__drop: int = 0
    ip4__dst_unicast: int = 0
    ip4__dst_multicast: int = 0
    ip4__dst_broadcast: int = 0
    ip4__frag: int = 0
    ip4__defrag: int = 0

    ip6__pre_parse: int = 0
    ip6__failed_parse__drop: int = 0
    ip6__dst_unknown__drop: int = 0
    ip6__dst_unicast: int = 0
    ip6__dst_multicast: int = 0

    ip6_ext_frag__pre_parse: int = 0
    ip6_ext_frag__failed_parse: int = 0
    ip6_ext_frag__defrag: int = 0

    icmp4__pre_parse: int = 0
    icmp4__failed_parse__drop: int = 0
    icmp4__echo_request: int = 0
    icmp4__unreachable: int = 0

    icmp6__pre_parse: int = 0
    icmp6__failed_parse__drop: int = 0
    icmp6__neighbor_solicitation: int = 0
    icmp6__neighbor_solicitation__unknown: int = 0
    icmp6__neighbor_solicitation__update_cache: int = 0
    icmp6__neighbor_advertisement: int = 0
    icmp6__neighbor_advertisement__run_dad: int = 0
    icmp6__neighbor_advertisement__update_cache: int = 0
    icmp6__router_colicitation: int = 0
    icmp6__router_advertisement: int = 0
    icmp6__echo_request: int = 0
    icmp6__unreachable: int = 0

    udp__pre_parse: int = 0
    udp__failed_parse__drop: int = 0
    udp__socket_match: int = 0
    udp__ip_source_unspecified: int = 0
    udp__echo_native: int = 0
    udp__no_socket_match__respond_icmp4_unreachable: int = 0
    udp__no_socket_match__respond_icmp6_unreachable: int = 0

    tcp__pre_parse: int = 0
    tcp__failed_parse__drop: int = 0
    tcp__socket_match__active: int = 0
    tcp__socket_match__listening: int = 0
    tcp__no_socket_match__respond_rst: int = 0

    def __eq__(self, other):
        return repr(self) == repr(other)


@dataclass
class PacketStatsTx:
    """Data store for tx packet handler statistics"""

    ether__pre_assemble: int = 0
    ether__src_unspec__fill: int = 0
    ether__src_spec: int = 0
    ether__dst_spec__send: int = 0
    ether__dst_unspec: int = 0
    ether__dst_unspec__ip6_lookup: int = 0
    ether__dst_unspec__ip6_lookup__multicast__send: int = 0
    ether__dst_unspec__ip6_lookup__ext_net__no_gw__drop: int = 0
    ether__dst_unspec__ip6_lookup__ext_net__gw_nd_cache_hit__send: int = 0
    ether__dst_unspec__ip6_lookup__ext_net__gw_nd_cache_miss__drop: int = 0
    ether__dst_unspec__ip6_lookup__loc_net__nd_cache_hit__send: int = 0
    ether__dst_unspec__ip4_lookup: int = 0
    ether__dst_unspec__ip4_lookup__limited_broadcast__send: int = 0
    ether__dst_unspec__ip4_lookup__network_broadcast__send: int = 0
    ether__dst_unspec__ip4_lookup__ext_net__no_gw__drop: int = 0
    ether__dst_unspec__ip4_lookup__ext_net__gw_nd_cache_hit__send: int = 0
    ether__dst_unspec__ip4_lookup__loc_net__nd_cache_hit__send: int = 0
    ether__dst_unspec__drop: int = 0

    arp__pre_assemble: int = 0
    arp__no_proto_support__drop: int = 0
    arp__op_request__send: int = 0
    arp__op_reply__send: int = 0

    ip4__pre_assemble: int = 0
    ip4__no_proto_support__drop: int = 0
    ip4__src_invalid__drop: int = 0
    ip4__dst_invalid__drop: int = 0
    ip4__mtu_ok__send: int = 0
    ip4__mtu_exceed__frag: int = 0
    ip4__mtu_exceed__frag__send: int = 0

    ip6__pre_assemble: int = 0
    ip6__no_proto_support__drop: int = 0
    ip6__src_invalid__drop: int = 0
    ip6__dst_invalid__drop: int = 0
    ip6__mtu_ok__send: int = 0
    ip6__mtu_exceed__frag: int = 0

    ip6_ext_frag__pre_assemble: int = 0
    ip6_ext_frag__send: int = 0

    icmp4__pre_assemble: int = 0
    icmp4__echo_reply__send: int = 0
    icmp4__echo_request__send: int = 0
    icmp4__unreachable__send: int = 0

    icmp6__pre_assemble: int = 0
    icmp6__echo_reply__send: int = 0
    icmp6__echo_request__send: int = 0
    icmp6__unreachable__send: int = 0

    tcp__pre_assemble: int = 0
    tcp__flag_ns: int = 0
    tcp__flag_crw: int = 0
    tcp__flag_ece: int = 0
    tcp__flag_urg: int = 0
    tcp__flag_ack: int = 0
    tcp__flag_psh: int = 0
    tcp__flag_rst: int = 0
    tcp__flag_syn: int = 0
    tcp__flag_fin: int = 0
    tcp__send: int = 0
    tcp__unknown__drop: int = 0

    udp__pre_assemble: int = 0
    udp__send: int = 0
    udp__unknown__drop: int = 0

    def __eq__(self, other):
        return repr(self) == repr(other)
