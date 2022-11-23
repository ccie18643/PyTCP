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

# pylint: disable = too-many-instance-attributes

"""
Module contains classes used to store packet statistics.

pytcp/lib/packet_stats.py

ver 2.7
"""


from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PacketStatsRx:
    """
    Data store for rx packet handler statistics.
    """

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
    arp__op_request__tpa_stack__respond: int = 0
    arp__op_request__tpa_unknown__drop: int = 0
    arp__op_request__update_arp_cache: int = 0
    arp__op_reply: int = 0
    arp__op_reply__ip_conflict: int = 0
    arp__op_reply__update_arp_cache: int = 0
    arp__op_reply__update_arp_cache_gratuitous: int = 0

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
    icmp4__echo_request__respond_echo_reply: int = 0
    icmp4__unreachable: int = 0

    icmp6__pre_parse: int = 0
    icmp6__failed_parse__drop: int = 0
    icmp6__nd_neighbor_solicitation: int = 0
    icmp6__nd_neighbor_solicitation__target_unknown__drop: int = 0
    icmp6__nd_neighbor_solicitation__target_stack__respond: int = 0
    icmp6__nd_neighbor_solicitation__update_nd_cache: int = 0
    icmp6__nd_neighbor_solicitation__dad: int = 0
    icmp6__nd_neighbor_advertisement: int = 0
    icmp6__nd_neighbor_advertisement__run_dad: int = 0
    icmp6__nd_neighbor_advertisement__update_nd_cache: int = 0
    icmp6__nd_router_solicitation: int = 0
    icmp6__nd_router_advertisement: int = 0
    icmp6__echo_request__respond_echo_reply: int = 0
    icmp6__unreachable: int = 0

    udp__pre_parse: int = 0
    udp__failed_parse__drop: int = 0
    udp__socket_match: int = 0
    udp__ip_source_unspecified: int = 0
    udp__echo_native__respond_udp: int = 0
    udp__no_socket_match__respond_icmp4_unreachable: int = 0
    udp__no_socket_match__respond_icmp6_unreachable: int = 0

    tcp__pre_parse: int = 0
    tcp__failed_parse__drop: int = 0
    tcp__socket_match_active__forward_to_socket: int = 0
    tcp__socket_match_listening__forward_to_socket: int = 0
    tcp__no_socket_match__respond_rst: int = 0

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)


@dataclass
class PacketStatsTx:
    """
    Data store for tx packet handler statistics.
    """

    ether__pre_assemble: int = 0
    ether__src_unspec__fill: int = 0
    ether__src_spec: int = 0
    ether__dst_spec__send: int = 0
    ether__dst_unspec__ip6_lookup: int = 0
    ether__dst_unspec__ip6_lookup__multicast__send: int = 0
    ether__dst_unspec__ip6_lookup__extnet__no_gw__drop: int = 0
    ether__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send: int = 0
    ether__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop: int = 0
    ether__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send: int = 0
    ether__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop: int = 0
    ether__dst_unspec__ip4_lookup: int = 0
    ether__dst_unspec__ip4_lookup__multicast__send: int = 0
    ether__dst_unspec__ip4_lookup__limited_broadcast__send: int = 0
    ether__dst_unspec__ip4_lookup__network_broadcast__send: int = 0
    ether__dst_unspec__ip4_lookup__extnet__no_gw__drop: int = 0
    ether__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send: int = 0
    ether__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop: int = 0
    ether__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send: int = 0
    ether__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop: int = 0
    ether__dst_unspec__drop: int = 0

    arp__pre_assemble: int = 0
    arp__no_proto_support__drop: int = 0
    arp__op_request__send: int = 0
    arp__op_reply__send: int = 0

    ip4__pre_assemble: int = 0
    ip4__no_proto_support__drop: int = 0
    ip4__src_not_owned__drop: int = 0
    ip4__src_multicast__replace: int = 0
    ip4__src_multicast__drop: int = 0
    ip4__src_limited_broadcast__replace: int = 0
    ip4__src_limited_broadcast__drop: int = 0
    ip4__src_network_broadcast__replace: int = 0
    ip4__src_network_unspecified__replace_local: int = 0
    ip4__src_network_unspecified__replace_external: int = 0
    ip4__src_unspecified__send: int = 0
    ip4__src_unspecified__drop: int = 0
    ip4__dst_unspecified__drop: int = 0
    ip4__mtu_ok__send: int = 0
    ip4__mtu_exceed__frag: int = 0
    ip4__mtu_exceed__frag__send: int = 0

    ip6__pre_assemble: int = 0
    ip6__no_proto_support__drop: int = 0
    ip6__src_not_owned__drop: int = 0
    ip6__src_multicast__replace: int = 0
    ip6__src_multicast__drop: int = 0
    ip6__src_network_unspecified__replace_local: int = 0
    ip6__src_network_unspecified__replace_external: int = 0
    ip6__src_unspecified__send: int = 0
    ip6__src_unspecified__drop: int = 0
    ip6__dst_unspecified__drop: int = 0
    ip6__mtu_ok__send: int = 0
    ip6__mtu_exceed__frag: int = 0

    ip6_ext_frag__pre_assemble: int = 0
    ip6_ext_frag__send: int = 0

    icmp4__pre_assemble: int = 0
    icmp4__echo_reply__send: int = 0
    icmp4__echo_request__send: int = 0
    icmp4__unreachable_port__send: int = 0
    icmp4__unknown__drop: int = 0

    icmp6__pre_assemble: int = 0
    icmp6__echo_reply__send: int = 0
    icmp6__echo_request__send: int = 0
    icmp6__unreachable_port__send: int = 0
    icmp6__nd_router_solicitation__send: int = 0
    icmp6__nd_router_advertisement__send: int = 0
    icmp6__nd_neighbor_solicitation__send: int = 0
    icmp6__nd_neighbor_advertisement__send: int = 0
    icmp6__mld2_report__send: int = 0
    icmp6__unknown__drop: int = 0

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
    tcp__opt_nop: int = 0
    tcp__opt_mss: int = 0
    tcp__opt_wscale: int = 0

    udp__pre_assemble: int = 0
    udp__send: int = 0
    udp__unknown__drop: int = 0

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)
