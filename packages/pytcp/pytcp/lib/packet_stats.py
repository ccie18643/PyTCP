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
This module contains the classes used to store the packet processing statistics.

pytcp/lib/packet_stats.py

ver 3.0.8
"""

import threading
from collections.abc import Callable
from dataclasses import dataclass, fields


@dataclass(slots=True)
class PacketStats:
    """
    The packet statistics data store base class.
    """


@dataclass(slots=True)
class LinkStatsCounters:
    """
    Link-level aggregate counters consumed by the Phase-3
    Link API ('pytcp.stack.link.stats'). Held on the
    'PacketHandler' alongside 'PacketStatsRx' /
    'PacketStatsTx' as a separate dataclass so adding
    byte / multicast counters here does NOT change the
    schema of 'PacketStatsRx' / 'PacketStatsTx' — the
    existing integration-test 'exact=True' assertions
    keep working unchanged (the 'exact' regression net
    only checks 'PacketStatsRx' / 'PacketStatsTx' field
    values, not 'LinkStatsCounters').

    'rx_bytes' / 'tx_bytes' are bumped by 'RxRing' /
    'TxRing' at frame receive / send time. They count
    the wire-level byte length of each frame regardless
    of which protocol consumed it, matching the Linux
    'ifInOctets' / 'ifOutOctets' (RFC 1213 MIB-II)
    semantics that 'ip -s link show' surfaces.
    """

    rx_bytes: int = 0
    tx_bytes: int = 0


@dataclass(slots=True)
class PacketStatsRx(PacketStats):
    """
    Data store for the RX packet handler statistics.
    """

    # Pre-protocol-handler RX-ring counters. Bumped by 'RxRing'
    # when packets are dropped before reaching the handler. A
    # non-zero rate-of-change indicates kernel-side saturation
    # ('rx_ring__queue_full__drop': consumer can't keep up) or
    # transient kernel errors on 'os.read' ('rx_ring__os_error__drop':
    # EINTR / EBADF / EIO / ENOMEM).
    rx_ring__queue_full__drop: int = 0
    rx_ring__os_error__drop: int = 0

    ethernet__pre_parse: int = 0
    ethernet__failed_parse__drop: int = 0
    ethernet__no_proto_support__drop: int = 0
    ethernet__dst_unknown__drop: int = 0
    ethernet__dst_unicast: int = 0
    ethernet__dst_multicast: int = 0
    ethernet__dst_broadcast: int = 0

    ethernet_802_3__pre_parse: int = 0
    ethernet_802_3__failed_parse__drop: int = 0
    ethernet_802_3__dst_unknown__drop: int = 0
    ethernet_802_3__dst_unicast: int = 0
    ethernet_802_3__dst_multicast: int = 0
    ethernet_802_3__dst_broadcast: int = 0
    # LLC dispatch (Phase 2 of the LLC/SNAP wire-up).
    ethernet_802_3__llc_failed_parse__drop: int = 0
    ethernet_802_3__llc_stp_bpdu__drop: int = 0
    ethernet_802_3__llc_novell_ipx__drop: int = 0
    ethernet_802_3__llc_global_dsap__drop: int = 0
    ethernet_802_3__llc_unknown_dsap__drop: int = 0
    # SNAP dispatch (DSAP=0xAA branch).
    ethernet_802_3__snap_failed_parse__drop: int = 0
    ethernet_802_3__snap_rfc1042_ip4: int = 0
    ethernet_802_3__snap_rfc1042_ip6: int = 0
    ethernet_802_3__snap_rfc1042_arp: int = 0
    ethernet_802_3__snap_rfc1042_unknown__drop: int = 0
    # Cisco SNAP (OUI=0x00000C) — individual counters per
    # protocol so log analysis can identify which Cisco
    # management traffic is on the wire.
    ethernet_802_3__snap_cisco_cdp__drop: int = 0
    ethernet_802_3__snap_cisco_cgmp__drop: int = 0
    ethernet_802_3__snap_cisco_vtp__drop: int = 0
    ethernet_802_3__snap_cisco_dtp__drop: int = 0
    ethernet_802_3__snap_cisco_pvst_plus__drop: int = 0
    ethernet_802_3__snap_cisco_vlan_bridge__drop: int = 0
    ethernet_802_3__snap_cisco_udld__drop: int = 0
    ethernet_802_3__snap_cisco_unknown__drop: int = 0
    # Other SNAP OUIs (IEEE 802.1, Apple, etc.).
    ethernet_802_3__snap_unknown_oui__drop: int = 0

    arp__pre_parse: int = 0
    arp__failed_parse__drop: int = 0
    arp__op_unknown__drop: int = 0
    arp__op_request: int = 0
    arp__op_request__looped__drop: int = 0
    arp__op_request__probe: int = 0
    arp__op_request__tpa_stack: int = 0
    arp__op_request__tpa_unknown: int = 0
    arp__op_request__gratuitous: int = 0
    arp__op_request__respond: int = 0
    arp__op_request__update_arp_cache: int = 0
    arp__op_reply: int = 0
    arp__op_reply__looped__drop: int = 0
    arp__op_reply__direct: int = 0
    arp__op_reply__gratuitous: int = 0
    arp__op_reply__update_arp_cache: int = 0

    ip4__pre_parse: int = 0
    ip4__failed_parse__drop: int = 0
    ip4__no_proto_support__drop: int = 0
    ip4__source_route__drop: int = 0
    ip4__src_directed_broadcast__drop: int = 0
    ip4__dst_unknown__drop: int = 0
    ip4__dst_unicast: int = 0
    ip4__dst_multicast: int = 0
    ip4__dst_broadcast: int = 0
    ip4__frag: int = 0
    ip4__defrag: int = 0
    ip4__frag__overlap__drop: int = 0
    ip4__frag__ecn_mixed__drop: int = 0

    ip6__pre_parse: int = 0
    ip6__failed_parse__drop: int = 0
    ip6__no_proto_support__drop: int = 0
    ip6__dst_unknown__drop: int = 0
    ip6__dst_unicast: int = 0
    ip6__dst_multicast: int = 0

    ip6_frag__pre_parse: int = 0
    ip6_frag__failed_parse: int = 0
    ip6_frag__defrag: int = 0
    ip6_frag__overlap__drop: int = 0
    ip6_frag__ecn_mixed__drop: int = 0
    ip6_frag__atomic__defrag: int = 0

    ip6_hbh__pre_parse: int = 0
    ip6_hbh__failed_parse: int = 0
    ip6_hbh__option_cap_exceeded__drop: int = 0
    ip6_routing__pre_parse: int = 0
    ip6_routing__failed_parse: int = 0
    ip6_routing__rh0__drop: int = 0
    ip6_dest_opts__pre_parse: int = 0
    ip6_dest_opts__failed_parse: int = 0
    ip6_dest_opts__option_cap_exceeded__drop: int = 0
    ip6__hbh__not_first__drop: int = 0
    ip6__no_next_header: int = 0

    ip4__no_proto_support__respond_icmp4_unreachable: int = 0
    ip4__no_proto_support__icmp4_unreachable_suppressed: int = 0
    ip6__no_proto_support__respond_icmp6_param_problem: int = 0
    ip6__no_proto_support__icmp6_param_problem_suppressed: int = 0

    # SHOULD #2 - Parameter Problem outbound generation on a
    # sanity-failed inbound IPv4 / IPv6 packet (RFC 1122 §3.2.2.5).
    ip4__sanity_error__respond_icmp4_param_problem: int = 0
    ip4__sanity_error__icmp4_param_problem_suppressed: int = 0
    ip6__sanity_error__respond_icmp6_param_problem: int = 0
    ip6__sanity_error__icmp6_param_problem_suppressed: int = 0

    icmp4__pre_parse: int = 0
    icmp4__failed_parse__drop: int = 0
    icmp4__echo_reply: int = 0
    icmp4__destination_unreachable: int = 0
    icmp4__destination_unreachable__fragmentation_needed: int = 0
    icmp4__destination_unreachable__fragmentation_needed__notify_pmtu: int = 0
    icmp4__destination_unreachable__tcp__notify: int = 0
    icmp4__destination_unreachable__tcp__seq_out_of_window__drop: int = 0
    icmp4__echo_request__respond_echo_reply: int = 0
    icmp4__echo_request__bcast_or_mcast__drop: int = 0
    icmp4__time_exceeded: int = 0
    icmp4__time_exceeded__tcp__notify: int = 0
    icmp4__time_exceeded__tcp__seq_out_of_window__drop: int = 0
    icmp4__time_exceeded__udp__notify: int = 0
    icmp4__parameter_problem: int = 0
    icmp4__parameter_problem__tcp__notify: int = 0
    icmp4__parameter_problem__tcp__seq_out_of_window__drop: int = 0
    icmp4__parameter_problem__udp__notify: int = 0
    icmp4__unknown: int = 0

    icmp6__pre_parse: int = 0
    icmp6__failed_parse__drop: int = 0
    icmp6__destination_unreachable: int = 0
    icmp6__destination_unreachable__tcp__notify: int = 0
    icmp6__destination_unreachable__tcp__seq_out_of_window__drop: int = 0
    icmp6__time_exceeded: int = 0
    icmp6__time_exceeded__tcp__notify: int = 0
    icmp6__time_exceeded__tcp__seq_out_of_window__drop: int = 0
    icmp6__time_exceeded__udp__notify: int = 0
    icmp6__parameter_problem: int = 0
    icmp6__parameter_problem__tcp__notify: int = 0
    icmp6__parameter_problem__tcp__seq_out_of_window__drop: int = 0
    icmp6__parameter_problem__udp__notify: int = 0
    icmp6__packet_too_big: int = 0
    icmp6__packet_too_big__notify_pmtu: int = 0
    icmp6__packet_too_big__tcp__seq_out_of_window__drop: int = 0
    icmp6__echo_request__respond_echo_reply: int = 0
    icmp6__echo_reply: int = 0
    icmp6__nd_neighbor_solicitation: int = 0
    icmp6__nd_neighbor_solicitation__target_unknown__drop: int = 0
    icmp6__nd_neighbor_solicitation__target_stack__respond: int = 0
    icmp6__nd_neighbor_solicitation__update_nd_cache: int = 0
    icmp6__nd_neighbor_solicitation__dad: int = 0
    icmp6__nd_neighbor_solicitation__dad_conflict: int = 0
    icmp6__nd_neighbor_solicitation__loop_hairpin__drop: int = 0
    icmp6__nd_neighbor_advertisement: int = 0
    icmp6__nd_neighbor_advertisement__run_dad: int = 0
    icmp6__nd_neighbor_advertisement__update_nd_cache: int = 0
    icmp6__nd_router_solicitation: int = 0
    icmp6__nd_router_advertisement: int = 0
    icmp6__nd_router_advertisement__prefix_info__drop: int = 0
    icmp6__nd_router_advertisement__update_router: int = 0
    icmp6__nd_router_advertisement__remove_router: int = 0
    icmp6__nd_router_advertisement__defrtr__drop: int = 0
    icmp6__nd_router_advertisement__pi__update_address: int = 0
    icmp6__nd_router_advertisement__pi__remove_address: int = 0
    icmp6__nd_router_advertisement__pi__pinfo_disabled__drop: int = 0
    icmp6__nd_router_advertisement__pi__2hour_rule_ignored__drop: int = 0
    icmp6__nd_router_advertisement__cur_hop_limit__update: int = 0
    icmp6__nd_router_advertisement__cur_hop_limit__floor__drop: int = 0
    icmp6__nd_router_advertisement__reachable_time__update: int = 0
    icmp6__nd_router_advertisement__retrans_timer__update: int = 0
    icmp6__nd_redirect: int = 0
    icmp6__nd_redirect__update_nd_cache: int = 0
    icmp6__nd_redirect__bad_target__drop: int = 0
    icmp6__nd_redirect__accept_redirects_zero__drop: int = 0
    icmp6__nd_message__fragmented__drop: int = 0
    icmp6__mld2_report: int = 0
    icmp6__mld2_query: int = 0
    icmp6__mld2_query__scheduled: int = 0
    icmp6__mld2_query__superseded: int = 0
    icmp6__mld2_query__respond: int = 0
    icmp6__unknown: int = 0

    igmp__pre_parse: int = 0
    igmp__failed_parse__drop: int = 0
    igmp__ttl_invalid__drop: int = 0
    igmp__membership_query: int = 0
    igmp__membership_query__scheduled: int = 0
    igmp__membership_query__superseded: int = 0
    igmp__membership_query__respond: int = 0
    igmp__membership_query__suppressed: int = 0
    igmp__membership_report: int = 0
    igmp__unknown: int = 0

    udp__pre_parse: int = 0
    udp__failed_parse__drop: int = 0
    udp__ip6_zero_cksum__drop: int = 0
    udp__socket_match: int = 0
    udp__multicast_source_filtered__drop: int = 0
    udp__ip_source_unspecified: int = 0
    udp__echo_native__respond_udp: int = 0
    udp__no_socket_match__respond_icmp4_unreachable: int = 0
    udp__no_socket_match__respond_icmp6_unreachable: int = 0
    udp__no_socket_match__icmp4_unreachable_suppressed: int = 0
    udp__no_socket_match__icmp6_unreachable_suppressed: int = 0

    tcp__pre_parse: int = 0
    tcp__failed_parse__drop: int = 0
    tcp__socket_match_active__forward_to_socket: int = 0
    tcp__socket_match_listening__forward_to_socket: int = 0
    tcp__no_socket_match__rst__drop: int = 0
    tcp__no_socket_match__respond_rst: int = 0

    raw__socket_match: int = 0
    raw__multicast_source_filtered__drop: int = 0


@dataclass(slots=True)
class PacketStatsTx(PacketStats):
    """
    Data store for the TX packet handler statistics.
    """

    # Post-protocol-handler TX-ring counters. Bumped by 'TxRing'
    # when packets are dropped after the handler emits them.
    # 'tx_ring__queue_full__drop': producer outpaced 'os.writev'
    # drain. 'tx_ring__os_error__drop': 'os.writev' raised
    # 'OSError' (typically ENOBUFS / ENETDOWN / EIO).
    tx_ring__queue_full__drop: int = 0
    tx_ring__os_error__drop: int = 0

    ethernet__pre_assemble: int = 0
    ethernet__src_unspec__fill: int = 0
    ethernet__src_spec: int = 0
    ethernet__dst_spec__send: int = 0
    ethernet__dst_unspec__ip6_lookup: int = 0
    ethernet__dst_unspec__ip6_lookup__multicast__send: int = 0
    ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop: int = 0
    ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send: int = 0
    ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop: int = 0
    ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send: int = 0
    ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop: int = 0
    ethernet__dst_unspec__ip4_lookup: int = 0
    ethernet__dst_unspec__ip4_lookup__multicast__send: int = 0
    ethernet__dst_unspec__ip4_lookup__limited_broadcast__send: int = 0
    ethernet__dst_unspec__ip4_lookup__network_broadcast__send: int = 0
    ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop: int = 0
    ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send: int = 0
    ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop: int = 0
    ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send: int = 0
    ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop: int = 0
    ethernet__dst_unspec__drop: int = 0

    ethernet_802_3__pre_assemble: int = 0
    ethernet_802_3__src_unspec__fill: int = 0
    ethernet_802_3__src_spec: int = 0
    ethernet_802_3__dst_spec__send: int = 0
    ethernet_802_3__dst_unspec__drop: int = 0

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
    ip4__dst_broadcast_disallowed__drop: int = 0
    ip4__link_local_scope_mismatch__drop: int = 0
    ip4__mtu_ok__send: int = 0
    ip4__loopback__send: int = 0
    ip4__mtu_exceed__frag: int = 0
    ip4__mtu_exceed__frag__send: int = 0
    ip4__mtu_exceed__df_set__drop: int = 0

    ip6__pre_assemble: int = 0
    ip6__no_proto_support__drop: int = 0
    ip6__src_not_owned__drop: int = 0
    ip6__src_multicast__replace: int = 0
    ip6__src_multicast__drop: int = 0
    ip6__src_network_unspecified__replace_local: int = 0
    ip6__src_network_unspecified__replace_external: int = 0
    ip6__src_unspecified__replace_multicast: int = 0
    ip6__src_unspecified__send: int = 0
    ip6__src_unspecified__drop: int = 0
    ip6__src_scope_mismatch__drop: int = 0
    ip6__dst_unspecified__drop: int = 0
    ip6__mtu_ok__send: int = 0
    ip6__loopback__send: int = 0
    ip6__mtu_exceed__frag: int = 0

    ip6_frag__pre_assemble: int = 0
    ip6_frag__send: int = 0
    ip6_frag__nd_message__drop: int = 0

    icmp4__pre_assemble: int = 0
    icmp4__echo_reply__send: int = 0
    icmp4__echo_request__send: int = 0
    icmp4__destination_unreachable__port__send: int = 0
    icmp4__destination_unreachable__protocol__send: int = 0
    icmp4__parameter_problem__send: int = 0
    icmp4__unknown__drop: int = 0

    icmp6__pre_assemble: int = 0
    icmp6__echo_reply__send: int = 0
    icmp6__echo_request__send: int = 0
    icmp6__destination_unreachable__port__send: int = 0
    icmp6__parameter_problem__send: int = 0
    icmp6__nd__router_solicitation__send: int = 0
    icmp6__nd__router_advertisement__send: int = 0
    icmp6__nd__neighbor_solicitation__send: int = 0
    icmp6__nd__neighbor_advertisement__send: int = 0
    icmp6__mld2__report__send: int = 0
    icmp6__mld1__report__send: int = 0
    icmp6__unknown__drop: int = 0

    igmp__pre_assemble: int = 0
    igmp__v3_report__send: int = 0
    igmp__v2_report__send: int = 0
    igmp__v1_report__send: int = 0
    igmp__v2_leave__send: int = 0

    tcp__pre_assemble: int = 0
    tcp__flag_ns: int = 0
    tcp__flag_cwr: int = 0
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
    tcp__opt_sackperm: int = 0
    tcp__opt_sack: int = 0
    tcp__opt_timestamps: int = 0

    udp__pre_assemble: int = 0
    udp__send: int = 0
    udp__unknown__drop: int = 0


class PacketStatsShards[T: PacketStats]:
    """
    Per-thread shards of a 'PacketStats' dataclass for free-threaded
    (no-GIL) counter accumulation. Each writing thread increments its
    own shard via 'current()' with no lock and no cross-core
    contention; 'snapshot()' sums the shards field-by-field into a
    fresh instance for introspection. The Linux 'percpu_counter'
    analogue — lock-per-increment would serialize the per-packet hot
    path, so the counters are sharded instead and reconciled only on
    the (rare) read.

    The constructing thread's shard is seeded with the supplied
    instance so test fixtures that inject a 'PacketStats' object and
    drive the stack synchronously on one thread read their exact
    counts back unchanged.
    """

    def __init__(self, *, factory: Callable[[], T], seed: T) -> None:
        """
        Bind the per-shard factory and register the seed shard to the
        constructing thread.
        """

        self._factory = factory
        self._shards: list[T] = [seed]
        self._local = threading.local()
        self._local.shard = seed
        self._lock = threading.Lock()

    def current(self) -> T:
        """
        Get the calling thread's shard, creating and registering one
        on first access from a new thread.
        """

        shard: T | None = getattr(self._local, "shard", None)
        if shard is None:
            shard = self._factory()
            with self._lock:
                self._shards.append(shard)
            self._local.shard = shard
        return shard

    def snapshot(self) -> T:
        """
        Get a fresh copy-by-value instance summing every thread's
        shard field-by-field.
        """

        with self._lock:
            shards = tuple(self._shards)
        result = self._factory()
        for field in fields(result):
            setattr(result, field.name, sum(getattr(shard, field.name) for shard in shards))
        return result
