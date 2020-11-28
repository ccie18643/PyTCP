#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_icmpv6.py - packet handler for outbound ICMPv6 packets

"""

import ps_icmpv6


def phtx_icmpv6(
    self,
    ipv6_src,
    ipv6_dst,
    icmpv6_type,
    icmpv6_code=0,
    ipv6_hop=64,
    icmpv6_un_raw_data=None,
    icmpv6_ec_id=None,
    icmpv6_ec_seq=None,
    icmpv6_ec_raw_data=None,
    icmpv6_ns_target_address=None,
    icmpv6_na_flag_r=False,
    icmpv6_na_flag_s=False,
    icmpv6_na_flag_o=False,
    icmpv6_na_target_address=None,
    icmpv6_nd_options=[],
    icmpv6_mlr2_multicast_address_record=[],
    icmpv6_ipv6_packet_rx=None,
    echo_tracker=None,
):
    """ Handle outbound ICMPv6 packets """

    # Check if IPv6 protocol support is enabled, if not then silently drop the packet
    if not self.stack_ipv6_support:
        return

    icmpv6_packet_tx = ps_icmpv6.ICMPv6Packet(
        icmpv6_type=icmpv6_type,
        icmpv6_code=icmpv6_code,
        icmpv6_un_raw_data=icmpv6_un_raw_data,
        icmpv6_ec_id=icmpv6_ec_id,
        icmpv6_ec_seq=icmpv6_ec_seq,
        icmpv6_ec_raw_data=icmpv6_ec_raw_data,
        icmpv6_ns_target_address=icmpv6_ns_target_address,
        icmpv6_na_flag_r=icmpv6_na_flag_r,
        icmpv6_na_flag_s=icmpv6_na_flag_s,
        icmpv6_na_flag_o=icmpv6_na_flag_o,
        icmpv6_na_target_address=icmpv6_na_target_address,
        icmpv6_nd_options=icmpv6_nd_options,
        icmpv6_mlr2_multicast_address_record=icmpv6_mlr2_multicast_address_record,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmpv6_packet_tx.tracker}</magenta> - {icmpv6_packet_tx}")
    self.phtx_ipv6(ipv6_src=ipv6_src, ipv6_dst=ipv6_dst, ipv6_hop=ipv6_hop, child_packet=icmpv6_packet_tx)
