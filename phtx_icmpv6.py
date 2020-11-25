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
    icmpv6_id=None,
    icmpv6_seq=None,
    icmpv6_raw_data=None,
    icmpv6_nd_flag_r=False,
    icmpv6_nd_flag_s=False,
    icmpv6_nd_flag_o=False,
    icmpv6_nd_target_address=None,
    icmpv6_nd_options=[],
    icmpv6_ipv6_packet_rx=None,
    echo_tracker=None,
):
    """ Handle outbound ICMPv6 packets """

    icmpv6_packet_tx = ps_icmpv6.ICMPv6Packet(
        icmpv6_type=icmpv6_type,
        icmpv6_code=icmpv6_code,
        icmpv6_id=icmpv6_id,
        icmpv6_seq=icmpv6_seq,
        icmpv6_raw_data=icmpv6_raw_data,
        icmpv6_nd_flag_r=icmpv6_nd_flag_r,
        icmpv6_nd_flag_s=icmpv6_nd_flag_s,
        icmpv6_nd_flag_o=icmpv6_nd_flag_o,
        icmpv6_nd_options=icmpv6_nd_options,
        icmpv6_nd_target_address=icmpv6_nd_target_address,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmpv6_packet_tx.tracker}</magenta> - {icmpv6_packet_tx}")
    self.phtx_ipv6(ipv6_src=ipv6_src, ipv6_dst=ipv6_dst, child_packet=icmpv6_packet_tx)
