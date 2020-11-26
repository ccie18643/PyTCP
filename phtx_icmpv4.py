#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_icmpv4.py - packet handler for outbound ICMPv4 packets

"""

import ps_icmpv4


def phtx_icmpv4(
    self, ipv4_src, ipv4_dst, icmpv4_type, icmpv4_code=0, icmpv4_id=None, icmpv4_seq=None, icmpv4_raw_data=None, icmpv4_ipv4_packet_rx=None, echo_tracker=None
):
    """ Handle outbound ICMPv4 packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not self.stack_ipv4_support:
        return

    icmpv4_packet_tx = ps_icmpv4.ICMPv4Packet(
        icmpv4_type=icmpv4_type, icmpv4_code=icmpv4_code, icmpv4_id=icmpv4_id, icmpv4_seq=icmpv4_seq, icmpv4_raw_data=icmpv4_raw_data, echo_tracker=echo_tracker
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmpv4_packet_tx.tracker}</magenta> - {icmpv4_packet_tx}")
    self.phtx_ipv4(ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, child_packet=icmpv4_packet_tx)
