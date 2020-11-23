#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_icmp.py - packet handler for outbound ICMP packets

"""

import ps_icmp


def phtx_icmp(self, ipv4_src, ipv4_dst, icmp_type, icmp_code=0, icmp_id=None, icmp_seq=None, icmp_raw_data=None, icmp_ipv4_packet_rx=None, echo_tracker=None):
    """ Handle outbound ICMP packets """

    icmp_packet_tx = ps_icmp.IcmpPacket(
        icmp_type=icmp_type, icmp_code=icmp_code, icmp_id=icmp_id, icmp_seq=icmp_seq, icmp_raw_data=icmp_raw_data, echo_tracker=echo_tracker
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmp_packet_tx.tracker}</magenta> - {icmp_packet_tx}")
    self.phtx_ipv4(ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, child_packet=icmp_packet_tx)
