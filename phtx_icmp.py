#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phtx_icmp.py - packet handler for outbound ICMP packets

"""

import ps_icmp


def phtx_icmp(self, ip_dst, icmp_type, icmp_code=0, icmp_msg_id=None, icmp_msg_seq=None, icmp_msg_data=None, icmp_msg_ip_packet_rx=None, echo_tracker=None):
    """ Handle outbound ICMP packets """

    icmp_packet_tx = ps_icmp.IcmpPacket(
        hdr_type=icmp_code, hdr_code=icmp_code, msg_id=icmp_msg_id, msg_seq=icmp_msg_seq, msg_data=icmp_msg_data, echo_tracker=echo_tracker
    )

    self.logger.opt(ansi=True).info(f"<magenta>{icmp_packet_tx.tracker}</magenta> - {icmp_packet_tx}")
    self.phtx_ip(ip_dst=ip_dst, child_packet=icmp_packet_tx)
