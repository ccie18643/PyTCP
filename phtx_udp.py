#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phtx_udp.py - protocol support for outbound UDP packets

"""

import ps_udp


def phtx_udp(self, ip_src, ip_dst, udp_sport, udp_dport, raw_data=b"", echo_tracker=None):
    """ Handle outbound UDP packets """

    udp_packet_tx = ps_udp.UdpPacket(udp_sport=udp_sport, udp_dport=udp_dport, raw_data=raw_data, echo_tracker=echo_tracker)

    self.logger.opt(ansi=True).info(f"<magenta>{udp_packet_tx.tracker}</magenta> - {udp_packet_tx}")
    self.phtx_ip(ip_src=ip_src, ip_dst=ip_dst, child_packet=udp_packet_tx)
