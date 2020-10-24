#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""


import ps_tcp


def phrx_tcp(self, ip_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Socket mechanism support
    if False:
        pass

    else:
        self.logger.debug(f"Received TCP packet from {ip_packet_rx.hdr_src} to closed port {tcp_packet_rx.hdr_dport}, sending TCP Reset packet")

        self.phtx_tcp(
            ip_dst=ip_packet_rx.hdr_src,
            tcp_sport=tcp_packet_rx.hdr_dport,
            tcp_dport=tcp_packet_rx.hdr_sport,
            tcp_ack_num=tcp_packet_rx.hdr_seq_num + 1,
            tcp_flag_rst=True,
            tcp_flag_ack=True,
            echo_tracker=tcp_packet_rx.tracker,
        )
