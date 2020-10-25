#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""




def phrx_tcp(self, ip_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Silently drop packet if it has all zero source IP address
    if ip_packet_rx.ip_src == "0.0.0.0":
        self.logger.debug(
            f"Received TCP packet from {ip_packet_rx.ip_src}:{tcp_packet_rx.tcp_sport} to {ip_packet_rx.ip_dst}:{tcp_packet_rx.tcp_dport}, droping"
        )
        return

    self.logger.debug(f"Received TCP packet from {ip_packet_rx.ip_src} to closed port {tcp_packet_rx.tcp_dport}, sending TCP Reset packet")

    self.phtx_tcp(
        ip_src=ip_packet_rx.ip_dst,
        ip_dst=ip_packet_rx.ip_src,
        tcp_sport=tcp_packet_rx.tcp_dport,
        tcp_dport=tcp_packet_rx.tcp_sport,
        tcp_ack_num=tcp_packet_rx.tcp_seq_num + 1,
        tcp_flag_rst=True,
        tcp_flag_ack=True,
        echo_tracker=tcp_packet_rx.tracker,
    )
