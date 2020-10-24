#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phtx_tcp.py - packet handler for outbound TCP packets

"""

import ps_tcp


def phtx_tcp(
    self,
    ip_dst,
    tcp_sport,
    tcp_dport,
    tcp_seq_num=0,
    tcp_ack_num=0,
    tcp_flag_ns=False,
    tcp_flag_crw=False,
    tcp_flag_ece=False,
    tcp_flag_urg=False,
    tcp_flag_ack=False,
    tcp_flag_psh=False,
    tcp_flag_rst=False,
    tcp_flag_syn=False,
    tcp_flag_fin=False,
    tcp_win=0,
    tcp_urp=0,
    tcp_options=[],
    raw_data=b"",
    echo_tracker=None,
):
    """ Handle outbound TCP packets """

    tcp_packet_tx = ps_tcp.TcpPacket(
        tcp_sport=tcp_sport,
        tcp_dport=tcp_dport,
        tcp_seq_num=tcp_seq_num,
        tcp_ack_num=tcp_ack_num,
        tcp_flag_ns=tcp_flag_ns,
        tcp_flag_crw=tcp_flag_crw,
        tcp_flag_ece=tcp_flag_ece,
        tcp_flag_urg=tcp_flag_urg,
        tcp_flag_ack=tcp_flag_ack,
        tcp_flag_psh=tcp_flag_psh,
        tcp_flag_rst=tcp_flag_rst,
        tcp_flag_syn=tcp_flag_syn,
        tcp_flag_fin=tcp_flag_fin,
        tcp_win=tcp_win,
        tcp_urp=tcp_urp,
        tcp_options=tcp_options,
        raw_data=raw_data,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{tcp_packet_tx.tracker}</magenta> - {tcp_packet_tx}")
    self.phtx_ip(ip_dst=ip_dst, child_packet=tcp_packet_tx)
