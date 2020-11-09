#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_tcp.py - packet handler for outbound TCP packets

"""


from ps_tcp import TcpPacket, TcpOptMss


def phtx_tcp(
    self,
    ip_src,
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
    tcp_mss=None,
    tcp_win=0,
    tcp_urp=0,
    raw_data=b"",
    tracker=None,
    echo_tracker=None,
):
    """ Handle outbound TCP packets """

    tcp_options = []

    if tcp_mss:
        tcp_options.append(TcpOptMss(opt_mss=tcp_mss))

    tcp_packet_tx = TcpPacket(
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
        tracker=tracker,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{tcp_packet_tx.tracker}</magenta> - {tcp_packet_tx}")
    self.phtx_ip(ip_src=ip_src, ip_dst=ip_dst, child_packet=tcp_packet_tx)

    # Return arguments method has been invoked with so they can be used to re-send packet if needed
    args = locals()
    args.pop("self")
    args.pop("tcp_packet_tx")
    args.pop("tcp_options")
    return args
