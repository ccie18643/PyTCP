#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_tcp.py - packet handler for outbound TCP packets

"""


from ps_tcp import TcpPacket, TcpOptMss


PACKET_LOSS = False


def phtx_tcp(
    self,
    ip_src,
    ip_dst,
    tcp_sport,
    tcp_dport,
    tcp_seq=0,
    tcp_ack=0,
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
        tcp_seq=tcp_seq,
        tcp_ack=tcp_ack,
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

    # Check if packet should be dropped due to random packet loss enabled (for TCP retansmission testing)
    if PACKET_LOSS:
        from random import randint

        if randint(0, 9) == 7:
            self.logger.critical("SIMULATED LOSS TX DATA PACKET")
            return

    self.phtx_ip(ip_src=ip_src, ip_dst=ip_dst, child_packet=tcp_packet_tx)
