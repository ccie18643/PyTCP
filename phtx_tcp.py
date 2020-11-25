#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_tcp.py - packet handler for outbound TCP packets

"""

from ipaddress import IPv4Address, IPv6Address

from ps_tcp import TcpPacket, TcpOptMss, TcpOptWscale, TcpOptNop


PACKET_LOSS = True


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
        tcp_options.append(TcpOptNop())
        tcp_options.append(TcpOptWscale(opt_wscale=0))

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

        if randint(0, 99) == 7:
            self.logger.critical("SIMULATED LOST TX DATA PACKET")
            return

    assert type(ip_src) in {IPv4Address, IPv6Address}
    assert type(ip_dst) in {IPv4Address, IPv6Address}

    if ip_src.version == 6 and ip_dst.version == 6:
        self.phtx_ipv6(ipv6_src=ip_src, ipv6_dst=ip_dst, child_packet=tcp_packet_tx)

    if ip_src.version == 4 and ip_dst.version == 4:
        self.phtx_ipv4(ipv4_src=ip_src, ipv4_dst=ip_dst, child_packet=tcp_packet_tx)
    
