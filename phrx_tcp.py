#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""

import stack

from tcp_packet import TcpPacket


def phrx_tcp(self, ip_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Validate TCP packet checksum
    if not tcp_packet_rx.validate_cksum(ip_packet_rx.ip_pseudo_header):
        self.logger.debug(f"{tcp_packet_rx.tracker} - TCP packet has invalid checksum, droping")
        return

    # Create TcpPacket object containing TCP metadata for further processing by TCP FSM
    packet = TcpPacket(
        local_ip_address=ip_packet_rx.ip_dst,
        local_port=tcp_packet_rx.tcp_dport,
        remote_ip_address=ip_packet_rx.ip_src,
        remote_port=tcp_packet_rx.tcp_sport,
        flag_syn=tcp_packet_rx.tcp_flag_syn,
        flag_ack=tcp_packet_rx.tcp_flag_ack,
        flag_fin=tcp_packet_rx.tcp_flag_fin,
        flag_rst=tcp_packet_rx.tcp_flag_rst,
        seq_num=tcp_packet_rx.tcp_seq_num,
        ack_num=tcp_packet_rx.tcp_ack_num,
        win=tcp_packet_rx.tcp_win * tcp_packet_rx.tcp_wscale,
        mss=tcp_packet_rx.tcp_mss,
        raw_data=tcp_packet_rx.raw_data,
        tracker=tcp_packet_rx.tracker,
    )

    # Check if incoming packet matches any TCP session
    for tcp_session_id_pattern in packet.tcp_session_id_patterns:
        if tcp_session := stack.tcp_sessions.get(tcp_session_id_pattern, None):
            self.logger.debug(f"{packet.tracker} - TCP packet is part of session {tcp_session.tcp_session_id}")
            tcp_session.tcp_fsm(packet=packet)
            return

    self.logger.debug(f"Received TCP packet from {ip_packet_rx.ip_src} to closed port {tcp_packet_rx.tcp_dport}, responding with TCP RST packet")
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

    return
