#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""

import stack

from tcp_packet_metadata import TcpPacketMetadata


PACKET_LOSS = True


def phrx_tcp(self, ipv4_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Validate TCP packet checksum
    if not tcp_packet_rx.validate_cksum(ipv4_packet_rx.ipv4_pseudo_header):
        self.logger.debug(f"{tcp_packet_rx.tracker} - TCP packet has invalid checksum, droping")
        return

    # Create TcpPacket object containing TCP metadata for further processing by TCP FSM
    packet = TcpPacketMetadata(
        local_ipv4_address=ipv4_packet_rx.ipv4_dst,
        local_port=tcp_packet_rx.tcp_dport,
        remote_ipv4_address=ipv4_packet_rx.ipv4_src,
        remote_port=tcp_packet_rx.tcp_sport,
        flag_syn=tcp_packet_rx.tcp_flag_syn,
        flag_ack=tcp_packet_rx.tcp_flag_ack,
        flag_fin=tcp_packet_rx.tcp_flag_fin,
        flag_rst=tcp_packet_rx.tcp_flag_rst,
        seq=tcp_packet_rx.tcp_seq,
        ack=tcp_packet_rx.tcp_ack,
        win=tcp_packet_rx.tcp_win,
        wscale=tcp_packet_rx.tcp_wscale,
        mss=tcp_packet_rx.tcp_mss,
        raw_data=tcp_packet_rx.raw_data,
        tracker=tcp_packet_rx.tracker,
    )

    # Check if packet should be dropped due to random packet loss enabled (for TCP retansmission testing)
    if PACKET_LOSS:
        from random import randint

        if randint(0, 99) == 7:
            self.logger.critical("SIMULATED LOST RX DATA PACKET")
            return

    # Check if incoming packet matches active TCP session
    if tcp_session := stack.tcp_sessions.get(packet.tcp_session_id, None):
        self.logger.debug(f"{packet.tracker} - TCP packet is part of active session {tcp_session.tcp_session_id}")
        tcp_session.tcp_fsm(packet=packet)
        return

    # Check if incoming packet is an initial SYN packet and if it matches any listening TCP session
    if all({packet.flag_syn}) and not any({packet.flag_ack, packet.flag_fin, packet.flag_rst}):
        for tcp_session_id_pattern in packet.tcp_session_listening_patterns:
            if tcp_session := stack.tcp_sessions.get(tcp_session_id_pattern, None):
                self.logger.debug(f"{packet.tracker} - TCP packet matches listening session {tcp_session.tcp_session_id}")
                tcp_session.tcp_fsm(packet=packet)
                return

    # In case packet doesn't match any session send RST packet in response to it
    self.logger.debug(f"Received TCP packet from {ipv4_packet_rx.ipv4_src} to closed port {tcp_packet_rx.tcp_dport}, responding with TCP RST packet")
    self.phtx_tcp(
        ipv4_src=ipv4_packet_rx.ipv4_dst,
        ipv4_dst=ipv4_packet_rx.ipv4_src,
        tcp_sport=tcp_packet_rx.tcp_dport,
        tcp_dport=tcp_packet_rx.tcp_sport,
        tcp_seq=0,
        tcp_ack=tcp_packet_rx.tcp_seq + tcp_packet_rx.tcp_flag_syn + tcp_packet_rx.tcp_flag_fin + len(tcp_packet_rx.raw_data),
        tcp_flag_rst=True,
        tcp_flag_ack=True,
        echo_tracker=tcp_packet_rx.tracker,
    )

    return
