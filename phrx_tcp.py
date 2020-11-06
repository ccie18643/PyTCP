#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""


from tcp_socket import TcpSocket, TcpPacketMetadata


def phrx_tcp(self, ip_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Validate TCP packet checksum
    if not tcp_packet_rx.validate_cksum(ip_packet_rx.ip_pseudo_header):
        self.logger.debug(f"{tcp_packet_rx.tracker} - TCP packet has invalid checksum, droping")
        return

    # Send packet info and data to socket mechanism for further processing
    if TcpSocket.match_socket(
        TcpPacketMetadata(
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
            win=tcp_packet_rx.tcp_win,
            raw_data=tcp_packet_rx.raw_data,
            tracker=tcp_packet_rx.tracker,
        )
    ):
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

    return
