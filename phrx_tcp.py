#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_tcp.py - packet handler for inbound TCP packets

"""


class TcpSession:
    """ Class defining all the TCP session parameters """

    def __init__(self, local_ip_address, local_port, remote_ip_address, remote_port):
        """ Class constructor """

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port

    @property
    def session_id(self):
        """ Session ID """

        return f"TCP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"


def phrx_tcp_session(self, session):
    """ Handle TCP session """

    print(session)


def phrx_tcp(self, ip_packet_rx, tcp_packet_rx):
    """ Handle inbound TCP packets """

    self.logger.opt(ansi=True).info(f"<green>{tcp_packet_rx.tracker}</green> - {tcp_packet_rx}")

    # Silently drop packet if it doesn't seem to be valid
    if ip_packet_rx.ip_src == "0.0.0.0":
        self.logger.debug(
            f"Received TCP packet from {ip_packet_rx.ip_src}:{tcp_packet_rx.tcp_sport} to {ip_packet_rx.ip_dst}:{tcp_packet_rx.tcp_dport}, droping"
        )
        return

    # Check if incoming packet is part of existing connection
    session = self.tcp_sessions.get(f"TCP/{ip_packet_rx.ip_dst}/{tcp_packet_rx.tcp_dport}/{ip_packet_rx.ip_src}/{tcp_packet_rx.tcp_sport}", None)

    if session:
        self.phrx_tcp_session(session)
        return

    # Check if incoming packet contains intial SYN, if so start session
    if tcp_packet_rx.tcp_flag_syn:
        session = self.tcp_sessions[f"TCP/{ip_packet_rx.ip_dst}/{tcp_packet_rx.tcp_dport}/{ip_packet_rx.ip_src}/{tcp_packet_rx.tcp_sport}"] = TcpSession(
            local_ip_address=ip_packet_rx.ip_dst, local_port=tcp_packet_rx.tcp_dport, remote_ip_address=ip_packet_rx.ip_src, remote_port=tcp_packet_rx.tcp_sport
        )

    if session:
        self.phrx_tcp_session(session)
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
