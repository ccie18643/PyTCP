#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_udp.py - packet handler for inbound UDP packets

"""

from udp_socket import UdpSocket, UdpPacketMetadata

import ps_icmp


def phrx_udp(self, ip_packet_rx, udp_packet_rx):
    """ Handle inbound UDP packets """

    self.logger.opt(ansi=True).info(f"<green>{udp_packet_rx.tracker}</green> - {udp_packet_rx}")

    # Validate UDP packet checksum
    if not udp_packet_rx.validate_cksum(ip_packet_rx.ip_pseudo_header):
        self.logger.debug(f"{udp_packet_rx.tracker} - UDP packet has invalid checksum, droping")
        return

    # Check if packet is part of stack DHCP client message exchange
    pass

    # Send packet info and data to socket mechanism for further processing
    if UdpSocket.match_socket(
        UdpPacketMetadata(
            local_ip_address=ip_packet_rx.ip_dst,
            local_port=udp_packet_rx.udp_dport,
            remote_ip_address=ip_packet_rx.ip_src,
            remote_port=udp_packet_rx.udp_sport,
            raw_data=udp_packet_rx.raw_data,
            tracker=udp_packet_rx.tracker,
        )
    ):
        return

    # Silently drop packet if it has all zero source IP address
    if ip_packet_rx.ip_src == "0.0.0.0":
        self.logger.debug(
            f"Received UDP packet from {ip_packet_rx.ip_src}:{udp_packet_rx.udp_sport} to {ip_packet_rx.ip_dst}:{udp_packet_rx.udp_dport}, droping"
        )
        return

    # Respond with ICMP Port Unreachable message if no matching socket has been found
    self.logger.debug(f"Received UDP packet from {ip_packet_rx.ip_src} to closed port {udp_packet_rx.udp_dport}, sending ICMP Port Unreachable")

    self.phtx_icmp(
        ip_src=ip_packet_rx.ip_dst,
        ip_dst=ip_packet_rx.ip_src,
        icmp_type=ps_icmp.ICMP_UNREACHABLE,
        icmp_code=ps_icmp.ICMP_UNREACHABLE_PORT,
        icmp_raw_data=ip_packet_rx.get_raw_packet(),
        echo_tracker=udp_packet_rx.tracker,
    )
    return
