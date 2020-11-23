#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_udp.py - packet handler for inbound UDP packets

"""

import loguru

import stack

from udp_packet import UdpPacket

import ps_icmp


def phrx_udp(self, ipv4_packet_rx, udp_packet_rx):
    """ Handle inbound UDP packets """

    self.logger.opt(ansi=True).info(f"<green>{udp_packet_rx.tracker}</green> - {udp_packet_rx}")

    # Validate UDP packet checksum
    if not udp_packet_rx.validate_cksum(ipv4_packet_rx.ipv4_pseudo_header):
        self.logger.debug(f"{udp_packet_rx.tracker} - UDP packet has invalid checksum, droping")
        return

    # Check if packet is part of stack DHCP client message exchange
    pass

    # Create UdpPacket object containing UDP metadata and try to find matching UDP socket
    packet = UdpPacket(
        local_ipv4_address=ipv4_packet_rx.ipv4_dst,
        local_port=udp_packet_rx.udp_dport,
        remote_ipv4_address=ipv4_packet_rx.ipv4_src,
        remote_port=udp_packet_rx.udp_sport,
        raw_data=udp_packet_rx.raw_data,
        tracker=udp_packet_rx.tracker,
    )

    for socket_id in packet.socket_id_patterns:
        socket = stack.udp_sockets.get(socket_id, None)
        if socket:
            loguru.logger.bind(object_name="socket.").debug(f"{packet.tracker} - Found matching listening socket {socket_id}")
            socket.process_packet(packet)
            return

    # Silently drop packet if it has all zero source IP address
    if ipv4_packet_rx.ipv4_src == "0.0.0.0":
        self.logger.debug(
            f"Received UDP packet from {ipv4_packet_rx.ipv4_src}:{udp_packet_rx.udp_sport} to {ipv4_packet_rx.ipv4_dst}:{udp_packet_rx.udp_dport}, droping"
        )
        return

    # Respond with ICMP Port Unreachable message if no matching socket has been found
    self.logger.debug(f"Received UDP packet from {ipv4_packet_rx.ipv4_src} to closed port {udp_packet_rx.udp_dport}, sending ICMP Port Unreachable")

    self.phtx_icmp(
        ipv4_src=ipv4_packet_rx.ipv4_dst,
        ipv4_dst=ipv4_packet_rx.ipv4_src,
        icmp_type=ps_icmp.ICMP_UNREACHABLE,
        icmp_code=ps_icmp.ICMP_UNREACHABLE_PORT,
        icmp_raw_data=ipv4_packet_rx.get_raw_packet(),
        echo_tracker=udp_packet_rx.tracker,
    )
    return
