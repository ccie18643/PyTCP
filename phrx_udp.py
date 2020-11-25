#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_udp.py - packet handler for inbound UDP packets

"""

import loguru

from ipaddress import IPv4Address, IPv6Address

import stack

from udp_metadata import UdpMetadata

import ps_icmpv4


def phrx_udp(self, ip_packet_rx, udp_packet_rx):
    """ Handle inbound UDP packets """

    self.logger.opt(ansi=True).info(f"<green>{udp_packet_rx.tracker}</green> - {udp_packet_rx}")

    # Validate UDP packet checksum
    if not udp_packet_rx.validate_cksum(ip_packet_rx.ip_pseudo_header):
        self.logger.debug(f"{udp_packet_rx.tracker} - UDP packet has invalid checksum, droping")
        return

    # Check if packet is part of stack DHCP client message exchange
    pass

    # Set universal names for src and dst IP addresses whether packet was delivered by IPv6 or IPv4 protocol
    ip_packet_rx.ip_dst = ip_packet_rx.ipv6_dst if ip_packet_rx.protocol == "IPv6" else ip_packet_rx.ipv4_dst
    ip_packet_rx.ip_src = ip_packet_rx.ipv6_src if ip_packet_rx.protocol == "IPv6" else ip_packet_rx.ipv4_src

    # Create UdpMetadata object and try to find matching UDP socket
    packet = UdpMetadata(
        local_ip_address=ip_packet_rx.ip_dst,
        local_port=udp_packet_rx.udp_dport,
        remote_ip_address=ip_packet_rx.ip_src,
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
    if ip_packet_rx.ip_src in {IPv4Address("0.0.0.0"), IPv6Address("::")}:
        self.logger.debug(
            f"Received UDP packet from {ip_packet_rx.ip_src}:{udp_packet_rx.udp_sport} to {ip_packet_rx.ip_dst}:{udp_packet_rx.udp_dport}, droping"
        )
        return

    # Respond with ICMPv4 Port Unreachable message if no matching socket has been found
    self.logger.debug(f"Received UDP packet from {ip_packet_rx.ip_src} to closed port {udp_packet_rx.udp_dport}, sending ICMPv4 Port Unreachable")

    if ip_packet_rx.protocol == "IPv6":
        self.phtx_icmpv6(
            ipv6_src=ip_packet_rx.ipv6_dst,
            ipv6_dst=ip_packet_rx.ipv6_src,
            icmpv6_type=ps_icmpv6.ICMPV6_UNREACHABLE,
            icmpv6_code=ps_icmpv6.ICMPV6_UNREACHABLE_PORT,
            icmpv6_raw_data=ip_packet_rx.get_raw_packet(),
            echo_tracker=udp_packet_rx.tracker,
        )

    if ip_packet_rx.protocol == "IPv4":
        self.phtx_icmpv4(
            ipv4_src=ip_packet_rx.ip_dst,
            ipv4_dst=ip_packet_rx.ip_src,
            icmpv4_type=ps_icmpv4.ICMPV4_UNREACHABLE,
            icmpv4_code=ps_icmpv4.ICMPV4_UNREACHABLE_PORT,
            icmpv4_raw_data=ip_packet_rx.get_raw_packet(),
            echo_tracker=udp_packet_rx.tracker,
        )

    return
