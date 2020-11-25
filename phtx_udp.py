#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_udp.py - protocol support for outbound UDP packets

"""

from ipaddress import IPv4Address, IPv6Address

import ps_udp


def phtx_udp(self, ip_src, ip_dst, udp_sport, udp_dport, raw_data=b"", echo_tracker=None):
    """ Handle outbound UDP packets """

    udp_packet_tx = ps_udp.UdpPacket(udp_sport=udp_sport, udp_dport=udp_dport, raw_data=raw_data, echo_tracker=echo_tracker)

    self.logger.opt(ansi=True).info(f"<magenta>{udp_packet_tx.tracker}</magenta> - {udp_packet_tx}")

    assert type(ip_src) in {IPv4Address, IPv6Address}
    assert type(ip_dst) in {IPv4Address, IPv6Address}

    if ip_src.version == 6 and ip_dst.version == 6:
        self.phtx_ipv6(ipv6_src=ip_src, ipv6_dst=ip_dst, child_packet=udp_packet_tx)

    if ip_src.version == 4 and ip_dst.version == 4:
        self.phtx_ipv4(ipv4_src=ip_src, ipv4_dst=ip_dst, child_packet=udp_packet_tx)

