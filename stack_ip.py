#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack_ip.py - part of TCP/IP stack responsible for handling IP packets

"""

import ph_ip
import ph_icmp
import ph_udp
import ph_tcp


def ip_packet_handler(self, ether_packet_rx, ip_packet_rx):
    """ Handle incoming IP packets """

    self.logger.debug(f"{ether_packet_rx.serial_number_rx} - {ip_packet_rx}")

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
        self.icmp_packet_handler(ether_packet_rx, ip_packet_rx, ph_icmp.IcmpPacket(ip_packet_rx))

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_UDP:
        self.udp_packet_handler(ether_packet_rx, ip_packet_rx, ph_udp.UdpPacket(ip_packet_rx))

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_TCP:
        self.tcp_packet_handler(ether_packet_rx, ip_packet_rx, ph_tcp.TcpPacket(ip_packet_rx))
