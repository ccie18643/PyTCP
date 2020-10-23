#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack_ip.py - part of TCP/IP stack responsible for handling IP packets

"""

import ph_ip
import ph_icmp
import ph_udp
import ph_tcp

ip_fragments = {}

def ip_packet_handler(self, ether_packet_rx, ip_packet_rx):
    """ Handle incoming IP packets """

    self.logger.debug(f"{ether_packet_rx.serial_number_rx} - {ip_packet_rx}")

    # Check if IP packet is a first fragment
    if ip_packet_rx.hdr_frag_offset == 0 and ip_packet_rx.hdr_frag_mf:
        ip_fragments[ip_packet_rx.hdr_id] = {}
        ip_fragments[ip_packet_rx.hdr_id][ip_packet_rx.hdr_frag_offset] = ip_packet_rx.raw_data
        return

    # Check if IP packet is one of middle fragments
    if ip_packet_rx.hdr_frag_offset != 0 and ip_packet_rx.hdr_frag_mf:
        # Check if packet is part of existing fagment flow
        if ip_fragments.get(ip_packet_rx.hdr_id, None):
            ip_fragments[ip_packet_rx.hdr_id][ip_packet_rx.hdr_frag_offset] = ip_packet_rx.raw_data
        return

    # Check if IP packet is one of the last fragments
    if ip_packet_rx.hdr_frag_offset != 0 and not ip_packet_rx.hdr_frag_mf:
        # Check if packet is part of existing fagment flow
        if ip_fragments.get(ip_packet_rx.hdr_id, None):
            ip_fragments[ip_packet_rx.hdr_id][ip_packet_rx.hdr_frag_offset] = ip_packet_rx.raw_data

            raw_data = b""
            for offset in sorted(ip_fragments[ip_packet_rx.hdr_id]):
                raw_data += ip_fragments[ip_packet_rx.hdr_id][offset]

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_ICMP:
        self.icmp_packet_handler(ether_packet_rx, ip_packet_rx, ph_icmp.IcmpPacket(ip_packet_rx))
        return

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_UDP:
        self.udp_packet_handler(ether_packet_rx, ip_packet_rx, ph_udp.UdpPacket(ip_packet_rx))
        return

    if ip_packet_rx.hdr_proto == ph_ip.IP_PROTO_TCP:
        self.tcp_packet_handler(ether_packet_rx, ip_packet_rx, ph_tcp.TcpPacket(ip_packet_rx))
        return
