#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_ip.py - protocol support for incoming IP packets

"""

import ps_ip
import ps_icmp
import ps_udp
import ps_tcp

ip_fragments = {}


def phrx_ip(self, ether_packet_rx, ip_packet_rx):
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

            # Craft complete IP packet based on last fragment for further processing
            ip_packet_rx.hdr_frag_mf = False
            ip_packet_rx.hdr_frag_offset = 0
            ip_packet_rx.hdr_cksum = ip_packet_rx.compute_cksum()
            ip_packet_rx.raw_data = raw_data

    if ip_packet_rx.hdr_proto == ps_ip.IP_PROTO_ICMP:
        self.phrx_icmp(ether_packet_rx, ip_packet_rx, ps_icmp.IcmpPacket(ip_packet_rx))
        return

    if ip_packet_rx.hdr_proto == ps_ip.IP_PROTO_UDP:
        self.phrx_udp(ether_packet_rx, ip_packet_rx, ps_udp.UdpPacket(ip_packet_rx))
        return

    if ip_packet_rx.hdr_proto == ps_ip.IP_PROTO_TCP:
        self.phrx_tcp(ether_packet_rx, ip_packet_rx, ps_tcp.TcpPacket(ip_packet_rx))
        return
