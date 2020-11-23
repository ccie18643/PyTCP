#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_ip.py - packet handler for inbound IP packets

"""

import ps_ip
import ps_icmp
import ps_udp
import ps_tcp

import inet_cksum


ip_fragments = {}


def handle_ip_fragmentation(self, ip_packet_rx):
    """ Check if packet is fragmented """

    # Check if IP packet is a first fragment
    if ip_packet_rx.ip_frag_offset == 0 and ip_packet_rx.ip_frag_mf:
        ip_fragments[ip_packet_rx.ip_id] = {}
        ip_fragments[ip_packet_rx.ip_id][ip_packet_rx.ip_frag_offset] = ip_packet_rx.raw_data
        return

    # Check if IP packet is one of middle fragments
    if ip_packet_rx.ip_frag_offset != 0 and ip_packet_rx.ip_frag_mf:
        # Check if packet is part of existing fagment flow
        if ip_fragments.get(ip_packet_rx.ip_id, None):
            ip_fragments[ip_packet_rx.ip_id][ip_packet_rx.ip_frag_offset] = ip_packet_rx.raw_data
        return

    # Check if IP packet is last fragment
    if ip_packet_rx.ip_frag_offset != 0 and not ip_packet_rx.ip_frag_mf:

        # Check if packet is part of existing fagment flow
        if ip_fragments.get(ip_packet_rx.ip_id, None):
            ip_fragments[ip_packet_rx.ip_id][ip_packet_rx.ip_frag_offset] = ip_packet_rx.raw_data

            raw_data = b""
            for offset in sorted(ip_fragments[ip_packet_rx.ip_id]):
                raw_data += ip_fragments[ip_packet_rx.ip_id][offset]

            # Craft complete IP packet based on last fragment for further processing
            ip_packet_rx.ip_frag_mf = False
            ip_packet_rx.ip_frag_offset = 0
            ip_packet_rx.ip_plen = ip_packet_rx.ip_hlen + len(raw_data)
            ip_packet_rx.ip_cksum = 0
            ip_packet_rx.ip_cksum = inet_cksum.compute_cksum(ip_packet_rx.raw_header)
            ip_packet_rx.raw_data = raw_data

    return ip_packet_rx


def phrx_ip(self, ip_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ip_packet_rx.tracker} - {ip_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast/broadcast
    if (
        ip_packet_rx.ip_dst not in self.stack_ip_unicast
        and ip_packet_rx.ip_dst not in self.stack_ip_multicast
        and ip_packet_rx.ip_dst not in self.stack_ip_broadcast
    ):
        self.logger.debug(f"{ip_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    # Validate IP header checksum
    if not ip_packet_rx.validate_cksum():
        self.logger.debug(f"{ip_packet_rx.tracker} - IP packet has invalid checksum, droping")
        return

    # Check if packet is a fragment, and if so process it accrdingly
    ip_packet_rx = handle_ip_fragmentation(self, ip_packet_rx)
    if not ip_packet_rx:
        return

    if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_ICMP:
        self.phrx_icmp(ip_packet_rx, ps_icmp.IcmpPacket(ip_packet_rx))
        return

    if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_UDP:
        self.phrx_udp(ip_packet_rx, ps_udp.UdpPacket(ip_packet_rx))
        return

    if ip_packet_rx.ip_proto == ps_ip.IP_PROTO_TCP:
        self.phrx_tcp(ip_packet_rx, ps_tcp.TcpPacket(ip_packet_rx))
        return
