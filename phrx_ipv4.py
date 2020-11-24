#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_ipv4.py - packet handler for inbound IPv4 packets

"""

import ps_ipv4
import ps_icmpv4
import ps_udp
import ps_tcp

import inet_cksum


ipv4_fragments = {}


def handle_ipv4_fragmentation(self, ipv4_packet_rx):
    """ Check if packet is fragmented """

    # Check if IP packet is a first fragment
    if ipv4_packet_rx.ipv4_frag_offset == 0 and ipv4_packet_rx.ipv4_frag_mf:
        ipv4_fragments[ipv4_packet_rx.ipv4_packet_id] = {}
        ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data
        return

    # Check if IP packet is one of middle fragments
    if ipv4_packet_rx.ipv4_frag_offset != 0 and ipv4_packet_rx.ipv4_frag_mf:
        # Check if packet is part of existing fagment flow
        if ipv4_fragments.get(ipv4_packet_rx.ipv4_packet_id, None):
            ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data
        return

    # Check if IP packet is last fragment
    if ipv4_packet_rx.ipv4_frag_offset != 0 and not ipv4_packet_rx.ipv4_frag_mf:

        # Check if packet is part of existing fagment flow
        if ipv4_fragments.get(ipv4_packet_rx.ipv4_packet_id, None):
            ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][ipv4_packet_rx.ipv4_frag_offset] = ipv4_packet_rx.raw_data

            raw_data = b""
            for offset in sorted(ipv4_fragments[ipv4_packet_rx.ipv4_packet_id]):
                raw_data += ipv4_fragments[ipv4_packet_rx.ipv4_packet_id][offset]

            # Craft complete IP packet based on last fragment for further processing
            ipv4_packet_rx.ipv4_frag_mf = False
            ipv4_packet_rx.ipv4_frag_offset = 0
            ipv4_packet_rx.ipv4_plen = ipv4_packet_rx.ipv4_hlen + len(raw_data)
            ipv4_packet_rx.ipv4_cksum = 0
            ipv4_packet_rx.ipv4_cksum = inet_cksum.compute_cksum(ipv4_packet_rx.raw_header)
            ipv4_packet_rx.raw_data = raw_data

    return ipv4_packet_rx


def phrx_ipv4(self, ipv4_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ipv4_packet_rx.tracker} - {ipv4_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast/broadcast
    if (
        ipv4_packet_rx.ipv4_dst not in self.stack_ipv4_unicast
        and ipv4_packet_rx.ipv4_dst not in self.stack_ipv4_multicast
        and ipv4_packet_rx.ipv4_dst not in self.stack_ipv4_broadcast
    ):
        self.logger.debug(f"{ipv4_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    # Validate IP header checksum
    if not ipv4_packet_rx.validate_cksum():
        self.logger.debug(f"{ipv4_packet_rx.tracker} - IP packet has invalid checksum, droping")
        return

    # Check if packet is a fragment, and if so process it accrdingly
    ipv4_packet_rx = handle_ipv4_fragmentation(self, ipv4_packet_rx)
    if not ipv4_packet_rx:
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_ICMPv4:
        self.phrx_icmpv4(ipv4_packet_rx, ps_icmpv4.ICMPv4Packet(ipv4_packet_rx))
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_UDP:
        self.phrx_udp(ipv4_packet_rx, ps_udp.UdpPacket(ipv4_packet_rx))
        return

    if ipv4_packet_rx.ipv4_proto == ps_ipv4.IPV4_PROTO_TCP:
        self.phrx_tcp(ipv4_packet_rx, ps_tcp.TcpPacket(ipv4_packet_rx))
        return
