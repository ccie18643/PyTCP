#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phrx_ipv6.py - packet handler for inbound IPv6 packets

"""

import ps_ipv6

# import ps_icmpv6
import ps_udp
import ps_tcp


def phrx_ipv6(self, ipv6_packet_rx):
    """ Handle inbound IP packets """

    self.logger.debug(f"{ipv6_packet_rx.tracker} - {ipv6_packet_rx}")

    # Check if received packet has been sent to us directly or by unicast or multicast
    if ipv6_packet_rx.ipv6_dst not in self.stack_ipv6_unicast:
        self.logger.debug(f"{ipv4_packet_rx.tracker} - IP packet not destined for this stack, droping")
        return

    # if ipv6_packet_rx.ipv6_next == ps_ipv6.IPV6_NEXT_HEADER_ICMPV6:
    #    self.phrx_icmpv6(ipv6_packet_rx, ps_icmpv6.ICMPv6Packet(ipv6_packet_rx))
    #    return

    if ipv6_packet_rx.ipv6_proto == ps_ipv6.IPV6_NEXT_HEADER_UDP:
        self.phrx_udp(ipv6_packet_rx, ps_udp.UdpPacket(ipv6_packet_rx))
        return

    if ipv6_packet_rx.ipv6_proto == ps_ipv6.IPV6_NEXT_HEADER_TCP:
        self.phrx_tcp(ipv6_packet_rx, ps_tcp.TcpPacket(ipv6_packet_rx))
        return
