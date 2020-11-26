#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_arp.py - packet handler for outbound ARP packets

"""

import ps_arp


def phtx_arp(self, ether_src, ether_dst, arp_oper, arp_sha, arp_spa, arp_tha, arp_tpa, echo_tracker=None):
    """ Handle outbound ARP packets """

    # Check if IPv4 protocol support is enabled, if not then silently drop the packet
    if not self.stack_ipv4_support:
        return

    arp_packet_tx = ps_arp.ArpPacket(
        arp_oper=arp_oper,
        arp_sha=arp_sha,
        arp_spa=arp_spa,
        arp_tha=arp_tha,
        arp_tpa=arp_tpa,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{arp_packet_tx.tracker}</magenta> - {arp_packet_tx}")

    self.phtx_ether(ether_src=ether_src, ether_dst=ether_dst, child_packet=arp_packet_tx)
