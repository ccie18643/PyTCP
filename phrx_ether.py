#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_ether.py - packet handler for inbound Ethernet packets

"""


import ps_ether
import ps_arp
import ps_ip


def phrx_ether(self, ether_packet_rx):
    """ Handle inbound Ethernet packets """

    self.logger.debug(f"{ether_packet_rx.tracker} - {ether_packet_rx}")

    if ether_packet_rx.hdr_type == ps_ether.ETHER_TYPE_ARP:
        self.phrx_arp(ether_packet_rx, ps_arp.ArpPacket(ether_packet_rx))

    if ether_packet_rx.hdr_type == ps_ether.ETHER_TYPE_IP:
        self.phrx_ip(ps_ip.IpPacket(ether_packet_rx))
