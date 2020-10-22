#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack_ether.py - part of TCP/IP stack responsible for handling Ethernet packets

"""


import ph_ether
import ph_arp
import ph_ip


def ether_packet_handler(self, ether_packet_rx):
    """ Handle incoming Ethernet packets """

    self.logger.debug(f"{ether_packet_rx.serial_number_rx} - {ether_packet_rx}")

    if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_ARP:
        self.arp_packet_handler(ether_packet_rx, ph_arp.ArpPacket(ether_packet_rx))

    if ether_packet_rx.hdr_type == ph_ether.ETHER_TYPE_IP:
        self.ip_packet_handler(ether_packet_rx, ph_ip.IpPacket(ether_packet_rx))
