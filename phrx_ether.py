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

    # Check if received packet uses valid Ethernet II format
    if ether_packet_rx.ether_type < ps_ether.ETHER_TYPE_MIN:
        self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.tracker} - Packet doesn't comply with the Ethernet II standard, droping")
        return

    # Check if received packet has been sent to us directly or by broadcast
    if ether_packet_rx.ether_dst not in {self.stack_mac_address, "ff:ff:ff:ff:ff:ff"}:
        self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.tracker} - Ethernet packet not destined for this stack, droping")
        return

    if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP:
        self.phrx_arp(ether_packet_rx, ps_arp.ArpPacket(ether_packet_rx))

    if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_IP:
        self.phrx_ip(ps_ip.IpPacket(ether_packet_rx))
