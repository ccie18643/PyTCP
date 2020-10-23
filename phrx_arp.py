#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_arp.py - protocol support for incoming ARP packets

"""

import ps_ether
import ps_arp


ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = True
ARP_CACHE_UPDATE_FROM_NON_DIRECT_REQUEST = False
ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP = True


def phrx_arp(self, ether_packet_rx, arp_packet_rx):
    """ Handle incomming ARP packets """

    if arp_packet_rx.hdr_oper == ps_arp.ARP_OP_REQUEST:
        self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
        if arp_packet_rx.hdr_tpa == self.ps_ip_rx_address:

            arp_packet_tx = ps_arp.ArpPacket(
                hdr_oper=ps_arp.ARP_OP_REPLY,
                hdr_sha=self.stack_mac_address,
                hdr_spa=self.ps_ip_rx_address,
                hdr_tha=arp_packet_rx.hdr_sha,
                hdr_tpa=arp_packet_rx.hdr_spa,
            )
            ether_packet_tx = ps_ether.EtherPacket(hdr_src=self.stack_mac_address, hdr_dst=arp_packet_tx.hdr_tha, child_packet=arp_packet_tx)

            # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
            ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
            ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

            self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
            self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {arp_packet_tx}")
            self.tx_ring.enqueue(ether_packet_tx)

            # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
            if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                self.logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

        elif ARP_CACHE_UPDATE_FROM_NON_DIRECT_REQUEST:
            self.logger.debug(f"Adding/refreshing ARP cache entry from non-direct request - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

    # Handle ARP reply
    elif arp_packet_rx.hdr_oper == ps_arp.ARP_OP_REPLY:
        self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Update ARP cache with maping received as direct ARP reply
        if ether_packet_rx.hdr_dst == self.stack_mac_address:
            self.logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

        # Update ARP cache with maping received as gratitious ARP reply
        if ether_packet_rx.hdr_dst == "ff:ff:ff:ff:ff:ff" and ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP:
            self.logger.debug(f"Adding/refreshing ARP cache entry from gratitious reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)
