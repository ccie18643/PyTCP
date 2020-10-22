#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack_arp.py - part of TCP/IP stack responsible for handling ARP incoming packets

"""

import ph_ether
import ph_arp


def arp_packet_handler(self, ether_packet_rx, arp_packet_rx):
    """ Handle incomming ARP packets """

    if arp_packet_rx.hdr_oper == ph_arp.ARP_OP_REQUEST:
        self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
        if arp_packet_rx.hdr_tpa == self.stack_ip_address:

            arp_packet_tx = ph_arp.ArpPacket(
                hdr_oper=ph_arp.ARP_OP_REPLY,
                hdr_sha=self.stack_mac_address,
                hdr_spa=self.stack_ip_address,
                hdr_tha=arp_packet_rx.hdr_sha,
                hdr_tpa=arp_packet_rx.hdr_spa,
            )
            ether_packet_tx = ph_ether.EtherPacket(hdr_src=self.stack_mac_address, hdr_dst=arp_packet_tx.hdr_tha, child_packet=arp_packet_tx)

            # Pass the timestamp/serial info from request to reply packet for tracking in TX ring
            ether_packet_tx.timestamp_rx = ether_packet_rx.timestamp_rx
            ether_packet_tx.serial_number_rx = ether_packet_rx.serial_number_rx

            self.logger.debug(f"{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx}) - {ether_packet_tx}")
            self.logger.opt(ansi=True).info(f"<magenta>{ether_packet_tx.serial_number_tx} ({ether_packet_tx.serial_number_rx})</magenta> - {arp_packet_tx}")
            self.tx_ring.enqueue(ether_packet_tx)

            # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
            if self.arp_cache_update_from_direct_request:
                self.logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
                self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

    # Handle ARP reply
    elif arp_packet_rx.hdr_oper == ph_arp.ARP_OP_REPLY:
        self.logger.opt(ansi=True).info(f"<green>{ether_packet_rx.serial_number_rx}</green> - {arp_packet_rx}")

        # Update ARP cache with maping received as direct ARP reply
        if ether_packet_rx.hdr_dst == self.stack_mac_address:
            self.logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)

        # Update ARP cache with maping received as gratitious ARP reply
        if ether_packet_rx.hdr_dst == "ff:ff:ff:ff:ff:ff" and self.arp_cache_update_from_gratitious_arp:
            self.logger.debug(f"Adding/refreshing ARP cache entry from gratitious reply - {arp_packet_rx.hdr_spa} -> {arp_packet_rx.hdr_sha}")
            self.arp_cache.add_entry(arp_packet_rx.hdr_spa, arp_packet_rx.hdr_sha)
