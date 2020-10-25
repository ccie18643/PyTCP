#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
phrx_arp.py - packet handler for inbound ARP packets

"""

import ps_arp


ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST = False
ARP_CACHE_UPDATE_FROM_NON_DIRECT_REQUEST = False
ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP = True


def phrx_arp(self, ether_packet_rx, arp_packet_rx):
    """ Handle inbound ARP packets """

    if arp_packet_rx.arp_oper == ps_arp.ARP_OP_REQUEST:
        self.logger.opt(ansi=True).info(f"<green>{arp_packet_rx.tracker}</green> - {arp_packet_rx}")

        # Check if the request is for our IP address, if so the craft ARP reply packet and send it out
        if arp_packet_rx.arp_tpa == self.stack_ip_address:
            self.phtx_arp(
                ether_src=self.stack_mac_address,
                ether_dst=arp_packet_rx.arp_sha,
                arp_oper=ps_arp.ARP_OP_REPLY,
                arp_sha=self.stack_mac_address,
                arp_spa=self.stack_ip_address,
                arp_tha=arp_packet_rx.arp_sha,
                arp_tpa=arp_packet_rx.arp_spa,
                echo_tracker=arp_packet_rx.tracker,
            )

            # Update ARP cache with the maping learned from the received ARP request that was destined to this stack
            if ARP_CACHE_UPDATE_FROM_DIRECT_REQUEST:
                self.logger.debug(f"Adding/refreshing ARP cache entry from direct request - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
                self.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)

        elif ARP_CACHE_UPDATE_FROM_NON_DIRECT_REQUEST:
            self.logger.debug(f"Adding/refreshing ARP cache entry from non-direct request - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
            self.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)

    # Handle ARP reply
    elif arp_packet_rx.arp_oper == ps_arp.ARP_OP_REPLY:
        self.logger.opt(ansi=True).info(f"<green>{arp_packet_rx.tracker}</green> - {arp_packet_rx}")

        # Update ARP cache with maping received as direct ARP reply
        if ether_packet_rx.ether_dst == self.stack_mac_address:
            self.logger.debug(f"Adding/refreshing ARP cache entry from direct reply - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
            self.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)

        # Update ARP cache with maping received as gratitious ARP reply
        if ether_packet_rx.ether_dst == "ff:ff:ff:ff:ff:ff" and ARP_CACHE_UPDATE_FROM_GRATITIOUS_ARP:
            self.logger.debug(f"Adding/refreshing ARP cache entry from gratitious reply - {arp_packet_rx.arp_spa} -> {arp_packet_rx.arp_sha}")
            self.arp_cache.add_entry(arp_packet_rx.arp_spa, arp_packet_rx.arp_sha)
