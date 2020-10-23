#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ps_rx.py - protocol support for RX taffic

"""

import loguru
import threading


class PacketHandlerRx:
    """ Pick up and respond to incoming packets """

    from ps_ether_rx import ether_packet_handler
    from ps_arp_rx import arp_packet_handler
    from ps_ip_rx import ip_packet_handler
    from ps_icmp_rx import icmp_packet_handler
    from ps_udp_rx import udp_packet_handler
    from ps_tcp_rx import tcp_packet_handler

    def __init__(self, stack_mac_address, ps_ip_rx_address, rx_ring, tx_ring, arp_cache):
        """ Class constructor """

        self.ps_ip_rx_address = ps_ip_rx_address
        self.stack_mac_address = stack_mac_address
        self.tx_ring = tx_ring
        self.rx_ring = rx_ring
        self.arp_cache = arp_cache
        self.logger = loguru.logger.bind(object_name="packet_handler.")

        threading.Thread(target=self.__packet_handler).start()
        self.logger.debug("Started packet handler")

    def __packet_handler(self):
        """ Thread that picks up incoming packets from RX ring and process them """

        while True:
            self.ether_packet_handler(self.rx_ring.dequeue())
