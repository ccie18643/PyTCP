#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ph.py - protocol support for incoming and outgoing packets

"""

import time
import loguru
import random
import socket
import struct
import threading

import ps_arp

import stack


class PacketHandler:
    """ Pick up and respond to incoming packets """

    from phrx_ether import phrx_ether
    from phrx_arp import phrx_arp
    from phrx_ipv4 import phrx_ipv4
    from phrx_icmp import phrx_icmp
    from phrx_udp import phrx_udp
    from phrx_tcp import phrx_tcp

    from phtx_ether import phtx_ether
    from phtx_arp import phtx_arp
    from phtx_ipv4 import phtx_ipv4
    from phtx_icmp import phtx_icmp
    from phtx_udp import phtx_udp
    from phtx_tcp import phtx_tcp

    def __init__(self, stack_mac_address, stack_ipv4_address):
        """ Class constructor """

        self.stack_mac_address = stack_mac_address
        self.stack_ipv4_unicast_candidate = {_[0] for _ in stack_ipv4_address}
        self.stack_ipv4_address = []
        self.stack_ipv4_unicast = []
        self.stack_ipv4_multicast = []
        self.stack_ipv4_network = []
        self.stack_ipv4_broadcast = ["255.255.255.255"]
        self.logger = loguru.logger.bind(object_name="packet_handler.")

        self.arp_probe_unicast_conflict = set()

        self.ipv4_packet_id = 0

        # Start packed handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        self.logger.debug("Started packet handler")

        # If no stack IP address provided try to obtain it via DHCP
        if not stack_ipv4_address:
            self.__dhcp_client()

        # Create list of IP addresses stack should listen on
        self.__validate_stack_ipv4_addresses(stack_ipv4_address)
        self.logger.info(f"Stack listening on unicast IP addresses: {self.stack_ipv4_unicast}")
        self.logger.info(f"Stack listening on multicast IP addresses: {self.stack_ipv4_multicast}")
        self.logger.info(f"Stack listening on brodcast IP addresses: {self.stack_ipv4_broadcast}")
        self.logger.info(f"Stack ignoring network IP addresses: {self.stack_ipv4_network}")

    def __dhcp_client(self):
        """ Acquire IP address using DHCP client """
        pass

    def __validate_stack_ipv4_addresses(self, stack_ipv4_address):
        """ Create list of IP addresses stack should listen on """

        # Create list of all IP unicast addresses stack should listen on
        for i in range(3):
            for ipv4_unicast in self.stack_ipv4_unicast_candidate:
                if ipv4_unicast not in self.arp_probe_unicast_conflict:
                    self.__send_arp_probe(ipv4_unicast)
                    self.logger.debug(f"Sent out ARP Probe for {ipv4_unicast}")
            time.sleep(random.uniform(1, 2))

        for ipv4_unicast in self.arp_probe_unicast_conflict:
            self.logger.warning(f"Unable to claim IP address {ipv4_unicast}")

        # Compute network and broadcast address for every ip address / mask tuple provided in configuration
        for i, ipv4_address in enumerate(stack_ipv4_address):
            _1 = struct.unpack("!L", socket.inet_aton(ipv4_address[0]))[0]
            _2 = struct.unpack("!L", socket.inet_aton(ipv4_address[1]))[0]
            stack_ipv4_address[i] = (
                ipv4_address[0],
                ipv4_address[1],
                socket.inet_ntoa(struct.pack("!L", _1 & _2)),
                socket.inet_ntoa(struct.pack("!L", (_1 & _2) + (~_2 & 0xFFFFFFFF))),
                ipv4_address[2],
            )

        # Create list containing only ip addresses that were confiremed free to claim
        for ipv4_address in stack_ipv4_address:
            if ipv4_address[0] not in self.arp_probe_unicast_conflict and ipv4_address not in self.stack_ipv4_address:
                self.stack_ipv4_address.append(ipv4_address)

        # Clear ip unicast candidate list so the ARP Probe/Annoucement check is disabled
        self.stack_ipv4_unicast_candidate = []

        # Create list containing IP unicast adresses stack shuld listen to
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address[0] not in self.stack_ipv4_unicast:
                self.stack_ipv4_unicast.append(ipv4_address[0])

        for ipv4_unicast in self.stack_ipv4_unicast:
            self.__send_arp_announcement(ipv4_unicast)
            self.logger.debug(f"Succesfully claimed IP address {ipv4_unicast}")

        # Create list of all broadcast addresses stack should listen on
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address[3] not in self.stack_ipv4_broadcast:
                self.stack_ipv4_broadcast.append(ipv4_address[3])

        # Create list of all netwok addresses stack should ignore
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address[2] not in self.stack_ipv4_network:
                self.stack_ipv4_network.append(ipv4_address[2])

    def __send_arp_probe(self, ipv4_address):
        """ Send out ARP probe to detect possible IP conflict """

        self.phtx_arp(
            ether_src=self.stack_mac_address,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_address,
            arp_spa="0.0.0.0",
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __send_arp_announcement(self, ipv4_address):
        """ Send out ARP announcement to claim IP address """

        self.phtx_arp(
            ether_src=self.stack_mac_address,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_address,
            arp_spa=ipv4_address,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __send_gratitous_arp(self, ipv4_address):
        """ Send out gratitous arp """

        self.phtx_arp(
            ether_src=self.stack_mac_address,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REPLY,
            arp_sha=self.stack_mac_address,
            arp_spa=ipv4_address,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __thread_packet_handler(self):
        """ Thread picks up incoming packets from RX ring and process them """

        while True:
            self.phrx_ether(stack.rx_ring.dequeue())
