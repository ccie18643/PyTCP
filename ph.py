#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ph.py - protocol support for incoming and outgoing packets

"""

import re
import time
import loguru
import random
import threading

from ipaddress import IPv4Address, IPv6Address, IPv6Interface

import ps_arp
import stack


class PacketHandler:
    """ Pick up and respond to incoming packets """

    from phrx_ether import phrx_ether
    from phrx_arp import phrx_arp
    from phrx_ipv4 import phrx_ipv4
    from phrx_ipv6 import phrx_ipv6
    from phrx_icmpv4 import phrx_icmpv4

    from phrx_icmpv6 import phrx_icmpv6
    from phrx_udp import phrx_udp
    from phrx_tcp import phrx_tcp

    from phtx_ether import phtx_ether
    from phtx_arp import phtx_arp
    from phtx_ipv4 import phtx_ipv4
    from phtx_ipv6 import phtx_ipv6
    from phtx_icmpv4 import phtx_icmpv4

    from phtx_icmpv6 import phtx_icmpv6
    from phtx_udp import phtx_udp
    from phtx_tcp import phtx_tcp

    def __init__(self, stack_mac_address, stack_ipv4_address_candidate):
        """ Class constructor """

        self.stack_ipv4_address_candidate = stack_ipv4_address_candidate
        self.stack_mac_address = stack_mac_address
        self.stack_ipv4_address = []
        self.stack_ipv4_unicast = []
        self.stack_ipv4_multicast = []
        self.stack_ipv4_network = []
        self.stack_ipv4_broadcast = [IPv4Address("255.255.255.255")]
        self.logger = loguru.logger.bind(object_name="packet_handler.")

        self.arp_probe_unicast_conflict = set()

        self.ipv4_packet_id = 0

        # Create list of MAC addresses stack should listen on
        self.stack_mac_unicast = [stack_mac_address]
        self.stack_mac_multicast = []
        self.stack_mac_broadcast = ["ff:ff:ff:ff:ff:ff"]

        # Start packed handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        self.logger.debug("Started packet handler")

        # Create IPv6 link local address
        self.stack_ipv6_address = [self.__ipv6_eui64(stack_mac_address)]

        # Create list of IPv6 unicast addresses stack should listen on
        self.stack_ipv6_unicast = [_.ip for _ in self.stack_ipv6_address]

        # Create list of IPv6 multicast addresses stack should listen on, also update the stack MAC multicast list
        self.stack_ipv6_multicast = [self.ipv6_solicited_node_multicast(_) for _ in self.stack_ipv6_unicast]
        self.stack_ipv6_multicast.append(IPv6Address("ff02::1"))
        self.stack_mac_multicast = [self.ipv6_multicast_mac(_) for _ in self.stack_ipv6_multicast]

        # Create list of IPv4 unicast/multicast/broadcast addresses stack should listen on
        self.__validate_stack_ipv4_addresses()

        print("DUPA")
        self.phtx_icmpv6(
            ipv6_src=self.stack_ipv6_unicast[0], ipv6_dst=IPv6Address("ff02::2"), icmpv6_type=133, icmpv6_source_link_layer_address=self.stack_mac_unicast[0]
        )
        print("PIPA")

        # Log all the addresses stack will listen on
        self.logger.info(f"Stack listening on unicast MAC addresses: {self.stack_mac_unicast}")
        self.logger.info(f"Stack listening on multicast MAC addresses: {self.stack_mac_multicast}")
        self.logger.info(f"Stack listening on brodcast MAC addresses: {self.stack_mac_broadcast}")
        self.logger.info(f"Stack listening on unicast IPv6 addresses: {[str(_) for _ in self.stack_ipv6_unicast]}")
        self.logger.info(f"Stack listening on multicast IPv6 addresses: {[str(_) for _ in self.stack_ipv6_multicast]}")
        self.logger.info(f"Stack listening on unicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_unicast]}")
        self.logger.info(f"Stack listening on multicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_multicast]}")
        self.logger.info(f"Stack listening on brodcast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_broadcast]}")

    def __dhcp_client(self):
        """ Acquire IP address using DHCP client """
        pass

    def __validate_stack_ipv4_addresses(self):
        """ Create list of IP addresses stack should listen on """

        # Create list of all IP unicast addresses stack should listen on
        for i in range(3):
            for ipv4_unicast in [_.ip for _ in self.stack_ipv4_address_candidate]:
                if ipv4_unicast not in self.arp_probe_unicast_conflict:
                    self.__send_arp_probe(ipv4_unicast)
                    self.logger.debug(f"Sent out ARP Probe for {ipv4_unicast}")
            time.sleep(random.uniform(1, 2))

        for ipv4_unicast in self.arp_probe_unicast_conflict:
            self.logger.warning(f"Unable to claim IP address {ipv4_unicast}")

        # Create list containing only ip addresses that were confiremed free to claim
        for ipv4_address in self.stack_ipv4_address_candidate:
            if ipv4_address.ip not in self.arp_probe_unicast_conflict and ipv4_address not in self.stack_ipv4_address:
                self.stack_ipv4_address.append(ipv4_address)

        # Clear IPv4 address candidate list so the ARP Probe/Annoucement check is disabled
        self.stack_ipv4_address_candidate = []

        # Create list containing IP unicast adresses stack shuld listen to
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address.ip not in self.stack_ipv4_unicast:
                self.stack_ipv4_unicast.append(ipv4_address.ip)

        for ipv4_unicast in self.stack_ipv4_unicast:
            self.__send_arp_announcement(ipv4_unicast)
            self.logger.debug(f"Succesfully claimed IP address {ipv4_unicast}")

        # Create list of all broadcast addresses stack should listen on
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address.network.broadcast_address not in self.stack_ipv4_broadcast:
                self.stack_ipv4_broadcast.append(ipv4_address.network.broadcast_address)

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

    def __ipv6_eui64(self, mac, prefix="ff80::"):
        """ Create IPv6 EUI64 address """

        eui64 = re.sub(r"[.:-]", "", mac).lower()
        eui64 = eui64[0:6] + "fffe" + eui64[6:]
        eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
        eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
        return IPv6Interface(prefix + eui64 + "/64")

    def ipv6_solicited_node_multicast(self, ipv6_address):
        """ Create IPv6 solicited node multicast address """

        return IPv6Address("ff02::1:ff" + ipv6_address.exploded[-7:])

    def ipv6_multicast_mac(self, ipv6_multicast_address):
        """ Create IPv6 multicast MAC address """

        return "33:33:" + ":".join(["".join(ipv6_multicast_address.exploded[-9:].split(":"))[_ : _ + 2] for _ in range(0, 8, 2)])
