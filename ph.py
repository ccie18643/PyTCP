#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ph.py - protocol support for incoming and outgoing packets

"""

import time
import loguru
import random
import threading

from ipaddress import IPv4Address, IPv6Address

import ps_icmpv6
import ps_arp
import stack

from ipv6_helper import ipv6_eui64, ipv6_multicast_mac, ipv6_solicited_node_multicast


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

    def __init__(self, stack_mac_address, stack_ipv6_support=True, stack_ipv6_address_candidate=[], stack_ipv4_support=True, stack_ipv4_address_candidate=[]):
        """ Class constructor """

        self.stack_ipv6_support = stack_ipv6_support
        self.stack_ipv4_support = stack_ipv4_support

        self.stack_mac_unicast = [stack_mac_address]
        self.stack_mac_multicast = []
        self.stack_mac_broadcast = ["ff:ff:ff:ff:ff:ff"]

        self.stack_ipv6_address_candidate = stack_ipv6_address_candidate
        self.stack_ipv6_address = []
        self.stack_ipv6_unicast = []
        self.stack_ipv6_multicast = []

        self.stack_ipv4_address_candidate = stack_ipv4_address_candidate
        self.stack_ipv4_address = []
        self.stack_ipv4_unicast = []
        self.stack_ipv4_multicast = []
        self.stack_ipv4_broadcast = [IPv4Address("255.255.255.255")]

        self.logger = loguru.logger.bind(object_name="packet_handler.")

        self.arp_probe_unicast_conflict = set()

        # Used for the ICMPv6 ND DAT process
        self.ipv6_unicast_candidate = None
        self.event_icmpv6_nd_dad = threading.Semaphore(0)
        self.icmpv6_nd_dad_tlla = None

        # Used to keep IPv4 packet ID last value
        self.ipv4_packet_id = 0

        # Start packed handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        self.logger.debug("Started packet handler")

        if self.stack_ipv6_support:
            # Assign All IPv6 Nodes multicast address
            self.__assign_ipv6_multicast(IPv6Address("ff02::1"))
            # Create list of IPv6 unicast/multicast addresses stack should listen on
            self.__create_stack_ipv6_addresses()

        if self.stack_ipv4_support:
            # Create list of IPv4 unicast/multicast/broadcast addresses stack should listen on
            self.__create_stack_ipv4_addresses()

        # Log all the addresses stack will listen on
        self.logger.info(f"Stack listening on unicast MAC addresses: {self.stack_mac_unicast}")
        self.logger.info(f"Stack listening on multicast MAC addresses: {self.stack_mac_multicast}")
        self.logger.info(f"Stack listening on brodcast MAC addresses: {self.stack_mac_broadcast}")

        if self.stack_ipv6_support:
            self.logger.info(f"Stack listening on unicast IPv6 addresses: {[str(_) for _ in self.stack_ipv6_unicast]}")
            self.logger.info(f"Stack listening on multicast IPv6 addresses: {[str(_) for _ in self.stack_ipv6_multicast]}")

        if self.stack_ipv4_support:
            self.logger.info(f"Stack listening on unicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_unicast]}")
            self.logger.info(f"Stack listening on multicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_multicast]}")
            self.logger.info(f"Stack listening on brodcast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_broadcast]}")

    def __perform_ipv6_nd_dad(self, ipv6_unicast_candidate):
        """ Perform IPv6 ND Duplicate Address Detection, return True if passed """

        self.logger.debug(f"ICMPv6 ND DAD - Starting process for {ipv6_unicast_candidate}")
        self.ipv6_unicast_candidate = ipv6_unicast_candidate
        self.__send_icmpv6_nd_dad_message(ipv6_unicast_candidate)
        if event := self.event_icmpv6_nd_dad.acquire(timeout=1):
            self.logger.warning(f"ICMPv6 ND DAD - Duplicate IPv6 address detected, {ipv6_unicast_candidate} advertised by {self.icmpv6_nd_dad_tlla}")
        else:
            self.logger.debug(f"ICMPv6 ND DAD - No duplicate address detected for {ipv6_unicast_candidate}")
        self.ipv6_unicast_candidate = None
        return not event

    def __create_stack_ipv6_addresses(self):
        """ Create list of IPv6 addresses stack should listen on """

        # Check if there are any statically assigned link local addresses
        for ipv6_address_candidate in list(self.stack_ipv6_address_candidate):
            if (
                ipv6_address_candidate.ip.is_link_local
                and ipv6_address_candidate not in self.stack_ipv6_address
                and self.__perform_ipv6_nd_dad(ipv6_address_candidate.ip)
            ):
                self.stack_ipv6_address_candidate.remove(ipv6_address_candidate)
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.__assign_ipv6_unicast(ipv6_address_candidate.ip)

        # Check if we succeded in assigning any link local address, if not try to assign one automaticaly
        if not self.stack_ipv6_address:
            ipv6_address_candidate = ipv6_eui64(self.stack_mac_unicast[0])
            if self.__perform_ipv6_nd_dad(ipv6_address_candidate.ip):
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.__assign_ipv6_unicast(ipv6_address_candidate.ip)

        # If we still don't have any link local address set disable IPv6 protocol operations
        if not self.stack_ipv6_address:
            self.logger.warning("Unable to assign any IPv6 link local address, disabling IPv6 protocol")
            self.stack_ipv6_support = False
            return

        # Check if there are any other statically assigned addresses
        for ipv6_address_candidate in list(self.stack_ipv6_address_candidate):
            if (
                (ipv6_address_candidate.ip.is_global or ipv6_address_candidate.ip.is_private)
                and ipv6_address_candidate not in self.stack_ipv6_address
                and self.__perform_ipv6_nd_dad(ipv6_address_candidate.ip)
            ):
                self.stack_ipv6_address_candidate.remove(ipv6_address_candidate)
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.__assign_ipv6_unicast(ipv6_address_candidate.ip)

    def __create_stack_ipv4_addresses(self):
        """ Create list of IPv4 addresses stack should listen on """

        # Perform Duplicate Address Detection
        for i in range(3):
            for ipv4_unicast in [_.ip for _ in self.stack_ipv4_address_candidate]:
                if ipv4_unicast not in self.arp_probe_unicast_conflict:
                    self.__send_arp_probe(ipv4_unicast)
                    self.logger.debug(f"Sent out ARP Probe for {ipv4_unicast}")
            time.sleep(random.uniform(1, 2))

        for ipv4_unicast in self.arp_probe_unicast_conflict:
            self.logger.warning(f"Unable to claim IPv4 address {ipv4_unicast}")

        # Create list containing only IPv4 addresses that were confiremed free to claim
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
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa="0.0.0.0",
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __send_arp_announcement(self, ipv4_address):
        """ Send out ARP announcement to claim IP address """

        self.phtx_arp(
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa=ipv4_address,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __send_gratitous_arp(self, ipv4_address):
        """ Send out gratitous arp """

        self.phtx_arp(
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REPLY,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa=ipv4_address,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_address,
        )

    def __thread_packet_handler(self):
        """ Thread picks up incoming packets from RX ring and process them """

        while True:
            self.phrx_ether(stack.rx_ring.dequeue())

    def __send_icmpv6_nd_dad_message(self, ipv6_unicast_candidate):
        """ Send out ICMPv6 ND Duplicate Address Detection message """

        self.phtx_icmpv6(
            ipv6_src=IPv6Address("::"),
            ipv6_dst=ipv6_solicited_node_multicast(ipv6_unicast_candidate),
            icmpv6_type=ps_icmpv6.ICMPV6_NEIGHBOR_SOLICITATION,
            icmpv6_nd_target_address=ipv6_unicast_candidate,
        )

    def __assign_ipv6_unicast(self, ipv6_unicast):
        """ Assign IPv6 unicast address to the list stack listens on """

        self.stack_ipv6_unicast.append(ipv6_unicast)
        self.logger.debug(f"Assigned IPv6 unicast {ipv6_unicast}")
        self.__assign_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast))

    def __remove_ipv6_unicast(self, ipv6_unicast):
        """ Remove IPv6 unicast address from the list stack listens on """

        self.stack_ipv6_unicast.remove(ipv6_unicast)
        self.logger.debug(f"Removed IPv6 unicast {ipv6_unicast}")
        self.__remove_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast))

    def __assign_ipv6_multicast(self, ipv6_multicast):
        """ Assign IPv6 multicast address to the list stack listens on """

        self.stack_ipv6_multicast.append(ipv6_multicast)
        self.logger.debug(f"Assigned IPv6 multicast {ipv6_multicast}")
        self.__assign_mac_multicast(ipv6_multicast_mac(ipv6_multicast))

    def __remove_ipv6_multicast(self, ipv6_multicast):
        """ Remove IPv6 multicast address from the list stack listens on """

        self.stack_ipv6_multicast.remove(ipv6_multicast)
        self.logger.debug(f"Removed IPv6 multicast {ipv6_multicast}")
        self.__remove_mac_multicast(ipv6_multicast_mac(ipv6_multicast))

    def __assign_mac_unicast(self, mac_unicast):
        """ Assign MAC unicast address to the list stack listens on """

        self.stack_mac_unicast.append(mac_unicast)
        self.logger.debug(f"Assigned MAC unicast {mac_unicast}")

    def __remove_mac_unicast(self, mac_unicast):
        """ Remove MAC unicast address from the list stack listens on """

        self.stack_mac_unicast.remove(mac_unicast)
        self.logger.debug(f"Removed MAC unicast {mac_unicast}")

    def __assign_mac_multicast(self, mac_multicast):
        """ Assign MAC multicast address to the list stack listens on """

        self.stack_mac_multicast.append(mac_multicast)
        self.logger.debug(f"Assigned MAC multicast {mac_multicast}")

    def __remove_mac_multicast(self, mac_multicast):
        """ Remove MAC multicast address from the list stack listens on """

        self.stack_mac_multicast.remove(mac_multicast)
        self.logger.debug(f"Removed MAC multicast {mac_multicast}")
