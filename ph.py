#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# ph.py - protocol support for incoming and outgoing packets
#


import random
import threading
import time
from ipaddress import IPv4Address, IPv4Interface, IPv6Address

import loguru

import ps_arp
import ps_dhcp
import ps_icmpv6
import stack
from ipv6_helper import ipv6_eui64, ipv6_multicast_mac, ipv6_solicited_node_multicast
from udp_metadata import UdpMetadata
from udp_socket import UdpSocket


class PacketHandler:
    """ Pick up and respond to incoming packets """

    from phrx_arp import phrx_arp
    from phrx_ether import phrx_ether
    from phrx_icmpv4 import phrx_icmpv4
    from phrx_icmpv6 import phrx_icmpv6
    from phrx_ipv4 import phrx_ipv4
    from phrx_ipv6 import phrx_ipv6
    from phrx_tcp import phrx_tcp
    from phrx_udp import phrx_udp
    from phtx_arp import phtx_arp
    from phtx_ether import phtx_ether
    from phtx_icmpv4 import phtx_icmpv4
    from phtx_icmpv6 import phtx_icmpv6
    from phtx_ipv4 import phtx_ipv4
    from phtx_ipv6 import phtx_ipv6
    from phtx_tcp import phtx_tcp
    from phtx_udp import phtx_udp

    def __init__(self):
        """ Class constructor """

        stack.packet_handler = self

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This is to accomodate IPv6 Solicited Node Multicast mechanism where multiple
        # IPv6 unicast addresses can be tied to the same SNM address (and the same multicast MAC). This is important when removing one of unicast addresses,
        # so the other ones keep it's SNM entry in multicast list. Its the simplest solution and imho perfectly valid one in this case.

        self.stack_mac_unicast = stack.mac_address_candidate
        self.stack_mac_multicast = []
        self.stack_mac_broadcast = ["ff:ff:ff:ff:ff:ff"]

        self.stack_ipv6_address_candidate = stack.ipv6_address_candidate
        self.stack_ipv6_address = []
        self.stack_ipv6_unicast = []
        self.stack_ipv6_multicast = []

        self.stack_ipv4_address_candidate = stack.ipv4_address_candidate
        self.stack_ipv4_address = []
        self.stack_ipv4_unicast = []
        self.stack_ipv4_multicast = []
        self.stack_ipv4_broadcast = [IPv4Address("255.255.255.255")]

        self.logger = loguru.logger.bind(object_name="packet_handler.")

        self.arp_probe_unicast_conflict = set()

        # Used for the ICMPv6 ND DAD process
        self.ipv6_unicast_candidate = None
        self.event_icmpv6_nd_dad = threading.Semaphore(0)
        self.icmpv6_nd_dad_tlla = None

        # Used for the IcMPv6 ND RA address auto configuration
        self.icmpv6_ra_prefixes = []
        self.event_icmpv6_ra = threading.Semaphore(0)

        # Used to keep IPv4 packet ID last value
        self.ipv4_packet_id = 0

        # Start packed handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        self.logger.debug("Started packet handler")

        if stack.ipv6_support:
            # Assign All IPv6 Nodes multicast address
            self.assign_ipv6_multicast(IPv6Address("ff02::1"))
            # Create list of IPv6 unicast/multicast addresses stack should listen on
            self.create_stack_ipv6_addresses()

        if stack.ipv4_support:
            # Create list of IPv4 unicast/multicast/broadcast addresses stack should listen on, use DHCP if enabled
            if stack.ipv4_address_dhcp_enabled:
                ipv4_address_dhcp, _ = self.__dhcp_client()
                if ipv4_address_dhcp:
                    self.stack_ipv4_address_candidate.append(ipv4_address_dhcp)
            self.create_stack_ipv4_addresses()

        # Log all the addresses stack will listen on
        self.logger.info(f"Stack listening on unicast MAC addresses: {self.stack_mac_unicast}")
        self.logger.info(f"Stack listening on multicast MAC addresses: {list(set(self.stack_mac_multicast))}")
        self.logger.info(f"Stack listening on brodcast MAC addresses: {self.stack_mac_broadcast}")

        if stack.ipv6_support:
            self.logger.info(f"Stack listening on unicast IPv6 addresses: {[str(_) for _ in self.stack_ipv6_unicast]}")
            self.logger.info(f"Stack listening on multicast IPv6 addresses: {list(set(str(_) for _ in self.stack_ipv6_multicast))}")

        if stack.ipv4_support:
            self.logger.info(f"Stack listening on unicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_unicast]}")
            self.logger.info(f"Stack listening on multicast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_multicast]}")
            self.logger.info(f"Stack listening on brodcast IPv4 addresses: {[str(_) for _ in self.stack_ipv4_broadcast]}")

    def __thread_packet_handler(self):
        """ Thread picks up incoming packets from RX ring and process them """

        while True:
            self.phrx_ether(stack.rx_ring.dequeue())

    def perform_ipv6_nd_dad(self, ipv6_unicast_candidate):
        """ Perform IPv6 ND Duplicate Address Detection, return True if passed """

        self.logger.debug(f"ICMPv6 ND DAD - Starting process for {ipv6_unicast_candidate}")
        self.assign_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast_candidate))
        self.ipv6_unicast_candidate = ipv6_unicast_candidate
        self.send_icmpv6_nd_dad_message(ipv6_unicast_candidate)
        if event := self.event_icmpv6_nd_dad.acquire(timeout=1):
            self.logger.warning(f"ICMPv6 ND DAD - Duplicate IPv6 address detected, {ipv6_unicast_candidate} advertised by {self.icmpv6_nd_dad_tlla}")
        else:
            self.logger.debug(f"ICMPv6 ND DAD - No duplicate address detected for {ipv6_unicast_candidate}")
        self.ipv6_unicast_candidate = None
        self.remove_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast_candidate))
        return not event

    def create_stack_ipv6_addresses(self):
        """ Create list of IPv6 addresses stack should listen on """

        # Check if there are any statically assigned link local addresses
        for ipv6_address_candidate in list(self.stack_ipv6_address_candidate):
            if (
                ipv6_address_candidate.ip.is_link_local
                and ipv6_address_candidate not in self.stack_ipv6_address
                and self.perform_ipv6_nd_dad(ipv6_address_candidate.ip)
            ):
                self.stack_ipv6_address_candidate.remove(ipv6_address_candidate)
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.assign_ipv6_unicast(ipv6_address_candidate.ip)

        # Check if we succeded in assigning any link local address, if not try to assign one automaticaly
        if not self.stack_ipv6_address:
            ipv6_address_candidate = ipv6_eui64(self.stack_mac_unicast[0])
            if self.perform_ipv6_nd_dad(ipv6_address_candidate.ip):
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.assign_ipv6_unicast(ipv6_address_candidate.ip)

        # If we still don't have any link local address set disable IPv6 protocol operations
        if not self.stack_ipv6_address:
            self.logger.warning("Unable to assign any IPv6 link local address, disabling IPv6 protocol")
            stack.ipv6_support = False
            return

        # Check if there are any other statically assigned addresses
        for ipv6_address_candidate in list(self.stack_ipv6_address_candidate):
            if (
                (ipv6_address_candidate.ip.is_global or ipv6_address_candidate.ip.is_private)
                and ipv6_address_candidate not in self.stack_ipv6_address
                and self.perform_ipv6_nd_dad(ipv6_address_candidate.ip)
            ):
                self.stack_ipv6_address_candidate.remove(ipv6_address_candidate)
                self.stack_ipv6_address.append(ipv6_address_candidate)
                self.assign_ipv6_unicast(ipv6_address_candidate.ip)

        # Send out IPv6 Router Solicitation message and wait for response in attempt to auto configure addresses based on ICMPv6 Router Advertisement
        if stack.ipv6_address_autoconfig_enabled:
            self.send_icmpv6_nd_router_solicitation()
            self.event_icmpv6_ra.acquire(timeout=1)
            for icmpv6_ra_prefix in list(self.icmpv6_ra_prefixes):
                self.logger.debug(f"Attempting IPv6 address auto configuration for RA prefix {icmpv6_ra_prefix}")
                ipv6_address_candidate = ipv6_eui64(self.stack_mac_unicast[0], icmpv6_ra_prefix)
                if self.perform_ipv6_nd_dad(ipv6_address_candidate.ip):
                    self.stack_ipv6_address.append(ipv6_address_candidate)
                    self.assign_ipv6_unicast(ipv6_address_candidate.ip)

    def create_stack_ipv4_addresses(self):
        """ Create list of IPv4 addresses stack should listen on """

        # Perform Duplicate Address Detection
        for _ in range(3):
            for ipv4_unicast in [_.ip for _ in self.stack_ipv4_address_candidate]:
                if ipv4_unicast not in self.arp_probe_unicast_conflict:
                    self.send_arp_probe(ipv4_unicast)
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

        # If don't have any IPv4 address assigned disable IPv4 protocol operations
        if not self.stack_ipv4_address:
            self.logger.warning("Unable to assign any IPv4 address, disabling IPv4 protocol")
            stack.ipv4_support = False
            return

        # Create list containing IP unicast adresses stack shuld listen to
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address.ip not in self.stack_ipv4_unicast:
                self.stack_ipv4_unicast.append(ipv4_address.ip)

        for ipv4_unicast in self.stack_ipv4_unicast:
            self.send_arp_announcement(ipv4_unicast)
            self.logger.debug(f"Succesfully claimed IP address {ipv4_unicast}")

        # Create list of all broadcast addresses stack should listen on
        for ipv4_address in self.stack_ipv4_address:
            if ipv4_address.network.broadcast_address not in self.stack_ipv4_broadcast:
                self.stack_ipv4_broadcast.append(ipv4_address.network.broadcast_address)

    def send_arp_probe(self, ipv4_unicast):
        """ Send out ARP probe to detect possible IP conflict """

        self.phtx_arp(
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa=IPv4Address("0.0.0.0"),
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_unicast,
        )
        self.logger.debug(f"Sent out ARP probe for {ipv4_unicast}")

    def send_arp_announcement(self, ipv4_unicast):
        """ Send out ARP announcement to claim IP address """

        self.phtx_arp(
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REQUEST,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa=ipv4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_unicast,
        )
        self.logger.debug(f"Sent out ARP Announcement for {ipv4_unicast}")

    def send_gratitous_arp(self, ipv4_unicast):
        """ Send out gratitous arp """

        self.phtx_arp(
            ether_src=self.stack_mac_unicast[0],
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=ps_arp.ARP_OP_REPLY,
            arp_sha=self.stack_mac_unicast[0],
            arp_spa=ipv4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ipv4_unicast,
        )
        self.logger.debug(f"Sent out Gratitous ARP for {ipv4_unicast}")

    def send_icmpv6_multicast_listener_report(self):
        """ Send out ICMPv6 Multicast Listener Report for given list of addresses """

        # Need to use set here to avoid re-using duplicate multicast entries from stack_ipv6_multicast list,
        # also All Multicast Nodes address is not being advertised as this is not neccessary
        if icmpv6_mlr2_multicast_address_record := {
            ps_icmpv6.MulticastAddressRecord(record_type=ps_icmpv6.ICMP6_MART_CHANGE_TO_EXCLUDE, multicast_address=str(_))
            for _ in self.stack_ipv6_multicast
            if _ not in {IPv6Address("ff02::1")}
        }:
            self.phtx_icmpv6(
                ipv6_src=self.stack_ipv6_unicast[0] if self.stack_ipv6_unicast else IPv6Address("::"),
                ipv6_dst=IPv6Address("ff02::16"),
                ipv6_hop=1,
                icmpv6_type=ps_icmpv6.ICMP6_MULTICAST_LISTENER_REPORT_V2,
                icmpv6_mlr2_multicast_address_record=icmpv6_mlr2_multicast_address_record,
            )
            self.logger.debug(f"Sent out ICMPv6 Multicast Listener Report message for {[_.multicast_address for _ in icmpv6_mlr2_multicast_address_record]}")

    def send_icmpv6_nd_dad_message(self, ipv6_unicast_candidate):
        """ Send out ICMPv6 ND Duplicate Address Detection message """

        self.phtx_icmpv6(
            ipv6_src=IPv6Address("::"),
            ipv6_dst=ipv6_solicited_node_multicast(ipv6_unicast_candidate),
            ipv6_hop=255,
            icmpv6_type=ps_icmpv6.ICMP6_NEIGHBOR_SOLICITATION,
            icmpv6_ns_target_address=ipv6_unicast_candidate,
        )
        self.logger.debug(f"Sent out ICMPv6 ND DAD message for {ipv6_unicast_candidate}")

    def send_icmpv6_nd_router_solicitation(self):
        """ Send out ICMPv6 ND Router Solicitation """

        self.phtx_icmpv6(
            ipv6_src=self.stack_ipv6_unicast[0],
            ipv6_dst=IPv6Address("ff02::2"),
            ipv6_hop=255,
            icmpv6_type=ps_icmpv6.ICMP6_ROUTER_SOLICITATION,
            icmpv6_nd_options=[ps_icmpv6.ICMPv6NdOptSLLA(opt_slla=self.stack_mac_unicast[0])],
        )
        self.logger.debug("Sent out ICMPv6 ND Router Solicitation")

    def assign_ipv6_unicast(self, ipv6_unicast):
        """ Assign IPv6 unicast address to the list stack listens on """

        self.stack_ipv6_unicast.append(ipv6_unicast)
        self.logger.debug(f"Assigned IPv6 unicast {ipv6_unicast}")
        self.assign_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast))

    def remove_ipv6_unicast(self, ipv6_unicast):
        """ Remove IPv6 unicast address from the list stack listens on """

        self.stack_ipv6_unicast.remove(ipv6_unicast)
        self.logger.debug(f"Removed IPv6 unicast {ipv6_unicast}")
        self.remove_ipv6_multicast(ipv6_solicited_node_multicast(ipv6_unicast))

    def assign_ipv6_multicast(self, ipv6_multicast):
        """ Assign IPv6 multicast address to the list stack listens on """

        self.stack_ipv6_multicast.append(ipv6_multicast)
        self.logger.debug(f"Assigned IPv6 multicast {ipv6_multicast}")
        self.assign_mac_multicast(ipv6_multicast_mac(ipv6_multicast))

        # Send out the ICMPv6 Multicast Listener Report
        for _ in range(1):
            self.send_icmpv6_multicast_listener_report()

    def remove_ipv6_multicast(self, ipv6_multicast):
        """ Remove IPv6 multicast address from the list stack listens on """

        self.stack_ipv6_multicast.remove(ipv6_multicast)
        self.logger.debug(f"Removed IPv6 multicast {ipv6_multicast}")
        self.remove_mac_multicast(ipv6_multicast_mac(ipv6_multicast))

    def assign_mac_unicast(self, mac_unicast):
        """ Assign MAC unicast address to the list stack listens on """

        self.stack_mac_unicast.append(mac_unicast)
        self.logger.debug(f"Assigned MAC unicast {mac_unicast}")

    def remove_mac_unicast(self, mac_unicast):
        """ Remove MAC unicast address from the list stack listens on """

        self.stack_mac_unicast.remove(mac_unicast)
        self.logger.debug(f"Removed MAC unicast {mac_unicast}")

    def assign_mac_multicast(self, mac_multicast):
        """ Assign MAC multicast address to the list stack listens on """

        self.stack_mac_multicast.append(mac_multicast)
        self.logger.debug(f"Assigned MAC multicast {mac_multicast}")

    def remove_mac_multicast(self, mac_multicast):
        """ Remove MAC multicast address from the list stack listens on """

        self.stack_mac_multicast.remove(mac_multicast)
        self.logger.debug(f"Removed MAC multicast {mac_multicast}")

    def __dhcp_client(self):
        """ Obtain IPv4 address and default gateway using DHCP """

        def __send_dhcp_packet(dhcp_packet_tx):
            socket.send_to(
                UdpMetadata(
                    local_ip_address=IPv4Address("0.0.0.0"),
                    local_port=68,
                    remote_ip_address=IPv4Address("255.255.255.255"),
                    remote_port=67,
                    raw_data=dhcp_packet_tx.get_raw_packet(),
                )
            )

        socket = UdpSocket()
        socket.bind(local_ip_address="0.0.0.0", local_port=68)
        dhcp_xid = random.randint(0, 0xFFFFFFFF)

        # Send DHCP Discover
        __send_dhcp_packet(
            dhcp_packet_tx=ps_dhcp.DhcpPacket(
                dhcp_xid=dhcp_xid,
                dhcp_chaddr=self.stack_mac_unicast[0],
                dhcp_msg_type=ps_dhcp.DHCP_DISCOVER,
                dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                dhcp_host_name="PyTCP",
            )
        )
        self.logger.debug("Sent out DHCP Discover message")

        # Wait for DHCP Offer
        if not (packet := socket.receive_from(timeout=5)):
            self.logger.warning("Timeout waiting for DHCP Offer message")
            socket.close()
            return None, None

        dhcp_packet_rx = ps_dhcp.DhcpPacket(packet.raw_data)
        if dhcp_packet_rx.dhcp_msg_type != ps_dhcp.DHCP_OFFER:
            self.logger.warning("Didn't receive DHCP Offer message")
            socket.close()
            return None, None

        dhcp_srv_id = dhcp_packet_rx.dhcp_srv_id
        dhcp_yiaddr = dhcp_packet_rx.dhcp_yiaddr
        self.logger.debug(
            f"ClientUdpDhcp: Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
            + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
            + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
        )

        # Send DHCP Request
        __send_dhcp_packet(
            dhcp_packet_tx=ps_dhcp.DhcpPacket(
                dhcp_xid=dhcp_xid,
                dhcp_chaddr=self.stack_mac_unicast[0],
                dhcp_msg_type=ps_dhcp.DHCP_REQUEST,
                dhcp_srv_id=dhcp_srv_id,
                dhcp_req_ipv4_addr=dhcp_yiaddr,
                dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                dhcp_host_name="PyTCP",
            )
        )

        self.logger.debug(f"Sent out DHCP Request message to {dhcp_packet_rx.dhcp_srv_id}")

        # Wait for DHCP Ack
        if not (packet := socket.receive_from(timeout=5)):
            self.logger.warning("Timeout waiting for DHCP Ack message")
            return None, None

        dhcp_packet_rx = ps_dhcp.DhcpPacket(packet.raw_data)
        if dhcp_packet_rx.dhcp_msg_type != ps_dhcp.DHCP_ACK:
            self.logger.warning("Didn't receive DHCP Offer message")
            socket.close()
            return None, None

        self.logger.debug(
            f"Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
            + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
            + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
        )
        socket.close()
        return (
            IPv4Interface(str(dhcp_packet_rx.dhcp_yiaddr) + "/" + str(IPv4Address._make_netmask(str(dhcp_packet_rx.dhcp_subnet_mask))[1])),
            dhcp_packet_rx.dhcp_router[0],
        )
