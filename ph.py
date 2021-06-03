#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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
from ipaddress import AddressValueError

import loguru

import config
import fpa_arp
import fpa_icmp6
import ps_dhcp
import stack
from arp_cache import ArpCache
from icmp6_nd_cache import ICMPv6NdCache
from ipv4_address import IPv4Address, IPv4Interface
from ipv6_address import IPv6Address, IPv6Interface, IPv6Network
from rx_ring import RxRing
from tx_ring import TxRing
from udp_metadata import UdpMetadata
from udp_socket import UdpSocket


class PacketHandler:
    """Pick up and respond to incoming packets"""

    from phrx_arp import _phrx_arp
    from phrx_ether import _phrx_ether
    from phrx_icmp4 import _phrx_icmp4
    from phrx_icmp6 import _phrx_icmp6
    from phrx_ip4 import _phrx_ip4
    from phrx_ip6 import _phrx_ip6
    from phrx_ip6_ext_frag import _phrx_ip6_ext_frag
    from phrx_tcp import _phrx_tcp
    from phrx_udp import _phrx_udp
    from phtx_arp import _phtx_arp
    from phtx_ether import _phtx_ether
    from phtx_icmp4 import _phtx_icmp4
    from phtx_icmp6 import _phtx_icmp6
    from phtx_ip4 import _phtx_ip4
    from phtx_ip6 import _phtx_ip6
    from phtx_ip6_ext_frag import _phtx_ip6_ext_frag
    from phtx_tcp import _phtx_tcp
    from phtx_udp import _phtx_udp

    def __init__(self, tap):
        """Class constructor"""

        stack.packet_handler = self

        if __debug__:
            self._logger = loguru.logger.bind(object_name="packet_handler.")

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This is to accommodate IPv6 Solicited Node Multicast mechanism where multiple
        # IPv6 unicast addresses can be tied to the same SNM address (and the same multicast MAC). This is important when removing one of unicast addresses,
        # so the other ones keep it's SNM entry in multicast list. Its the simplest solution and imho perfectly valid one in this case.
        self.mac_unicast = config.mac_address
        self.mac_multicast = []
        self.mac_broadcast = "ff:ff:ff:ff:ff:ff"
        self.ip6_address = []
        self.ip6_multicast = []
        self.ip4_address = []
        self.ip4_multicast = []

        self.rx_ring = RxRing(tap)
        self.tx_ring = TxRing(tap)
        self.arp_cache = ArpCache(self)
        self.icmp6_nd_cache = ICMPv6NdCache(self)

        # Used for the ARP DAD process
        self.arp_probe_unicast_conflict = set()

        # Used for the ICMPv6 ND DAD process
        self.ip6_unicast_candidate = None
        self.event_icmp6_nd_dad = threading.Semaphore(0)
        self.icmp6_nd_dad_tlla = None

        # Used for the IcMPv6 ND RA address auto configuration
        self.icmp6_ra_prefixes = []
        self.event_icmp6_ra = threading.Semaphore(0)

        # Used to keep IPv4 and IPv6 packet ID last value
        self.ip4_id = 0
        self.ip6_id = 0

        # Used to defragment IPv4 and IPv6 packets
        self.ip4_frag_flows = {}
        self.ip6_frag_flows = {}

        # Start packed handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        if __debug__:
            self._logger.debug("Started packet handler")

        if config.ip6_support:
            # Assign All IPv6 Nodes multicast address
            self._assign_ip6_multicast(IPv6Address("ff02::1"))
            # Create list of IPv6 unicast/multicast addresses stack should listen on
            self.ip6_address_candidate = self._parse_stack_ip6_address_candidate(config.ip6_address_candidate)
            self._create_stack_ip6_addressing()

        if config.ip4_support:
            # Create list of IPv4 unicast/multicast/broadcast addresses stack should listen on, use DHCP if enabled
            ip4_address_dhcp = self._dhcp4_client()
            ip4_address_dhcp = [ip4_address_dhcp] if ip4_address_dhcp[0] else []
            self.ip4_address_candidate = self._parse_stack_ip4_address_candidate(config.ip4_address_candidate + ip4_address_dhcp)
            self._create_stack_ip4_addressing()

        # Log all the addresses stack will listen on
        if __debug__:
            self._logger.info(f"Stack listening on unicast MAC address: {self.mac_unicast}")
            self._logger.info(f"Stack listening on multicast MAC addresses: {list(set(self.mac_multicast))}")
            self._logger.info(f"Stack listening on broadcast MAC address: {self.mac_broadcast}")

        if config.ip6_support:
            if __debug__:
                self._logger.info(f"Stack listening on unicast IPv6 addresses: {[str(_) for _ in self.ip6_unicast]}")
                self._logger.info(f"Stack listening on multicast IPv6 addresses: {list(set(str(_) for _ in self.ip6_multicast))}")

        if config.ip4_support:
            if __debug__:
                self._logger.info(f"Stack listening on unicast IPv4 addresses: {[str(_) for _ in self.ip4_unicast]}")
                self._logger.info(f"Stack listening on multicast IPv4 addresses: {[str(_) for _ in self.ip4_multicast]}")
                self._logger.info(f"Stack listening on broadcast IPv4 addresses: {[str(_) for _ in self.ip4_broadcast]}")

    def __thread_packet_handler(self):
        """Thread picks up incoming packets from RX ring and processes them"""

        while True:
            self._phrx_ether(self.rx_ring.dequeue())

    @property
    def ip6_unicast(self):
        """Return list of stack's IPv6 unicast addresses"""

        return [_.ip for _ in self.ip6_address]

    @property
    def ip4_unicast(self):
        """Return list of stack's IPv4 unicast addresses"""

        return [_.ip for _ in self.ip4_address]

    @property
    def ip4_broadcast(self):
        """Return list of stack's IPv4 broadcast addresses"""

        ip4_broadcast = [_.network.broadcast_address for _ in self.ip4_address]
        ip4_broadcast.append("255.255.255.255")
        return ip4_broadcast

    def _perform_ip6_nd_dad(self, ip6_unicast_candidate):
        """Perform IPv6 ND Duplicate Address Detection, return True if passed"""

        if __debug__:
            self._logger.debug(f"ICMPv6 ND DAD - Starting process for {ip6_unicast_candidate}")
        self._assign_ip6_multicast(ip6_unicast_candidate.solicited_node_multicast)
        self.ip6_unicast_candidate = ip6_unicast_candidate
        self._send_icmp6_nd_dad_message(ip6_unicast_candidate)
        if event := self.event_icmp6_nd_dad.acquire(timeout=1):
            if __debug__:
                self._logger.warning(f"ICMPv6 ND DAD - Duplicate IPv6 address detected, {ip6_unicast_candidate} advertised by {self.icmp6_nd_dad_tlla}")
        else:
            self._logger.debug(f"ICMPv6 ND DAD - No duplicate address detected for {ip6_unicast_candidate}")
        self.ip6_unicast_candidate = None
        self._remove_ip6_multicast(ip6_unicast_candidate.solicited_node_multicast)
        return not event

    def _parse_stack_ip6_address_candidate(self, configured_address_candidate):
        """Parse IPv6 candidate address list"""

        valid_address_candidate = []

        for address, gateway in configured_address_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{address}', '{gateway}') entry")
            try:
                address = IPv6Interface(address)
            except AddressValueError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address}' format, skipping...")
                return None
            if address.is_multicast or address.is_reserved or address.is_loopback or address.is_unspecified:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address.ip}' type, skipping...")
                return None
            if address.ip in [_.ip for _ in valid_address_candidate]:
                if __debug__:
                    self._logger.warning(f"Duplicate host address '{address.ip}' configured, skipping...")
                return None
            if gateway is not None:
                try:
                    gateway = IPv6Address(gateway)
                    if not (gateway.is_link_local or (gateway in address.network and gateway != address.ip)):
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for interface address '{address}', skipping...")
                        gateway = None
                except AddressValueError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{gateway}' format configured for interface address '{address}' skipping...")
                    gateway = None
            if address.is_link_local and gateway is not None:
                if __debug__:
                    self._logger.warning("Gateway cannot be configured for link local address skipping...")
                gateway = None
            address.gateway = gateway
            valid_address_candidate.append(address)
            if __debug__:
                self._logger.debug(f"Parsed ('{address}', '{address.gateway}') entry")

        return valid_address_candidate

    def _create_stack_ip6_addressing(self):
        """Create lists of IPv6 unicast and multicast addresses stack should listen on"""

        def __(ip6_address):
            if self._perform_ip6_nd_dad(ip6_address.ip):
                self._assign_ip6_address(ip6_address)
                if __debug__:
                    self._logger.debug(f"Successfully claimed IPv6 address {ip6_address}")
            else:
                if __debug__:
                    self._logger.warning(f"Unable to claim IPv6 address {ip6_address}")

        # Configure Link Local address(es) staticaly
        for ip6_address in list(self.ip6_address_candidate):
            if ip6_address.is_link_local:
                self.ip6_address_candidate.remove(ip6_address)
                __(ip6_address)

        # Configure Link Local address automatically
        if config.ip6_lla_autoconfig:
            ip6_address = IPv6Network("fe80::/64").eui64(self.mac_unicast)
            ip6_address.gateway = None
            __(ip6_address)

        # If we don't have any link local address set disable IPv6 protocol operations
        if not self.ip6_address:
            if __debug__:
                self._logger.warning("Unable to assign any IPv6 link local address, disabling IPv6 protocol")
            config.ip6_support = False
            return

        # Check if there are any statically configures GUA addresses
        for ip6_address in list(self.ip6_address_candidate):
            self.ip6_address_candidate.remove(ip6_address)
            __(ip6_address)

        # Send out IPv6 Router Solicitation message and wait for response in attempt to auto configure addresses based on ICMPv6 Router Advertisement
        if config.ip6_gua_autoconfig:
            self._send_icmp6_nd_router_solicitation()
            self.event_icmp6_ra.acquire(timeout=1)
            for prefix, gateway in list(self.icmp6_ra_prefixes):
                if __debug__:
                    self._logger.debug(f"Attempting IPv6 address auto configuration for RA prefix {prefix}")
                ip6_address = prefix.eui64(self.mac_unicast)
                ip6_address.gateway = gateway
                __(ip6_address)

    def _parse_stack_ip4_address_candidate(self, configured_ip4_address_candidate):
        """Parse IPv4 candidate addresses configured in stack.py module"""

        valid_address_candidate = []

        for address, gateway in configured_ip4_address_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{address}', '{gateway}') entry")
            try:
                address = IPv4Interface(address)
            except AddressValueError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address}' format, skipping...")
                continue
            if address.is_multicast or address.is_reserved or address.is_loopback or address.is_unspecified:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address.ip}' type, skipping...")
                continue
            if address.ip == address.network_address or address.ip == address.broadcast_address:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address.ip}' configured for network '{address.network}', skipping...")
                continue
            if address.ip in [_.ip for _ in valid_address_candidate]:
                if __debug__:
                    self._logger.warning(f"Duplicate host address '{address.ip}' configured, skipping...")
                continue
            if gateway is not None:
                try:
                    gateway = IPv4Address(gateway)
                    if gateway not in address.network or gateway == address.network_address or gateway == address.broadcast_address or gateway == address.ip:
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for interface address '{address}', skipping...")
                        gateway = None
                except AddressValueError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{gateway}' format configured for interface address '{address}' skipping...")
                    gateway = None
            address.gateway = gateway
            valid_address_candidate.append(address)
            if __debug__:
                self._logger.debug(f"Parsed ('{address}', '{address.gateway}') entry")

        return valid_address_candidate

    def _create_stack_ip4_addressing(self):
        """Create lists of IPv4 unicast, multicast and broadcast addresses stack should listen on"""

        # Perform Duplicate Address Detection
        for _ in range(3):
            for ip4_unicast in [_.ip for _ in self.ip4_address_candidate]:
                if ip4_unicast not in self.arp_probe_unicast_conflict:
                    self._send_arp_probe(ip4_unicast)
                    if __debug__:
                        self._logger.debug(f"Sent out ARP Probe for {ip4_unicast}")
            time.sleep(random.uniform(1, 2))
        for ip4_unicast in self.arp_probe_unicast_conflict:
            if __debug__:
                self._logger.warning(f"Unable to claim IPv4 address {ip4_unicast}")

        # Create list containing only IPv4 addresses that were confiremed free to claim
        for ip4_address in list(self.ip4_address_candidate):
            self.ip4_address_candidate.remove(ip4_address)
            if ip4_address.ip not in self.arp_probe_unicast_conflict:
                self.ip4_address.append(ip4_address)
                self._send_arp_announcement(ip4_address.ip)
                if __debug__:
                    self._logger.debug(f"Successfully claimed IPv4 address {ip4_unicast}")

        # If don't have any IPv4 address assigned disable IPv4 protocol operations
        if not self.ip4_address:
            if __debug__:
                self._logger.warning("Unable to assign any IPv4 address, disabling IPv4 protocol")
            config.ip4_support = False
            return

    def _send_arp_probe(self, ip4_unicast):
        """Send out ARP probe to detect possible IP conflict"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=fpa_arp.ARP_OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=IPv4Address("0.0.0.0"),
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP probe for {ip4_unicast}")

    def _send_arp_announcement(self, ip4_unicast):
        """Send out ARP announcement to claim IP address"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=fpa_arp.ARP_OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP Announcement for {ip4_unicast}")

    def _send_gratitous_arp(self, ip4_unicast):
        """Send out gratitous arp"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=fpa_arp.ARP_OP_REPLY,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out Gratitous ARP for {ip4_unicast}")

    def _send_icmp6_multicast_listener_report(self):
        """Send out ICMPv6 Multicast Listener Report for given list of addresses"""

        # Need to use set here to avoid re-using duplicate multicast entries from stack_ip6_multicast list,
        # also All Multicast Nodes address is not being advertised as this is not necessary
        if icmp6_mlr2_multicast_address_record := {
            fpa_icmp6.MulticastAddressRecord(record_type=fpa_icmp6.ICMP6_MART_CHANGE_TO_EXCLUDE, multicast_address=str(_))
            for _ in self.ip6_multicast
            if _ not in {IPv6Address("ff02::1")}
        }:
            self._phtx_icmp6(
                ip6_src=self.ip6_unicast[0] if self.ip6_unicast else IPv6Address("::"),
                ip6_dst=IPv6Address("ff02::16"),
                ip6_hop=1,
                icmp6_type=fpa_icmp6.ICMP6_MLD2_REPORT,
                icmp6_mlr2_multicast_address_record=icmp6_mlr2_multicast_address_record,
            )
            if __debug__:
                self._logger.debug(
                    f"Sent out ICMPv6 Multicast Listener Report message for {[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}"
                )

    def _send_icmp6_nd_dad_message(self, ip6_unicast_candidate):
        """Send out ICMPv6 ND Duplicate Address Detection message"""

        self._phtx_icmp6(
            ip6_src=IPv6Address("::"),
            ip6_dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6_hop=255,
            icmp6_type=fpa_icmp6.ICMP6_NEIGHBOR_SOLICITATION,
            icmp6_ns_target_address=ip6_unicast_candidate,
        )
        if __debug__:
            self._logger.debug(f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}")

    def _send_icmp6_nd_router_solicitation(self):
        """Send out ICMPv6 ND Router Solicitation"""

        self._phtx_icmp6(
            ip6_src=self.ip6_unicast[0],
            ip6_dst=IPv6Address("ff02::2"),
            ip6_hop=255,
            icmp6_type=fpa_icmp6.ICMP6_ROUTER_SOLICITATION,
            icmp6_nd_options=[fpa_icmp6.Icmp6NdOptSLLA(self.mac_unicast)],
        )
        if __debug__:
            self._logger.debug("Sent out ICMPv6 ND Router Solicitation")

    def _assign_ip6_address(self, ip6_address):
        """Assign IPv6 unicast address to the list stack listens on"""

        self.ip6_address.append(ip6_address)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 unicast address {ip6_address}")
        self._assign_ip6_multicast(ip6_address.solicited_node_multicast)

    def _remove_ip6_address(self, ip6_address):
        """Remove IPv6 unicast address from the list stack listens on"""

        self.ip6_address.remove(ip6_address)
        if __debug__:
            self._logger.debug(f"Removed IPv6 unicast address {ip6_address}")
        self._remove_ip6_multicast(ip6_address.solicited_node_multicast)

    def _assign_ip6_multicast(self, ip6_multicast):
        """Assign IPv6 multicast address to the list stack listens on"""

        self.ip6_multicast.append(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 multicast {ip6_multicast}")
        self._assign_mac_multicast(ip6_multicast.multicast_mac)
        for _ in range(1):
            self._send_icmp6_multicast_listener_report()

    def _remove_ip6_multicast(self, ip6_multicast):
        """Remove IPv6 multicast address from the list stack listens on"""

        self.ip6_multicast.remove(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Removed IPv6 multicast {ip6_multicast}")
        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, mac_multicast):
        """Assign MAC multicast address to the list stack listens on"""

        self.mac_multicast.append(mac_multicast)
        if __debug__:
            self._logger.debug(f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, mac_multicast):
        """Remove MAC multicast address from the list stack listens on"""

        self.mac_multicast.remove(mac_multicast)
        if __debug__:
            self._logger.debug(f"Removed MAC multicast {mac_multicast}")

    def _dhcp4_client(self):
        """Obtain IPv4 address and default gateway using DHCP"""

        def _send_dhcp_packet(dhcp_packet_tx):
            socket.send_to(
                UdpMetadata(
                    local_ip_address=IPv4Address("0.0.0.0"),
                    local_port=68,
                    remote_ip_address=IPv4Address("255.255.255.255"),
                    remote_port=67,
                    data=dhcp_packet_tx.get_raw_packet(),
                )
            )

        socket = UdpSocket()
        socket.bind(local_ip_address="0.0.0.0", local_port=68)
        dhcp_xid = random.randint(0, 0xFFFFFFFF)

        # Send DHCP Discover
        _send_dhcp_packet(
            dhcp_packet_tx=ps_dhcp.DhcpPacket(
                dhcp_xid=dhcp_xid,
                dhcp_chaddr=self.mac_unicast,
                dhcp_msg_type=ps_dhcp.DHCP_DISCOVER,
                dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                dhcp_host_name="PyTCP",
            )
        )
        if __debug__:
            self._logger.debug("Sent out DHCP Discover message")

        # Wait for DHCP Offer
        if not (packet := socket.receive_from(timeout=5)):
            if __debug__:
                self._logger.warning("Timeout waiting for DHCP Offer message")
            socket.close()
            return None, None

        dhcp_packet_rx = ps_dhcp.DhcpPacket(packet.data)
        if dhcp_packet_rx.dhcp_msg_type != ps_dhcp.DHCP_OFFER:
            if __debug__:
                self._logger.warning("Didn't receive DHCP Offer message")
            socket.close()
            return None, None

        dhcp_srv_id = dhcp_packet_rx.dhcp_srv_id
        dhcp_yiaddr = dhcp_packet_rx.dhcp_yiaddr
        if __debug__:
            self._logger.debug(
                f"ClientUdpDhcp: Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
                + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
                + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
            )

        # Send DHCP Request
        _send_dhcp_packet(
            dhcp_packet_tx=ps_dhcp.DhcpPacket(
                dhcp_xid=dhcp_xid,
                dhcp_chaddr=self.mac_unicast,
                dhcp_msg_type=ps_dhcp.DHCP_REQUEST,
                dhcp_srv_id=dhcp_srv_id,
                dhcp_req_ip4_addr=dhcp_yiaddr,
                dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                dhcp_host_name="PyTCP",
            )
        )

        if __debug__:
            self._logger.debug(f"Sent out DHCP Request message to {dhcp_packet_rx.dhcp_srv_id}")

        # Wait for DHCP Ack
        if not (packet := socket.receive_from(timeout=5)):
            if __debug__:
                self._logger.warning("Timeout waiting for DHCP Ack message")
            return None, None

        dhcp_packet_rx = ps_dhcp.DhcpPacket(packet.data)
        if dhcp_packet_rx.dhcp_msg_type != ps_dhcp.DHCP_ACK:
            if __debug__:
                self._logger.warning("Didn't receive DHCP Offer message")
            socket.close()
            return None, None

        if __debug__:
            self._logger.debug(
                f"Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
                + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
                + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
            )
        socket.close()
        return (
            IPv4Interface(str(dhcp_packet_rx.dhcp_yiaddr) + "/" + str(IPv4Address._make_netmask(str(dhcp_packet_rx.dhcp_subnet_mask))[1])),
            dhcp_packet_rx.dhcp_router[0],
        )
