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


#
# ph.py - packet handler for inbound and outbound packets
#

import random
import threading
import time
from ipaddress import AddressValueError
from typing import Optional, cast

import loguru

import arp.ps
import config
import icmp6.fpa
import icmp6.ps
import misc.stack as stack
from misc.arp_cache import ArpCache
from misc.ipv4_address import IPv4Address, IPv4Interface
from misc.ipv6_address import IPv6Address, IPv6Interface, IPv6Network
from misc.nd_cache import NdCache
from misc.rx_ring import RxRing
from misc.tx_ring import TxRing


class PacketHandler:
    """Pick up and respond to incoming packets"""

    from arp.phrx import _phrx_arp
    from arp.phtx import _phtx_arp
    from dhcp4.client import _dhcp4_client
    from ether.phrx import _phrx_ether
    from ether.phtx import _phtx_ether
    from icmp4.phrx import _phrx_icmp4
    from icmp4.phtx import _phtx_icmp4
    from icmp6.phrx import _phrx_icmp6
    from icmp6.phtx import _phtx_icmp6
    from ip4.phrx import _defragment_ip4_packet, _phrx_ip4
    from ip4.phtx import _phtx_ip4, _validate_dst_ip4_address, _validate_src_ip4_address
    from ip6.phrx import _phrx_ip6
    from ip6.phtx import _phtx_ip6, _validate_dst_ip6_address, _validate_src_ip6_address
    from ip6_ext_frag.phrx import _defragment_ip6_packet, _phrx_ip6_ext_frag
    from ip6_ext_frag.phtx import _phtx_ip6_ext_frag
    from tcp.phrx import _phrx_tcp
    from tcp.phtx import _phtx_tcp
    from udp.phrx import _phrx_udp
    from udp.phtx import _phtx_udp

    def __init__(self, tap):
        """Class constructor"""

        # Skip most of the initialisations for the unit test / mock run
        if tap is None:
            return

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
        self.arp_cache = ArpCache()
        self.icmp6_nd_cache = NdCache()

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

    # typing: Typing causes MyPy 0.812 to crash
    def __thread_packet_handler(self):
        """Thread picks up incoming packets from RX ring and processes them"""

        while True:
            self._phrx_ether(self.rx_ring.dequeue())

    @property
    def ip6_unicast(self) -> list[IPv6Address]:
        """Return list of stack's IPv6 unicast addresses"""

        return [_.ip for _ in self.ip6_address]

    @property
    def ip4_unicast(self) -> list[IPv4Address]:
        """Return list of stack's IPv4 unicast addresses"""

        return [_.ip for _ in self.ip4_address]

    @property
    def ip4_broadcast(self) -> list[IPv4Address]:
        """Return list of stack's IPv4 broadcast addresses"""

        ip4_broadcast = [_.network.broadcast_address for _ in self.ip4_address]
        ip4_broadcast.append("255.255.255.255")
        return ip4_broadcast

    def _perform_ip6_nd_dad(self, ip6_unicast_candidate: IPv6Address) -> bool:
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
            if __debug__:
                self._logger.debug(f"ICMPv6 ND DAD - No duplicate address detected for {ip6_unicast_candidate}")
        self.ip6_unicast_candidate = None
        self._remove_ip6_multicast(ip6_unicast_candidate.solicited_node_multicast)
        return not event

    def _parse_stack_ip6_address_candidate(self, configured_address_candidate: list[tuple[str, str]]) -> list[IPv6Interface]:
        """Parse IPv6 candidate address list"""

        valid_address_candidate: list[IPv6Interface] = []

        for str_address, str_gateway in configured_address_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{str_address}', '{str_gateway}') entry")
            try:
                address = IPv6Interface(str_address)
            except AddressValueError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{str_address}' format, skipping...")
                continue
            if address.is_multicast or address.is_reserved or address.is_loopback or address.is_unspecified:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{address.ip}' type, skipping...")
                continue
            if address.ip in [_.ip for _ in valid_address_candidate]:
                if __debug__:
                    self._logger.warning(f"Duplicate host address '{address.ip}' configured, skipping...")
                continue
            if address.is_link_local and str_gateway:
                if __debug__:
                    self._logger.warning("Gateway cannot be configured for link local address skipping...")
                continue
            if str_gateway:
                try:
                    gateway: Optional[IPv6Address] = IPv6Address(str_gateway)
                    gateway = cast(IPv6Address, gateway)
                    if not (gateway.is_link_local or (gateway in address.network and gateway != address.ip)):
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for interface address '{address}', skipping...")
                        continue
                except AddressValueError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{str_gateway}' format configured for interface address '{address}' skipping...")
                    continue
            else:
                gateway = None
            address.gateway = gateway
            valid_address_candidate.append(address)
            if __debug__:
                self._logger.debug(f"Parsed ('{address}', '{address.gateway}') entry")

        return valid_address_candidate

    def _create_stack_ip6_addressing(self) -> None:
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

    def _parse_stack_ip4_address_candidate(self, configured_ip4_address_candidate: list[tuple[str, str]]) -> list[IPv4Interface]:
        """Parse IPv4 candidate addresses configured in config.py module"""

        valid_address_candidate: list[IPv4Interface] = []

        for str_address, str_gateway in configured_ip4_address_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{str_address}', '{str_gateway}') entry")
            try:
                address = IPv4Interface(str_address)
            except AddressValueError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{str_address}' format, skipping...")
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
            if str_gateway:
                try:
                    gateway: Optional[IPv4Address] = IPv4Address(str_gateway)
                    if gateway not in address.network or gateway == address.network_address or gateway == address.broadcast_address or gateway == address.ip:
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for interface address '{address}', skipping...")
                        continue
                except AddressValueError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{str_gateway}' format configured for interface address '{address}' skipping...")
                    continue
            else:
                gateway = None
            address.gateway = gateway
            valid_address_candidate.append(address)
            if __debug__:
                self._logger.debug(f"Parsed ('{address}', '{address.gateway}') entry")

        return valid_address_candidate

    def _create_stack_ip4_addressing(self) -> None:
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

    # typing: Typing causes MyPy 0.812 to crash
    def _send_arp_probe(self, ip4_unicast):
        """Send out ARP probe to detect possible IP conflict"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=arp.ps.OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=IPv4Address("0.0.0.0"),
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP probe for {ip4_unicast}")

    # typing: Typing causes MyPy 0.812 to crash
    def _send_arp_announcement(self, ip4_unicast):
        """Send out ARP announcement to claim IP address"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=arp.ps.OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP Announcement for {ip4_unicast}")

    # typing: Typing causes MyPy 0.812 to crash
    def _send_gratitous_arp(self, ip4_unicast):
        """Send out gratitous arp"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst="ff:ff:ff:ff:ff:ff",
            arp_oper=arp.ps.OP_REPLY,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha="00:00:00:00:00:00",
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out Gratitous ARP for {ip4_unicast}")

    # typing: Typing causes MyPy 0.812 to crash
    def _send_icmp6_multicast_listener_report(self):
        """Send out ICMPv6 Multicast Listener Report for given list of addresses"""

        # Need to use set here to avoid re-using duplicate multicast entries from stack_ip6_multicast list,
        # also All Multicast Nodes address is not being advertised as this is not necessary
        if icmp6_mlr2_multicast_address_record := {
            icmp6.fpa.MulticastAddressRecord(record_type=icmp6.ps.MART_CHANGE_TO_EXCLUDE, multicast_address=str(_))
            for _ in self.ip6_multicast
            if _ not in {IPv6Address("ff02::1")}
        }:
            self._phtx_icmp6(
                ip6_src=self.ip6_unicast[0] if self.ip6_unicast else IPv6Address("::"),
                ip6_dst=IPv6Address("ff02::16"),
                ip6_hop=1,
                icmp6_type=icmp6.ps.MLD2_REPORT,
                icmp6_mlr2_multicast_address_record=icmp6_mlr2_multicast_address_record,
            )
            if __debug__:
                self._logger.debug(
                    f"Sent out ICMPv6 Multicast Listener Report message for {[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}"
                )

    # typing: Typing causes MyPy 0.812 to crash
    def _send_icmp6_nd_dad_message(self, ip6_unicast_candidate):
        """Send out ICMPv6 ND Duplicate Address Detection message"""

        self._phtx_icmp6(
            ip6_src=IPv6Address("::"),
            ip6_dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6_hop=255,
            icmp6_type=icmp6.ps.NEIGHBOR_SOLICITATION,
            icmp6_ns_target_address=ip6_unicast_candidate,
        )
        if __debug__:
            self._logger.debug(f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}")

    # typing: Typing causes MyPy 0.812 to crash
    def _send_icmp6_nd_router_solicitation(self):
        """Send out ICMPv6 ND Router Solicitation"""

        self._phtx_icmp6(
            ip6_src=self.ip6_unicast[0],
            ip6_dst=IPv6Address("ff02::2"),
            ip6_hop=255,
            icmp6_type=icmp6.ps.ROUTER_SOLICITATION,
            icmp6_nd_options=[icmp6.fpa.NdOptSLLA(self.mac_unicast)],
        )

        if __debug__:
            self._logger.debug("Sent out ICMPv6 ND Router Solicitation")

    def _assign_ip6_address(self, ip6_address: IPv6Address) -> None:
        """Assign IPv6 unicast address to the list stack listens on"""

        self.ip6_address.append(ip6_address)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 unicast address {ip6_address}")
        self._assign_ip6_multicast(ip6_address.solicited_node_multicast)

    def _remove_ip6_address(self, ip6_address: IPv6Address) -> None:
        """Remove IPv6 unicast address from the list stack listens on"""

        self.ip6_address.remove(ip6_address)
        if __debug__:
            self._logger.debug(f"Removed IPv6 unicast address {ip6_address}")
        self._remove_ip6_multicast(ip6_address.solicited_node_multicast)

    def _assign_ip6_multicast(self, ip6_multicast: IPv6Address) -> None:
        """Assign IPv6 multicast address to the list stack listens on"""

        self.ip6_multicast.append(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 multicast {ip6_multicast}")
        self._assign_mac_multicast(ip6_multicast.multicast_mac)
        for _ in range(1):
            self._send_icmp6_multicast_listener_report()

    def _remove_ip6_multicast(self, ip6_multicast: IPv6Address) -> None:
        """Remove IPv6 multicast address from the list stack listens on"""

        self.ip6_multicast.remove(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Removed IPv6 multicast {ip6_multicast}")
        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, mac_multicast: str) -> None:
        """Assign MAC multicast address to the list stack listens on"""

        self.mac_multicast.append(mac_multicast)
        if __debug__:
            self._logger.debug(f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, mac_multicast: str) -> None:
        """Remove MAC multicast address from the list stack listens on"""

        self.mac_multicast.remove(mac_multicast)
        if __debug__:
            self._logger.debug(f"Removed MAC multicast {mac_multicast}")
