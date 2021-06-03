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
from typing import Optional

import loguru

import arp.phrx
import arp.phtx
import arp.ps
import config
import dhcp4.client
import ether.phrx
import ether.phtx
import icmp4.phrx
import icmp4.phtx
import icmp6.fpa
import icmp6.phrx
import icmp6.phtx
import icmp6.ps
import ip4.phrx
import ip4.phtx
import ip6.phrx
import ip6.phtx
import ip6_ext_frag.phrx
import ip6_ext_frag.phtx
import misc.stack as stack
import tcp.phrx
import tcp.phtx
import udp.phrx
import udp.phtx
from lib.ip4_address import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4Host,
    Ip4HostFormatError,
)
from lib.ip6_address import (
    Ip6Address,
    Ip6AddressFormatError,
    Ip6Host,
    Ip6HostFormatError,
    Ip6Network,
)
from lib.mac_address import MacAddress
from misc.arp_cache import ArpCache
from misc.nd_cache import NdCache
from misc.rx_ring import RxRing
from misc.tx_ring import TxRing


class PacketHandler:
    """Pick up and respond to incoming packets"""

    # Using external imports due to MyPy bug #10488
    _phrx_arp = arp.phrx._phrx_arp
    _phtx_arp = arp.phtx._phtx_arp
    _phrx_ether = ether.phrx._phrx_ether
    _phtx_ether = ether.phtx._phtx_ether
    _phrx_icmp6 = icmp6.phrx._phrx_icmp6
    _phtx_icmp6 = icmp6.phtx._phtx_icmp6
    _phrx_ip6_ext_frag = ip6_ext_frag.phrx._phrx_ip6_ext_frag
    _defragment_ip6_packet = ip6_ext_frag.phrx._defragment_ip6_packet
    _phtx_ip6_ext_frag = ip6_ext_frag.phtx._phtx_ip6_ext_frag
    _phrx_icmp4 = icmp4.phrx._phrx_icmp4
    _phtx_icmp4 = icmp4.phtx._phtx_icmp4
    _phrx_ip4 = ip4.phrx._phrx_ip4
    _defragment_ip4_packet = ip4.phrx._defragment_ip4_packet
    _phtx_ip4 = ip4.phtx._phtx_ip4
    _validate_dst_ip4_address = ip4.phtx._validate_dst_ip4_address
    _validate_src_ip4_address = ip4.phtx._validate_src_ip4_address
    _phrx_ip6 = ip6.phrx._phrx_ip6
    _phtx_ip6 = ip6.phtx._phtx_ip6
    _validate_dst_ip6_address = ip6.phtx._validate_dst_ip6_address
    _validate_src_ip6_address = ip6.phtx._validate_src_ip6_address
    _phrx_tcp = tcp.phrx._phrx_tcp
    _phtx_tcp = tcp.phtx._phtx_tcp
    _phrx_udp = udp.phrx._phrx_udp
    _phtx_udp = udp.phtx._phtx_udp
    _dhcp4_client = dhcp4.client._dhcp4_client

    def __init__(self, tap: int) -> None:
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
        self.mac_unicast = MacAddress(config.mac_address)
        self.mac_multicast: list[MacAddress] = []
        self.mac_broadcast = MacAddress("ff:ff:ff:ff:ff:ff")
        self.ip6_host: list[Ip6Host] = []
        self.ip6_multicast: list[Ip6Address] = []
        self.ip4_host: list[Ip4Host] = []
        self.ip4_multicast: list[Ip4Address] = []

        self.rx_ring = RxRing(tap)
        self.tx_ring = TxRing(tap)
        self.arp_cache = ArpCache()
        self.icmp6_nd_cache = NdCache()

        # Used for the ARP DAD process
        self.arp_probe_unicast_conflict: set[Ip4Address] = set()

        # Used for the ICMPv6 ND DAD process
        self.ip6_unicast_candidate: Optional[Ip6Address] = None
        self.event_icmp6_nd_dad = threading.Semaphore(0)
        self.icmp6_nd_dad_tlla: Optional[Ip6Address] = None

        # Used for the IcMPv6 ND RA address auto configuration
        self.icmp6_ra_prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self.event_icmp6_ra = threading.Semaphore(0)

        # Used to keep IPv4 and IPv6 packet ID last value
        self.ip4_id = 0
        self.ip6_id = 0

        # Used to defragment IPv4 and IPv6 packets
        self.ip4_frag_flows: dict[int, bytes] = {}
        self.ip6_frag_flows: dict[int, bytes] = {}

        # Start packet handler so we can receive packets from network
        threading.Thread(target=self.__thread_packet_handler).start()
        if __debug__:
            self._logger.debug("Started packet handler")

        if config.ip6_support:
            # Assign All IPv6 Nodes multicast address
            self._assign_ip6_multicast(Ip6Address("ff02::1"))
            # Create list of IPv6 unicast/multicast addresses stack should listen on
            self.ip6_host_candidate = self._parse_stack_ip6_host_candidate(config.ip6_host_candidate)
            self._create_stack_ip6_addressing()

        if config.ip4_support:
            # Create list of IPv4 unicast/multicast/broadcast addresses stack should listen on, use DHCP if enabled
            ip4_host_dhcp = self._dhcp4_client()
            ip4_host_dhcp = [ip4_host_dhcp] if ip4_host_dhcp[0] else []
            self.ip4_host_candidate = self._parse_stack_ip4_host_candidate(config.ip4_host_candidate + ip4_host_dhcp)
            self._create_stack_ip4_addressing()

        # Log all the addresses stack will listen on
        if __debug__:
            self._logger.info(f"Stack listening on unicast MAC address: {self.mac_unicast}")
            self._logger.info(f"Stack listening on multicast MAC addresses: {[str(_) for _ in set(self.mac_multicast)]}")
            self._logger.info(f"Stack listening on broadcast MAC address: {self.mac_broadcast}")

        if config.ip6_support:
            if __debug__:
                self._logger.info(f"Stack listening on unicast IPv6 addresses: {[str(_) for _ in self.ip6_unicast]}")
                self._logger.info(f"Stack listening on multicast IPv6 addresses: {[str(_) for _ in set(self.ip6_multicast)]})")

        if config.ip4_support:
            if __debug__:
                self._logger.info(f"Stack listening on unicast IPv4 addresses: {[str(_) for _ in self.ip4_unicast]}")
                self._logger.info(f"Stack listening on multicast IPv4 addresses: {[str(_) for _ in self.ip4_multicast]}")
                self._logger.info(f"Stack listening on broadcast IPv4 addresses: {[str(_) for _ in self.ip4_broadcast]}")

    def __thread_packet_handler(self) -> None:
        """Thread picks up incoming packets from RX ring and processes them"""

        while True:
            self._phrx_ether(self.rx_ring.dequeue())

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """Return list of stack's IPv6 unicast addresses"""

        return [_.address for _ in self.ip6_host]

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """Return list of stack's IPv4 unicast addresses"""

        return [_.address for _ in self.ip4_host]

    @property
    def ip4_broadcast(self) -> list[Ip4Address]:
        """Return list of stack's IPv4 broadcast addresses"""

        ip4_broadcast = [_.network.broadcast for _ in self.ip4_host]
        ip4_broadcast.append(Ip4Address("255.255.255.255"))
        return ip4_broadcast

    def _perform_ip6_nd_dad(self, ip6_unicast_candidate: Ip6Address) -> bool:
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

    def _parse_stack_ip6_host_candidate(self, configured_host_candidate: list[tuple[str, str]]) -> list[Ip6Host]:
        """Parse IPv6 candidate address list"""

        valid_host_candidate: list[Ip6Host] = []

        for str_host, str_gateway in configured_host_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{str_host}', '{str_gateway}') entry")
            try:
                host = Ip6Host(str_host)
            except Ip6HostFormatError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{str_host}' format, skipping...")
                continue
            if not host.address.is_private and not host.address.is_global and not host.address.is_link_local:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{host.address}' type, skipping...")
                continue
            if host.address in [_.address for _ in valid_host_candidate]:
                if __debug__:
                    self._logger.warning(f"Duplicate host address '{host.address}' configured, skipping...")
                continue
            if host.address.is_link_local and str_gateway:
                if __debug__:
                    self._logger.warning("Gateway cannot be configured for link local address skipping...")
                continue
            if str_gateway:
                try:
                    gateway: Optional[Ip6Address] = Ip6Address(str_gateway)
                    assert gateway is not None
                    if not (gateway.is_link_local or (gateway in host.network and gateway != host.address)):
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for host address '{host}', skipping...")
                        continue
                except Ip6AddressFormatError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{str_gateway}' format configured for host address '{host}' skipping...")
                    continue
            else:
                gateway = None
            host.gateway = gateway
            valid_host_candidate.append(host)
            if __debug__:
                self._logger.debug(f"Parsed ('{host}', '{host.gateway}') entry")

        return valid_host_candidate

    def _create_stack_ip6_addressing(self) -> None:
        """Create lists of IPv6 unicast and multicast addresses stack should listen on"""

        def __(ip6_host):
            if self._perform_ip6_nd_dad(ip6_host.address):
                self._assign_ip6_host(ip6_host)
                if __debug__:
                    self._logger.debug(f"Successfully claimed IPv6 address {ip6_host}")
            else:
                if __debug__:
                    self._logger.warning(f"Unable to claim IPv6 address {ip6_host}")

        # Configure Link Local address(es) staticaly
        for ip6_host in list(self.ip6_host_candidate):
            if ip6_host.address.is_link_local:
                self.ip6_host_candidate.remove(ip6_host)
                __(ip6_host)

        # Configure Link Local address automatically
        if config.ip6_lla_autoconfig:
            ip6_host = Ip6Network("fe80::/64").eui64(self.mac_unicast)
            ip6_host.gateway = None
            __(ip6_host)

        # If we don't have any link local address set disable IPv6 protocol operations
        if not self.ip6_host:
            if __debug__:
                self._logger.warning("Unable to assign any IPv6 link local address, disabling IPv6 protocol")
            config.ip6_support = False
            return

        # Check if there are any statically configures GUA addresses
        for ip6_host in list(self.ip6_host_candidate):
            self.ip6_host_candidate.remove(ip6_host)
            __(ip6_host)

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

    def _parse_stack_ip4_host_candidate(self, configured_ip4_address_candidate: list[tuple[str, str]]) -> list[Ip4Host]:
        """Parse IPv4 candidate host addresses configured in config.py module"""

        valid_address_candidate: list[Ip4Host] = []

        for str_host, str_gateway in configured_ip4_address_candidate:
            if __debug__:
                self._logger.debug(f"Parsing ('{str_host}', '{str_gateway}') entry")
            try:
                host = Ip4Host(str_host)
            except Ip4HostFormatError:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{str_host}' format, skipping...")
                continue
            if not host.address.is_private and not host.address.is_global:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{host.address}' type, skipping...")
                continue
            if host.address == host.network.address or host.address == host.network.broadcast:
                if __debug__:
                    self._logger.warning(f"Invalid host address '{host.address}' configured for network '{host.network}', skipping...")
                continue
            if host.address in [_.address for _ in valid_address_candidate]:
                if __debug__:
                    self._logger.warning(f"Duplicate host address '{host.address}' configured, skipping...")
                continue
            if str_gateway:
                try:
                    gateway: Optional[Ip4Address] = Ip4Address(str_gateway)
                    if gateway not in host.network or gateway in {host.network.address, host.network.broadcast, host.address}:
                        if __debug__:
                            self._logger.warning(f"Invalid gateway '{gateway}' configured for host address '{host}', skipping...")
                        continue
                except Ip4AddressFormatError:
                    if __debug__:
                        self._logger.warning(f"Invalid gateway '{str_gateway}' format configured for host address '{host}' skipping...")
                    continue
            else:
                gateway = None
            host.gateway = gateway
            valid_address_candidate.append(host)
            if __debug__:
                self._logger.debug(f"Parsed ('{host}', '{host.gateway}') entry")

        return valid_address_candidate

    def _create_stack_ip4_addressing(self) -> None:
        """Create lists of IPv4 unicast, multicast and broadcast addresses stack should listen on"""

        # Perform Duplicate Address Detection
        for _ in range(3):
            for ip4_unicast in [_.address for _ in self.ip4_host_candidate]:
                if ip4_unicast not in self.arp_probe_unicast_conflict:
                    self._send_arp_probe(ip4_unicast)
                    if __debug__:
                        self._logger.debug(f"Sent out ARP Probe for {ip4_unicast}")
            time.sleep(random.uniform(1, 2))
        for ip4_unicast in self.arp_probe_unicast_conflict:
            if __debug__:
                self._logger.warning(f"Unable to claim IPv4 address {ip4_unicast}")

        # Create list containing only IPv4 addresses that were confirmed free to claim
        for ip4_host in list(self.ip4_host_candidate):
            self.ip4_host_candidate.remove(ip4_host)
            if ip4_host.address not in self.arp_probe_unicast_conflict:
                self.ip4_host.append(ip4_host)
                self._send_arp_announcement(ip4_host.address)
                if __debug__:
                    self._logger.debug(f"Successfully claimed IPv4 address {ip4_unicast}")

        # If don't have any IPv4 address assigned disable IPv4 protocol operations
        if not self.ip4_host:
            if __debug__:
                self._logger.warning("Unable to assign any IPv4 address, disabling IPv4 protocol")
            config.ip4_support = False
            return

    def _send_arp_probe(self, ip4_unicast: Ip4Address) -> None:
        """Send out ARP probe to detect possible IP conflict"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            arp_oper=arp.ps.ARP_OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=Ip4Address("0.0.0.0"),
            arp_tha=MacAddress("00:00:00:00:00:00"),
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP probe for {ip4_unicast}")

    def _send_arp_announcement(self, ip4_unicast: Ip4Address) -> None:
        """Send out ARP announcement to claim IP address"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            arp_oper=arp.ps.ARP_OP_REQUEST,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha=MacAddress("00:00:00:00:00:00"),
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out ARP Announcement for {ip4_unicast}")

    def _send_gratitous_arp(self, ip4_unicast: Ip4Address) -> None:
        """Send out gratitous arp"""

        self._phtx_arp(
            ether_src=self.mac_unicast,
            ether_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            arp_oper=arp.ps.ARP_OP_REPLY,
            arp_sha=self.mac_unicast,
            arp_spa=ip4_unicast,
            arp_tha=MacAddress("00:00:00:00:00:00"),
            arp_tpa=ip4_unicast,
        )
        if __debug__:
            self._logger.debug(f"Sent out Gratitous ARP for {ip4_unicast}")

    def _send_icmp6_multicast_listener_report(self) -> None:
        """Send out ICMPv6 Multicast Listener Report for given list of addresses"""

        # Need to use set here to avoid re-using duplicate multicast entries from stack_ip6_multicast list,
        # also All Multicast Nodes address is not being advertised as this is not necessary
        if icmp6_mlr2_multicast_address_record := {
            icmp6.fpa.MulticastAddressRecord(record_type=icmp6.ps.ICMP6_MART_CHANGE_TO_EXCLUDE, multicast_address=_)
            for _ in self.ip6_multicast
            if _ not in {Ip6Address("ff02::1")}
        }:
            self._phtx_icmp6(
                ip6_src=self.ip6_unicast[0] if self.ip6_unicast else Ip6Address("::"),
                ip6_dst=Ip6Address("ff02::16"),
                ip6_hop=1,
                icmp6_type=icmp6.ps.ICMP6_MLD2_REPORT,
                icmp6_mlr2_multicast_address_record=icmp6_mlr2_multicast_address_record,
            )
            if __debug__:
                self._logger.debug(
                    f"Sent out ICMPv6 Multicast Listener Report message for {[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}"
                )

    def _send_icmp6_nd_dad_message(self, ip6_unicast_candidate: Ip6Address) -> None:
        """Send out ICMPv6 ND Duplicate Address Detection message"""

        self._phtx_icmp6(
            ip6_src=Ip6Address("::"),
            ip6_dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6_hop=255,
            icmp6_type=icmp6.ps.ICMP6_NEIGHBOR_SOLICITATION,
            icmp6_ns_target_address=ip6_unicast_candidate,
        )
        if __debug__:
            self._logger.debug(f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}")

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """Send out ICMPv6 ND Router Solicitation"""

        self._phtx_icmp6(
            ip6_src=self.ip6_unicast[0],
            ip6_dst=Ip6Address("ff02::2"),
            ip6_hop=255,
            icmp6_type=icmp6.ps.ICMP6_ROUTER_SOLICITATION,
            icmp6_nd_options=[icmp6.fpa.Icmp6NdOptSLLA(self.mac_unicast)],
        )

        if __debug__:
            self._logger.debug("Sent out ICMPv6 ND Router Solicitation")

    def _assign_ip6_host(self, ip6_host: Ip6Host) -> None:
        """Assign IPv6 host unicast  address to the list stack listens on"""

        self.ip6_host.append(ip6_host)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 unicast address {ip6_host}")
        self._assign_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _remove_ip6_host(self, ip6_host: Ip6Host) -> None:
        """Remove IPv6 ihost unicast address from the list stack listens on"""

        self.ip6_host.remove(ip6_host)
        if __debug__:
            self._logger.debug(f"Removed IPv6 unicast address {ip6_host}")
        self._remove_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _assign_ip6_multicast(self, ip6_multicast: Ip6Address) -> None:
        """Assign IPv6 multicast address to the list stack listens on"""

        self.ip6_multicast.append(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Assigned IPv6 multicast {ip6_multicast}")
        self._assign_mac_multicast(ip6_multicast.multicast_mac)
        for _ in range(1):
            self._send_icmp6_multicast_listener_report()

    def _remove_ip6_multicast(self, ip6_multicast: Ip6Address) -> None:
        """Remove IPv6 multicast address from the list stack listens on"""

        self.ip6_multicast.remove(ip6_multicast)
        if __debug__:
            self._logger.debug(f"Removed IPv6 multicast {ip6_multicast}")
        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, mac_multicast: MacAddress) -> None:
        """Assign MAC multicast address to the list stack listens on"""

        self.mac_multicast.append(mac_multicast)
        if __debug__:
            self._logger.debug(f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, mac_multicast: MacAddress) -> None:
        """Remove MAC multicast address from the list stack listens on"""

        self.mac_multicast.remove(mac_multicast)
        if __debug__:
            self._logger.debug(f"Removed MAC multicast {mac_multicast}")
