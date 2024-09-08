#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains packet handler class for inbound and outbound packets.

pytcp/subsystems/icmp6__packet_handler.py

ver 3.0.2
"""


from __future__ import annotations

import random
import threading
import time
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.logger import log
from pytcp.lib.net_addr import (
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    Ip6Network,
    MacAddress,
)
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.protocols.arp.arp__packet_handler_rx import ArpPacketHandlerRx
from pytcp.protocols.arp.arp__packet_handler_tx import ArpPacketHandlerTx
from pytcp.protocols.dhcp4__legacy.client import Dhcp4Client
from pytcp.protocols.ethernet.ethernet__packet_handler_rx import (
    EthernetPacketHandlerRx,
)
from pytcp.protocols.ethernet.ethernet__packet_handler_tx import (
    EthernetPacketHandlerTx,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__PACKET__MAX_LEN,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__packet_handler_rx import (
    Ethernet8023PacketHandlerRx,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__packet_handler_tx import (
    Ethernet8023PacketHandlerTx,
)
from pytcp.protocols.icmp4.icmp4__packet_handler_rx import Icmp4PacketHandlerRx
from pytcp.protocols.icmp4.icmp4__packet_handler_tx import Icmp4PacketHandlerTx
from pytcp.protocols.icmp6.icmp6__packet_handler_rx import Icmp6PacketHandlerRx
from pytcp.protocols.icmp6.icmp6__packet_handler_tx import Icmp6PacketHandlerTx
from pytcp.protocols.ip4.ip4__packet_handler_rx import Ip4PacketHandlerRx
from pytcp.protocols.ip4.ip4__packet_handler_tx import Ip4PacketHandlerTx
from pytcp.protocols.ip6.ip6__packet_handler_rx import Ip6PacketHandlerRx
from pytcp.protocols.ip6.ip6__packet_handler_tx import Ip6PacketHandlerTx
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__packet_handler_rx import (
    Ip6ExtFragPacketHandlerRx,
)
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__packet_handler_tx import (
    Ip6ExtFragPacketHandlerTx,
)
from pytcp.protocols.tcp.tcp__packet_handler_rx import TcpPacketHandlerRx
from pytcp.protocols.tcp.tcp__packet_handler_tx import TcpPacketHandlerTx
from pytcp.protocols.udp.udp__packet_handler_rx import UdpPacketHandlerRx
from pytcp.protocols.udp.udp__packet_handler_tx import UdpPacketHandlerTx

if TYPE_CHECKING:
    from threading import Semaphore


class PacketHandler(
    ArpPacketHandlerRx,
    ArpPacketHandlerTx,
    EthernetPacketHandlerRx,
    EthernetPacketHandlerTx,
    Ethernet8023PacketHandlerRx,
    Ethernet8023PacketHandlerTx,
    Icmp6PacketHandlerRx,
    Icmp6PacketHandlerTx,
    Icmp4PacketHandlerRx,
    Icmp4PacketHandlerTx,
    Ip4PacketHandlerRx,
    Ip4PacketHandlerTx,
    Ip6PacketHandlerRx,
    Ip6PacketHandlerTx,
    Ip6ExtFragPacketHandlerRx,
    Ip6ExtFragPacketHandlerTx,
    TcpPacketHandlerRx,
    TcpPacketHandlerTx,
    UdpPacketHandlerRx,
    UdpPacketHandlerTx,
):
    """
    Pick up and respond to incoming packets.
    """

    def __init__(self) -> None:
        """
        Class constructor.
        """

        # Initialize data stores for packet statistics (used mainly in usnit
        # testing, but also available via cli).
        self.packet_stats_rx = PacketStatsRx()
        self.packet_stats_tx = PacketStatsTx()

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This
        # is to accommodate IPv6 Solicited Node Multicast mechanism where
        # multiple IPv6 unicast addresses can be tied to the same SNM address
        # (and the same multicast MAC). This is important when removing one of
        # the unicast addresses, so the other ones keep it's SNM entry in the
        # multicast list. Its the simplest solution and imho perfectly valid
        # one in this case.
        self.mac_unicast: MacAddress = MacAddress(config.ETHERNET__MAC_ADDRESS)
        self.mac_multicast: list[MacAddress] = []
        self.mac_broadcast: MacAddress = MacAddress(0xFFFFFFFFFFFF)
        self.ip6_host_candidate: list[Ip6Host] = []
        self.ip6_host: list[Ip6Host] = []
        self.ip6_multicast: list[Ip6Address] = []
        self.ip4_host_candidate: list[Ip4Host] = []
        self.ip4_host: list[Ip4Host] = []
        self.ip4_multicast: list[Ip4Address] = []

        # Used for the ARP DAD process
        self.arp_probe_unicast_conflict: set[Ip4Address] = set()

        # Used for the ICMPv6 ND DAD process
        self.ip6_unicast_candidate: Ip6Address | None = None
        self.icmp6_nd_dad_event: Semaphore = threading.Semaphore(0)
        self.icmp6_nd_dad_tlla: MacAddress | None = None

        # Used for the IcMPv6 ND RA address auto configuration
        self.icmp6_ra_prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self.icmp6_ra_event: Semaphore = threading.Semaphore(0)

        # Used to keep IPv4 and IPv6 packet ID last value
        self.ip4_id: int = 0
        self.ip6_id: int = 0

        # Used to defragment IPv4 and IPv6 packets
        self.ip4_frag_flows: dict[tuple[Ip4Address, Ip4Address, int], dict] = {}
        self.ip6_frag_flows: dict[tuple[Ip6Address, Ip6Address, int], dict] = {}

        # Thread control
        self._run_thread: bool = False

        # Used for IPv4 and IPv6 address configuration
        self.ip_configuration_in_progress: Semaphore = threading.Semaphore(0)

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """
        Return list of stack's IPv6 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self.ip6_host]

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """
        Return list of stack's IPv4 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self.ip4_host]

    @property
    def ip4_broadcast(self) -> list[Ip4Address]:
        """
        Return list of stack's IPv4 broadcast addresses.
        """

        ip4_broadcast = [
            ip4_host.network.broadcast for ip4_host in self.ip4_host
        ]
        ip4_broadcast.append(Ip4Address(0xFFFFFFFF))

        return ip4_broadcast

    def start(self) -> None:
        """
        Start packet handler thread.
        """

        __debug__ and log("stack", "Starting packet handler")

        self._run_thread = True
        threading.Thread(target=self.__thread__packet_handler__receive).start()
        time.sleep(0.1)

        self._acquire_ip4_addresses()
        self._acquire_ip6_addresses()

        self._log_stack_address_info()

    def stop(self) -> None:
        """
        Stop packet handler thread.
        """

        __debug__ and log("stack", "Stopping packet handler")

        self._run_thread = False
        time.sleep(0.1)

    def __thread__packet_handler__acquire_ip6_addresses(self) -> None:
        """
        Thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Started the IPv6 address acquire thread")

        self._assign_ip6_multicast(Ip6Address("ff02::1"))
        self._create_stack_ip6_addressing()

        self.ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv6 address acquire thread")

    def __thread__packet_handler__acquire_ip4_addresses(self) -> None:
        """
        Thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Started the IPv4 address acquire thread")

        if not self.ip4_host_candidate:
            if config.IP4__HOST_DHCP:
                if ip4_host := Dhcp4Client(self.mac_unicast).fetch():
                    self.ip4_host_candidate.append(ip4_host)
        self._create_stack_ip4_addressing()

        self.ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv4 address acquire thread")

    def __thread__packet_handler__receive(self) -> None:
        """
        Thread picks up incoming packets from RX ring and processes them.
        """

        __debug__ and log("stack", "Started packet handler")

        while self._run_thread:
            if (packet_rx := stack.rx_ring.dequeue()) is not None:
                if (
                    int.from_bytes(packet_rx.frame[12:14])
                    <= ETHERNET_802_3__PACKET__MAX_LEN
                ):
                    self._phrx_ethernet_802_3(packet_rx)
                else:
                    self._phrx_ethernet(packet_rx)

        __debug__ and log("stack", "Stopped packet handler")

    def _acquire_ip6_addresses(self) -> None:
        """
        Start thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Starting the IPv6 address acquire thread")

        threading.Thread(
            target=self.__thread__packet_handler__acquire_ip6_addresses
        ).start()

    def _acquire_ip4_addresses(self) -> None:
        """
        Start thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Starting the IPv4 address acquire thread")

        threading.Thread(
            target=self.__thread__packet_handler__acquire_ip4_addresses
        ).start()

    def _assign_mac_address(self, *, mac_unicast: MacAddress) -> None:
        """
        Assign MAC address information.
        """

        self.mac_unicast = mac_unicast

    def _assign_ip6_address(self, *, ip6_host: Ip6Host) -> None:
        """
        Assign IPv6 address information.
        """

        self.ip6_host_candidate.append(ip6_host)

    def _assign_ip4_address(self, *, ip4_host: Ip4Host) -> None:
        """
        Assign IPv4 address information.
        """

        self.ip4_host_candidate.append(ip4_host)

    def _perform_ip6_nd_dad(self, *, ip6_unicast_candidate: Ip6Address) -> bool:
        """
        Perform IPv6 ND Duplicate Address Detection, return True if passed.
        """

        __debug__ and log(
            "stack",
            f"ICMPv6 ND DAD - Starting process for {ip6_unicast_candidate}",
        )

        self.ip6_unicast_candidate = ip6_unicast_candidate

        self._assign_ip6_multicast(
            ip6_multicast=ip6_unicast_candidate.solicited_node_multicast
        )
        self._send_icmp6_nd_dad_message(
            ip6_unicast_candidate=ip6_unicast_candidate
        )
        if event := self.icmp6_nd_dad_event.acquire(timeout=1):
            __debug__ and log(
                "stack",
                "<WARN>ICMPv6 ND DAD - Duplicate IPv6 address detected, "
                f"{ip6_unicast_candidate} advertised by "
                f"{self.icmp6_nd_dad_tlla}</>",
            )
        else:
            __debug__ and log(
                "stack",
                "ICMPv6 ND DAD - No duplicate address detected for "
                f"{ip6_unicast_candidate}",
            )
        self.ip6_unicast_candidate = None
        self._remove_ip6_multicast(
            ip6_unicast_candidate.solicited_node_multicast
        )
        return not event

    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.
        """

        def _claim_ip6_address(ip6_host: Ip6Host) -> None:
            if self._perform_ip6_nd_dad(
                ip6_unicast_candidate=ip6_host.address,
            ):
                self._assign_ip6_host(ip6_host=ip6_host)
                __debug__ and log(
                    "stack", f"Successfully claimed IPv6 address {ip6_host}"
                )
            else:
                __debug__ and log(
                    "stack",
                    f"<WARN>Unable to claim IPv6 address {ip6_host}</>",
                )

        # Configure Link Local address(es) staticaly
        for ip6_host in list(self.ip6_host_candidate):
            if ip6_host.address.is_link_local:
                self.ip6_host_candidate.remove(ip6_host)
                _claim_ip6_address(ip6_host)

        # Configure Link Local address automatically
        if config.IP6__LLA_AUTOCONFIG:
            ip6_host = Ip6Host.from_eui64(
                mac_address=self.mac_unicast,
                ip6_network=Ip6Network("fe80::/64"),
            )
            ip6_host.gateway = None
            _claim_ip6_address(ip6_host)

        # If we don't have any link local address set disable
        # IPv6 protocol operations
        if not self.ip6_host:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 link local address, "
                "disabling IPv6 protocol</>",
            )
            config.IP6__SUPPORT_ENABLED = False
            return

        # Check if there are any statically configures GUA addresses
        for ip6_host in list(self.ip6_host_candidate):
            self.ip6_host_candidate.remove(ip6_host)
            _claim_ip6_address(ip6_host)

        # Send out IPv6 Router Solicitation message and wait for response
        # in attempt to auto configure addresses based on
        # ICMPv6 Router Advertisement.
        if config.IP6__GUA_AUTOCONFIG:
            self._send_icmp6_nd_router_solicitation()
            self.icmp6_ra_event.acquire(timeout=1)
            for prefix, gateway in list(self.icmp6_ra_prefixes):
                __debug__ and log(
                    "stack",
                    f"Attempting IPv6 address auto configuration for RA "
                    f"prefix {prefix}",
                )
                ip6_address = Ip6Host.from_eui64(
                    mac_address=self.mac_unicast,
                    ip6_network=prefix,
                )
                ip6_address.gateway = gateway
                _claim_ip6_address(ip6_address)

    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        # Perform Duplicate Address Detection
        for _ in range(3):
            for ip4_unicast in [_.address for _ in self.ip4_host_candidate]:
                if ip4_unicast not in self.arp_probe_unicast_conflict:
                    self._send_arp_probe(ip4_unicast=ip4_unicast)
                    __debug__ and log(
                        "stack", f"Sent out ARP Probe for {ip4_unicast}"
                    )
            time.sleep(random.uniform(1, 2))
        for ip4_unicast in self.arp_probe_unicast_conflict:
            __debug__ and log(
                "stack",
                f"<WARN>Unable to claim IPv4 address {ip4_unicast}</>",
            )

        # Create list containing only IPv4 addresses that were
        # confirmed free to claim
        for ip4_host in list(self.ip4_host_candidate):
            self.ip4_host_candidate.remove(ip4_host)
            if ip4_host.address not in self.arp_probe_unicast_conflict:
                self.ip4_host.append(ip4_host)
                self._send_arp_announcement(ip4_unicast=ip4_host.address)
                __debug__ and log(
                    "stack",
                    f"Successfully claimed IPv4 address {ip4_host.address}",
                )

        # If don't have any IPv4 address assigned disable IPv4 protocol
        # operations
        if not self.ip4_host:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv4 address, disabling IPv4 "
                "protocol</>",
            )
            config.IP4__SUPPORT_ENABLED = False
            return

    def _assign_ip6_host(self, /, ip6_host: Ip6Host) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        self.ip6_host.append(ip6_host)

        __debug__ and log("stack", f"Assigned IPv6 unicast address {ip6_host}")

        self._assign_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _remove_ip6_host(self, /, ip6_host: Ip6Host) -> None:
        """
        Remove IPv6 host unicast address from the list stack listens on.
        """

        self.ip6_host.remove(ip6_host)

        __debug__ and log("stack", f"Removed IPv6 unicast address {ip6_host}")

        self._remove_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        self.ip6_multicast.append(ip6_multicast)

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._assign_mac_multicast(ip6_multicast.multicast_mac)
        for _ in range(1):
            self._send_icmp6_multicast_listener_report()

    def _remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        self.ip6_multicast.remove(ip6_multicast)

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")

        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Assign MAC multicast address to the list stack listens on.
        """

        self.mac_multicast.append(mac_multicast)

        __debug__ and log("stack", f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Remove MAC multicast address from the list stack listens on.
        """

        self.mac_multicast.remove(mac_multicast)

        __debug__ and log("stack", f"Removed MAC multicast {mac_multicast}")

    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (config.IP6__SUPPORT_ENABLED, config.IP4__SUPPORT_ENABLED):
            stack.packet_handler.ip_configuration_in_progress.acquire(
                timeout=15
            )

        if __debug__:
            log(
                "stack",
                "<INFO>Stack listening on unicast MAC address: "
                f"{self.mac_unicast}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on multicast MAC addresses: "
                f"{', '.join([str(mac_multicast) for mac_multicast in set(self.mac_multicast)])}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on broadcast MAC address: "
                f"{self.mac_broadcast}</>",
            )

            if config.IP6__SUPPORT_ENABLED:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv6 addresses: "
                    f"{', '.join([str(ip6_unicast) for ip6_unicast in self.ip6_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv6 addresses: "
                    f"{', '.join([str(ip6_multicast) for ip6_multicast in set(self.ip6_multicast)])}</>",
                )

            if config.IP4__SUPPORT_ENABLED:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv4 addresses: "
                    f"{', '.join([str(ip4_unicast) for ip4_unicast in self.ip4_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv4 addresses: "
                    f"{', '.join([str(ip4_multicast) for ip4_multicast in self.ip4_multicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on broadcast IPv4 addresses: "
                    f"{', '.join([str(ip4_broadcast) for ip4_broadcast in self.ip4_broadcast])}</>",
                )
