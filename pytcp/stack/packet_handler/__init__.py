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
This package contains packet handler class for inbound and outbound packets.

pytcp/subsystems/packet_handler/__init__.py

ver 3.0.3
"""


from __future__ import annotations

import random
import threading
import time
from abc import ABC
from typing import TYPE_CHECKING, override

from net_addr import (
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    Ip6Network,
    MacAddress,
)
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.lib.subsystem import Subsystem
from pytcp.protocols.dhcp4__legacy.client import Dhcp4Client
from pytcp.protocols.enums import EtherType
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__PACKET__MAX_LEN,
)

from .packet_handler__arp__rx import PacketHandlerArpRx
from .packet_handler__arp__tx import PacketHandlerArpTx
from .packet_handler__ethernet_802_3__rx import PacketHandlerEthernet8023Rx
from .packet_handler__ethernet_802_3__tx import PacketHandlerEthernet8023Tx
from .packet_handler__ethernet__rx import PacketHandlerEthernetRx
from .packet_handler__ethernet__tx import PacketHandlerEthernetTx
from .packet_handler__icmp4__rx import PacketHandlerIcmp4Rx
from .packet_handler__icmp4__tx import PacketHandlerIcmp4Tx
from .packet_handler__icmp6__rx import PacketHandlerIcmp6Rx
from .packet_handler__icmp6__tx import PacketHandlerIcmp6Tx
from .packet_handler__ip4__rx import PacketHandlerIp4Rx
from .packet_handler__ip4__tx import PacketHandlerIp4Tx
from .packet_handler__ip6__rx import PacketHandlerIp6Rx
from .packet_handler__ip6__tx import PacketHandlerIp6Tx
from .packet_handler__ip6_frag__rx import PacketHandlerIp6FragRx
from .packet_handler__ip6_frag__tx import PacketHandlerIp6FragTx
from .packet_handler__tcp__rx import PacketHandlerTcpRx
from .packet_handler__tcp__tx import PacketHandlerTcpTx
from .packet_handler__udp__rx import PacketHandlerUdpRx
from .packet_handler__udp__tx import PacketHandlerUdpTx

if TYPE_CHECKING:
    from threading import Semaphore


class PacketHandler(Subsystem, ABC):
    """
    Base class for packet handlers.
    """

    _subsystem_name = "Packet Handler"

    _event__stop_subsystem: threading.Event

    _packet_stats_rx: PacketStatsRx
    _packet_stats_tx: PacketStatsTx
    _ip4_id: int
    _ip6_id: int
    _ip4_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip6_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip4_support: bool
    _ip6_support: bool

    def __init__(
        self,
        *,
        interface_mtu: int,
        ip6_support: bool,
        ip4_support: bool,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__()

        # Initialize the interface mtu.
        self._interface_mtu = interface_mtu

        # Initialize support for IPv6 and IPv4 protocols.
        self._ip6_support = ip6_support
        self._ip4_support = ip4_support

        # Initialize data stores for packet statistics used in unit testing.
        self._packet_stats_rx = PacketStatsRx()
        self._packet_stats_tx = PacketStatsTx()

        # Used to keep IPv4 and IPv6 packet ID last value.
        self._ip4_id: int = 0
        self._ip6_id: int = 0

        # Used to defragment IPv4 and IPv6 packets.
        self._ip4_frag_flows = {}
        self._ip6_frag_flows = {}


class PacketHandlerL2(
    PacketHandler,
    PacketHandlerArpRx,
    PacketHandlerArpTx,
    PacketHandlerEthernetRx,
    PacketHandlerEthernetTx,
    PacketHandlerEthernet8023Rx,
    PacketHandlerEthernet8023Tx,
    PacketHandlerIcmp6Rx,
    PacketHandlerIcmp6Tx,
    PacketHandlerIcmp4Rx,
    PacketHandlerIcmp4Tx,
    PacketHandlerIp4Rx,
    PacketHandlerIp4Tx,
    PacketHandlerIp6Rx,
    PacketHandlerIp6Tx,
    PacketHandlerIp6FragRx,
    PacketHandlerIp6FragTx,
    PacketHandlerTcpRx,
    PacketHandlerTcpTx,
    PacketHandlerUdpRx,
    PacketHandlerUdpTx,
):
    """
    Pick up and respond to incoming packets on Layer 2 (TAP) interface.
    """

    _interface_layer = InterfaceLayer.L2

    _packet_stats_rx: PacketStatsRx
    _packet_stats_tx: PacketStatsTx
    _ip4_id: int
    _ip6_id: int
    _ip4_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip6_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip4_support: bool
    _ip6_support: bool
    _interface_mtu: int

    _ip4_dhcp: bool
    _ip6_lla_autoconfig: bool
    _ip6_gua_autoconfig: bool
    _mac_unicast: MacAddress
    _mac_multicast: list[MacAddress]
    _mac_broadcast: MacAddress
    _ip6_host_candidate: list[Ip6Host]
    _ip6_host: list[Ip6Host]
    _ip6_multicast: list[Ip6Address]
    _ip4_host_candidate: list[Ip4Host]
    _ip4_host: list[Ip4Host]
    _ip4_multicast: list[Ip4Address]
    _arp_probe_unicast_conflict: set[Ip4Address]
    _ip6_unicast_candidate: Ip6Address | None
    _icmp6_nd_dad_event: Semaphore
    _icmp6_nd_dad_tlla: MacAddress | None
    _icmp6_ra_prefixes: list[tuple[Ip6Network, Ip6Address]]
    _icmp6_ra_event: Semaphore
    _ip_configuration_in_progress: Semaphore

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        interface_mtu: int,
        ip4_support: bool = True,
        ip4_host: Ip4Host | None = None,
        ip4_dhcp: bool = True,
        ip6_support: bool = True,
        ip6_host: Ip6Host | None = None,
        ip6_lla_autoconfig: bool = True,
        ip6_gua_autoconfig: bool = True,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__(
            interface_mtu=interface_mtu,
            ip6_support=ip6_support,
            ip4_support=ip4_support,
        )

        self._ip4_dhcp = ip4_dhcp
        self._ip6_lla_autoconfig = ip6_lla_autoconfig
        self._ip6_gua_autoconfig = ip6_gua_autoconfig

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This
        # is to accommodate IPv6 Solicited Node Multicast mechanism where
        # multiple IPv6 unicast addresses can be tied to the same SNM address
        # (and the same multicast MAC). This is important when removing one of
        # the unicast addresses, so the other ones keep it's SNM entry in the
        # multicast list. Its the simplest solution and imho perfectly valid
        # one in this case.
        self._mac_unicast = mac_address
        self._mac_multicast = []
        self._mac_broadcast = MacAddress(0xFFFFFFFFFFFF)
        self._ip6_host_candidate = []
        self._ip6_host = []
        self._ip6_multicast = []
        self._ip4_host_candidate = []
        self._ip4_host = []
        self._ip4_multicast = []

        # Used for the ARP DAD process.
        self._arp_probe_unicast_conflict: set[Ip4Address] = set()

        # Used for the ICMPv6 ND DAD process.
        self._ip6_unicast_candidate: Ip6Address | None = None
        self._icmp6_nd_dad_event: Semaphore = threading.Semaphore(0)
        self._icmp6_nd_dad_tlla: MacAddress | None = None

        # Used for the ICMPv6 ND RA address auto configuration.
        self._icmp6_ra_prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self._icmp6_ra_event: Semaphore = threading.Semaphore(0)

        # Used for IPv4 and IPv6 address configuration.
        self._ip_configuration_in_progress: Semaphore = threading.Semaphore(0)

        # Assigned IP addresses statically.
        if ip4_host is not None:
            self._ip4_host_candidate.append(ip4_host)

        if ip6_host is not None:
            self._ip6_host_candidate.append(ip6_host)

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return [ip6_host.address for ip6_host in self._ip6_host]

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self._ip4_host]

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        ip4_broadcast = [
            ip4_host.network.broadcast for ip4_host in self._ip4_host
        ]
        ip4_broadcast.append(Ip4Address(0xFFFFFFFF))

        return ip4_broadcast

    ###
    # Public interface.
    ###

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        """
        Get the packet statistics for received packets.
        """

        return self._packet_stats_rx

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        """
        Get the packet statistics for transmitted packets.
        """

        return self._packet_stats_tx

    @property
    def ip6_host(self) -> list[Ip6Host]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip6_host

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return self._ip6_unicast

    @property
    def ip4_host(self) -> list[Ip4Host]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip4_host

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast

    ###
    # Internal methods.
    ###

    @override
    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem thread.
        """

        self._acquire_ip4_addresses()
        self._acquire_ip6_addresses()

        self._log_stack_address_info()

    def _thread__packet_handler__acquire_ip6_addresses(self) -> None:
        """
        Thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Started the IPv6 address acquire thread")

        self._assign_ip6_multicast(Ip6Address("ff02::1"))
        self._create_stack_ip6_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv6 address acquire thread")

    def _thread__packet_handler__acquire_ip4_addresses(self) -> None:
        """
        Thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Started the IPv4 address acquire thread")

        if not self._ip4_host_candidate:
            if self._ip4_dhcp:
                if ip4_host := Dhcp4Client(self._mac_unicast).fetch():
                    self._ip4_host_candidate.append(ip4_host)

        self._create_stack_ip4_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv4 address acquire thread")

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        """

        from pytcp.stack import rx_ring

        if (packet_rx := rx_ring.dequeue()) is not None:
            if (
                int.from_bytes(packet_rx.frame[12:14])
                <= ETHERNET_802_3__PACKET__MAX_LEN
            ):
                self._phrx_ethernet_802_3(packet_rx)
            else:
                self._phrx_ethernet(packet_rx)

    def _acquire_ip6_addresses(self) -> None:
        """
        Start thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Starting the IPv6 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip6_addresses,
            daemon=True,
        ).start()

    def _acquire_ip4_addresses(self) -> None:
        """
        Start thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Starting the IPv4 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip4_addresses,
            daemon=True,
        ).start()

    def _perform_ip6_nd_dad(self, *, ip6_unicast_candidate: Ip6Address) -> bool:
        """
        Perform IPv6 ND Duplicate Address Detection, return True if passed.
        """

        __debug__ and log(
            "stack",
            f"ICMPv6 ND DAD - Starting process for {ip6_unicast_candidate}",
        )

        self._ip6_unicast_candidate = ip6_unicast_candidate

        self._assign_ip6_multicast(
            ip6_multicast=ip6_unicast_candidate.solicited_node_multicast
        )
        self._send_icmp6_nd_dad_message(
            ip6_unicast_candidate=ip6_unicast_candidate
        )

        if event := self._icmp6_nd_dad_event.acquire(timeout=1):
            __debug__ and log(
                "stack",
                "<WARN>ICMPv6 ND DAD - Duplicate IPv6 address detected, "
                f"{ip6_unicast_candidate} advertised by "
                f"{self._icmp6_nd_dad_tlla}</>",
            )
        else:
            __debug__ and log(
                "stack",
                "ICMPv6 ND DAD - No duplicate address detected for "
                f"{ip6_unicast_candidate}",
            )

        self._ip6_unicast_candidate = None
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

        # Configure Link Local address(es) staticaly.
        for ip6_host in list(self._ip6_host_candidate):
            if ip6_host.address.is_link_local:
                self._ip6_host_candidate.remove(ip6_host)
                _claim_ip6_address(ip6_host)

        # Configure Link Local address automatically.
        if self._ip6_lla_autoconfig:
            ip6_host = Ip6Host.from_eui64(
                mac_address=self._mac_unicast,
                ip6_network=Ip6Network("fe80::/64"),
            )
            ip6_host.gateway = None
            _claim_ip6_address(ip6_host)

        # If we don't have any link local address then disable
        # IPv6 protocol operations.
        if not self._ip6_host:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 link local address, "
                "disabling IPv6 protocol</>",
            )
            self._ip6_support = False
            return

        # Check if there are any statically configures GUA addresses.
        for ip6_host in list(self._ip6_host_candidate):
            self._ip6_host_candidate.remove(ip6_host)
            _claim_ip6_address(ip6_host)

        # Send out IPv6 Router Solicitation message and wait for response
        # in attempt to auto configure addresses based on
        # ICMPv6 Router Advertisement.
        if self._ip6_gua_autoconfig:
            self._send_icmp6_nd_router_solicitation()
            self._icmp6_ra_event.acquire(timeout=1)
            for prefix, gateway in list(self._icmp6_ra_prefixes):
                __debug__ and log(
                    "stack",
                    f"Attempting IPv6 address auto configuration for RA "
                    f"prefix {prefix}",
                )
                ip6_address = Ip6Host.from_eui64(
                    mac_address=self._mac_unicast,
                    ip6_network=prefix,
                )
                ip6_address.gateway = gateway
                _claim_ip6_address(ip6_address)

    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        # Perform Duplicate Address Detection.
        for _ in range(3):
            for ip4_unicast in [
                ip4_host_candidate.address
                for ip4_host_candidate in self._ip4_host_candidate
            ]:
                if ip4_unicast not in self._arp_probe_unicast_conflict:
                    self._send_arp_probe(ip4_unicast=ip4_unicast)
                    __debug__ and log(
                        "stack", f"Sent out ARP Probe for {ip4_unicast}"
                    )
            time.sleep(random.uniform(1, 2))

        for ip4_unicast in self._arp_probe_unicast_conflict:
            __debug__ and log(
                "stack",
                f"<WARN>Unable to claim IPv4 address {ip4_unicast}</>",
            )

        # Create list containing only IPv4 addresses that were
        # confirmed free to claim.
        for ip4_host in list(self._ip4_host_candidate):
            self._ip4_host_candidate.remove(ip4_host)
            if ip4_host.address not in self._arp_probe_unicast_conflict:
                self._ip4_host.append(ip4_host)
                self._send_arp_announcement(ip4_unicast=ip4_host.address)
                __debug__ and log(
                    "stack",
                    f"Successfully claimed IPv4 address {ip4_host.address}",
                )

        # If don't have any IPv4 address assigned disable IPv4 protocol
        # operations.
        if not self._ip4_host:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv4 address, disabling IPv4 "
                "protocol</>",
            )
            self._ip4_support = False
            return

    def _assign_ip6_host(self, /, ip6_host: Ip6Host) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        self._ip6_host.append(ip6_host)

        __debug__ and log("stack", f"Assigned IPv6 unicast address {ip6_host}")

        self._assign_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _remove_ip6_host(self, /, ip6_host: Ip6Host) -> None:
        """
        Remove IPv6 host unicast address from the list stack listens on.
        """

        self._ip6_host.remove(ip6_host)

        __debug__ and log("stack", f"Removed IPv6 unicast address {ip6_host}")

        self._remove_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        self._ip6_multicast.append(ip6_multicast)

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._assign_mac_multicast(ip6_multicast.multicast_mac)

        self._send_icmp6_multicast_listener_report()

    def _remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        self._ip6_multicast.remove(ip6_multicast)

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")

        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Assign MAC multicast address to the list stack listens on.
        """

        self._mac_multicast.append(mac_multicast)

        __debug__ and log("stack", f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Remove MAC multicast address from the list stack listens on.
        """

        self._mac_multicast.remove(mac_multicast)

        __debug__ and log("stack", f"Removed MAC multicast {mac_multicast}")

    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (self._ip6_support, self._ip4_support):
            self._ip_configuration_in_progress.acquire(timeout=15)

        if __debug__:
            log(
                "stack",
                "<INFO>Stack listening on unicast MAC address: "
                f"{self._mac_unicast}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on multicast MAC addresses: "
                f"{', '.join([str(mac_multicast) for mac_multicast in set(self._mac_multicast)])}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on broadcast MAC address: "
                f"{self._mac_broadcast}</>",
            )

            if self._ip6_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv6 addresses: "
                    f"{', '.join([str(ip6_unicast) for ip6_unicast in self.ip6_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv6 addresses: "
                    f"{', '.join([str(ip6_multicast) for ip6_multicast in set(self._ip6_multicast)])}</>",
                )

            if self._ip4_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv4 addresses: "
                    f"{', '.join([str(ip4_unicast) for ip4_unicast in self._ip4_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv4 addresses: "
                    f"{', '.join([str(ip4_multicast) for ip4_multicast in self._ip4_multicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on broadcast IPv4 addresses: "
                    f"{', '.join([str(ip4_broadcast) for ip4_broadcast in self._ip4_broadcast])}</>",
                )


class PacketHandlerL3(
    PacketHandler,
    PacketHandlerIcmp6Rx,
    PacketHandlerIcmp6Tx,
    PacketHandlerIcmp4Rx,
    PacketHandlerIcmp4Tx,
    PacketHandlerIp4Rx,
    PacketHandlerIp4Tx,
    PacketHandlerIp6Rx,
    PacketHandlerIp6Tx,
    PacketHandlerIp6FragRx,
    PacketHandlerIp6FragTx,
    PacketHandlerTcpRx,
    PacketHandlerTcpTx,
    PacketHandlerUdpRx,
    PacketHandlerUdpTx,
):
    """
    Pick up and respond to incoming packets on Layer 3 (TUN) interface.
    """

    _interface_layer = InterfaceLayer.L3

    _packet_stats_rx: PacketStatsRx
    _packet_stats_tx: PacketStatsTx
    _ip4_id: int
    _ip6_id: int
    _ip4_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip6_frag_flows: dict[IpFragFlowId, IpFragData]
    _ip4_support: bool
    _ip6_support: bool
    _interface_mtu: int

    _ip6_host: list[Ip6Host]
    _ip6_multicast: list[Ip6Address]
    _ip4_host: list[Ip4Host]
    _ip4_multicast: list[Ip4Address]

    def __init__(
        self,
        *,
        interface_mtu: int,
        ip4_support: bool = True,
        ip4_host: Ip4Host | None = None,
        ip6_support: bool = True,
        ip6_host: Ip6Host | None = None,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__(
            interface_mtu=interface_mtu,
            ip6_support=ip6_support,
            ip4_support=ip4_support,
        )

        # Initialize IPv6 addressing.
        if self._ip6_support:
            assert ip6_host is not None
            self._ip6_host = [ip6_host]
            self._ip6_multicast = []

        # Initialize IPv4 addressing.
        if self._ip4_support:
            assert ip4_host is not None
            self._ip4_host = [ip4_host]
            self._ip4_multicast = []

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return [ip6_host.address for ip6_host in self._ip6_host]

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self._ip4_host]

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        ip4_broadcast = [
            ip4_host.network.broadcast for ip4_host in self._ip4_host
        ]
        ip4_broadcast.append(Ip4Address(0xFFFFFFFF))

        return ip4_broadcast

    ###
    # Public interface.
    ###

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        """
        Get the packet statistics for received packets.
        """

        return self._packet_stats_rx

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        """
        Get the packet statistics for transmitted packets.
        """

        return self._packet_stats_tx

    @property
    def ip6_host(self) -> list[Ip6Host]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip6_host

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return self._ip6_unicast

    @property
    def ip4_host(self) -> list[Ip4Host]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip4_host

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast

    ###
    # Internal methods.
    ###

    @override
    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem thread.
        """

        self._log_stack_address_info()

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        """

        from pytcp.stack import rx_ring

        if (packet_rx := rx_ring.dequeue()) is not None:
            match EtherType.from_bytes(packet_rx.frame[2:4]):
                case EtherType.IP6:
                    if self._ip6_support:
                        packet_rx.frame = packet_rx.frame[4:]
                        self._phrx_ip6(packet_rx)
                case EtherType.IP4:
                    if self._ip4_support:
                        packet_rx.frame = packet_rx.frame[4:]
                        self._phrx_ip4(packet_rx)
                case _:
                    __debug__ and log(
                        "stack",
                        f"<WARN>Unknown EtherType 0x{packet_rx.frame[2:4].hex()} "
                        "received, dropping packet</>",
                    )

    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        if __debug__:
            if self._ip6_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv6 addresses: "
                    f"{', '.join([str(ip6_unicast) for ip6_unicast in self.ip6_unicast])}</>",
                )

            if self._ip4_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv4 addresses: "
                    f"{', '.join([str(ip4_unicast) for ip4_unicast in self._ip4_unicast])}</>",
                )
