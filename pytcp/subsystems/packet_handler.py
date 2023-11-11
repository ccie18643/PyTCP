#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-arguments
# pylint: disable = too-many-locals
# pylint: disable = redefined-builtin
# pylint: disable = expression-not-assigned
# pylint: disable = consider-using-with


"""
Module contains packet handler class for inbound and outbound packets.

pytcp/subsystems/packet_handler.py

ver 2.7
"""


from __future__ import annotations

import random
import threading
import time
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address, Ip4Host
from pytcp.lib.ip6_address import Ip6Address, Ip6Host, Ip6Network
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.arp.phrx import PacketHandlerRxArp
from pytcp.protocols.arp.phtx import PacketHandlerTxArp
from pytcp.protocols.arp.ps import ArpOperation
from pytcp.protocols.dhcp4.client import Dhcp4Client
from pytcp.protocols.ethernet.phrx import PacketHandlerRxEthernet
from pytcp.protocols.ethernet.phtx import PacketHandlerTxEthernet
from pytcp.protocols.icmp4.phrx import PacketHandlerRxIcmp4
from pytcp.protocols.icmp4.phtx import PacketHandlerTxIcmp4
from pytcp.protocols.icmp4.ps import Icmp4Message
from pytcp.protocols.icmp6.fpa import (
    Icmp6Mld2AddressRecordAssembler,
    Icmp6Mld2ReportMessageAssembler,
    Icmp6NdNeighborSolicitationMessageAssembler,
    Icmp6NdOptSllaAssembler,
    Icmp6NdRouterSolicitationMessageAssembler,
)
from pytcp.protocols.icmp6.phrx import PacketHandlerRxIcmp6
from pytcp.protocols.icmp6.phtx import PacketHandlerTxIcmp6
from pytcp.protocols.icmp6.ps import Icmp6Message, Icmp6Mld2RecordType
from pytcp.protocols.ip4.phrx import PacketHandlerRxIp4
from pytcp.protocols.ip4.phtx import PacketHandlerTxIp4
from pytcp.protocols.ip6.phrx import PacketHandlerRxIp6
from pytcp.protocols.ip6.phtx import PacketHandlerTxIp6
from pytcp.protocols.ip6_ext_frag.phrx import PacketHandlerRxIp6ExtFrag
from pytcp.protocols.ip6_ext_frag.phtx import PacketHandlerTxIp6ExtFrag
from pytcp.protocols.tcp.phrx import PacketHandlerRxTcp
from pytcp.protocols.tcp.phtx import PacketHandlerTxTcp
from pytcp.protocols.udp.phrx import PacketHandlerRxUdp
from pytcp.protocols.udp.phtx import PacketHandlerTxUdp

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.lib.ip_address import IpAddress


class PacketHandler(
    PacketHandlerRxArp,
    PacketHandlerTxArp,
    PacketHandlerRxEthernet,
    PacketHandlerTxEthernet,
    PacketHandlerRxIcmp6,
    PacketHandlerTxIcmp6,
    PacketHandlerRxIcmp4,
    PacketHandlerTxIcmp4,
    PacketHandlerRxIp4,
    PacketHandlerTxIp4,
    PacketHandlerRxIp6,
    PacketHandlerTxIp6,
    PacketHandlerRxIp6ExtFrag,
    PacketHandlerTxIp6ExtFrag,
    PacketHandlerRxTcp,
    PacketHandlerTxTcp,
    PacketHandlerRxUdp,
    PacketHandlerTxUdp,
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
        self.mac_unicast: MacAddress = MacAddress(config.MAC_ADDRESS)
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

    def start(self) -> None:
        """
        Start packet handler thread.
        """

        __debug__ and log("stack", "Starting packet handler")

        self._run_thread = True
        threading.Thread(target=self.__thread_packet_handler).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop packet handler thread.
        """

        __debug__ and log("stack", "Stopping packet handler")

        self._run_thread = False
        time.sleep(0.1)

    def assign_mac_address(self, *, mac_unicast: MacAddress) -> None:
        """
        Assign MAC address information.
        """

        self.mac_unicast = mac_unicast

    def assign_ip6_address(self, *, ip6_host: Ip6Host) -> None:
        """
        Assign IPv6 address information.
        """

        self.ip6_host_candidate.append(ip6_host)

    def acquire_ip6_addresses(self) -> None:
        """
        Assign the IPv6 addresses.
        """

        if config.IP6_SUPPORT:
            self._assign_ip6_multicast(Ip6Address("ff02::1"))
            self._create_stack_ip6_addressing()

    def assign_ip4_address(self, *, ip4_host: Ip4Host) -> None:
        """
        Assign IPv4 address information.
        """

        self.ip4_host_candidate.append(ip4_host)

    def acquire_ip4_addresses(self) -> None:
        """
        Acquire the IPv4 addresses.
        """

        if config.IP4_SUPPORT:
            if not self.ip4_host_candidate:
                if config.IP4_HOST_DHCP:
                    if ip4_host := Dhcp4Client(self.mac_unicast).fetch():
                        self.ip4_host_candidate.append(ip4_host)
            self._create_stack_ip4_addressing()

    def log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

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

            if config.IP6_SUPPORT:
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

            if config.IP4_SUPPORT:
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

    def __thread_packet_handler(self) -> None:
        """
        Thread picks up incoming packets from RX ring and processes them.
        """

        __debug__ and log("stack", "Started packet handler")

        while self._run_thread:
            if (packet_rx := stack.rx_ring.dequeue()) is not None:
                self._phrx_ethernet(packet_rx=packet_rx)

        __debug__ and log("stack", "Stopped packet handler")

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
        if config.IP6_LLA_AUTOCONFIG:
            ip6_host = Ip6Network("fe80::/64").eui64(self.mac_unicast)
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
            config.IP6_SUPPORT = False
            return

        # Check if there are any statically configures GUA addresses
        for ip6_host in list(self.ip6_host_candidate):
            self.ip6_host_candidate.remove(ip6_host)
            _claim_ip6_address(ip6_host)

        # Send out IPv6 Router Solicitation message and wait for response
        # in attempt to auto configure addresses based on
        # ICMPv6 Router Advertisement.
        if config.IP6_GUA_AUTOCONFIG:
            self._send_icmp6_nd_router_solicitation()
            self.icmp6_ra_event.acquire(timeout=1)
            for prefix, gateway in list(self.icmp6_ra_prefixes):
                __debug__ and log(
                    "stack",
                    f"Attempting IPv6 address auto configuration for RA "
                    f"prefix {prefix}",
                )
                ip6_address = prefix.eui64(self.mac_unicast)
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
            config.IP4_SUPPORT = False
            return

    def _send_arp_probe(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out ARP probe to detect possible IP conflict.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mac_unicast,
            arp__spa=Ip4Address(0),
            arp__tha=MacAddress(0),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP probe for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP probe for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def _send_arp_announcement(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out ARP announcement to claim IP address.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REQUEST,
            arp__sha=self.mac_unicast,
            arp__spa=ip4_unicast,
            arp__tha=MacAddress(0),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ARP Announcement for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ARP Announcement for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def _send_gratitous_arp(self, *, ip4_unicast: Ip4Address) -> None:
        """
        Send out gratitous arp.
        """

        tx_status = self._phtx_arp(
            ethernet__src=self.mac_unicast,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            arp__oper=ArpOperation.REPLY,
            arp__sha=self.mac_unicast,
            arp__spa=ip4_unicast,
            arp__tha=MacAddress(0),
            arp__tpa=ip4_unicast,
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out Gratitous ARP for {ip4_unicast}",
            )
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out Gratitous ARP for {ip4_unicast}, "
                f"tx_status: {tx_status}",
            )

    def _send_icmp6_multicast_listener_report(self) -> None:
        """
        Send out ICMPv6 Multicast Listener Report for given list of addresses.
        """

        # Need to use set here to avoid re-using duplicate multicast entries
        # from stack_ip6_multicast list, also All Multicast Nodes address is
        # not being advertised as this is not necessary.
        if icmp6_mlr2_multicast_address_record := {
            Icmp6Mld2AddressRecordAssembler(
                record_type=Icmp6Mld2RecordType.CHANGE_TO_EXCLUDE,
                multicast_address=multicast_address,
            )
            for multicast_address in self.ip6_multicast
            if multicast_address not in {Ip6Address("ff02::1")}
        }:
            tx_status = self._phtx_icmp6(
                ip6__src=self.ip6_unicast[0]
                if self.ip6_unicast
                else Ip6Address(0),
                ip6__dst=Ip6Address("ff02::16"),
                ip6__hop=1,
                icmp6__message=Icmp6Mld2ReportMessageAssembler(
                    records=list(icmp6_mlr2_multicast_address_record)
                ),
            )

            if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
                __debug__ and log(
                    "stack",
                    "Sent out ICMPv6 Multicast Listener Report message for "
                    f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}",
                )
            else:
                __debug__ and log(
                    "stack",
                    "Failed to send out ICMPv6 Multicast Listener Report message for "
                    f"{[_.multicast_address for _ in icmp6_mlr2_multicast_address_record]}, "
                    f"tx_status: {tx_status}",
                )

    def _send_icmp6_nd_dad_message(
        self, *, ip6_unicast_candidate: Ip6Address
    ) -> None:
        """
        Send out ICMPv6 ND Duplicate Address Detection message.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=Ip6Address(0),
            ip6__dst=ip6_unicast_candidate.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdNeighborSolicitationMessageAssembler(
                target_address=ip6_unicast_candidate,
                nd_options=[],  # ND DAD message has no options.
            ),
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log(
                "stack",
                f"Sent out ICMPv6 ND DAD message for {ip6_unicast_candidate}",
            )
        else:
            __debug__ and log(
                "stack",
                "Failed to send out ICMPv6 ND DAD message for "
                f"{ip6_unicast_candidate}, tx_status: {tx_status}",
            )

    def _send_icmp6_nd_router_solicitation(self) -> None:
        """
        Send out ICMPv6 ND Router Solicitation.
        """

        tx_status = self._phtx_icmp6(
            ip6__src=self.ip6_unicast[0],
            ip6__dst=Ip6Address("ff02::2"),
            ip6__hop=255,
            icmp6__message=Icmp6NdRouterSolicitationMessageAssembler(
                nd_options=[
                    Icmp6NdOptSllaAssembler(slla=self.mac_unicast),
                ],
            ),
        )

        if tx_status == TxStatus.PASSED__ETHERNET__TO_TX_RING:
            __debug__ and log("stack", "Sent out ICMPv6 ND Router Solicitation")
        else:
            __debug__ and log(
                "stack",
                f"Failed to send out ICMPv6 ND Router Solicitation, {tx_status}",
            )

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

    def send_udp_packet(
        self,
        *,
        ip__local_address: IpAddress,
        ip__remote_address: IpAddress,
        udp__local_port: int,
        udp__remote_port: int,
        udp__data: bytes | None = None,
    ) -> TxStatus:
        """
        Interface method for UDP Socket -> FPA communication.
        """

        return self._phtx_udp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            udp__sport=udp__local_port,
            udp__dport=udp__remote_port,
            udp__data=udp__data,
        )

    def send_tcp_packet(
        self,
        *,
        ip__local_address: IpAddress,
        ip__remote_address: IpAddress,
        tcp__local_port: int,
        tcp__remote_port: int,
        tcp__flag_syn: bool = False,
        tcp__flag_ack: bool = False,
        tcp__flag_fin: bool = False,
        tcp__flag_rst: bool = False,
        tcp__seq: int = 0,
        tcp__ack: int = 0,
        tcp__win: int = 0,
        tcp__wscale: int | None = None,
        tcp__mss: int | None = None,
        tcp__data: bytes | None = None,
    ) -> TxStatus:
        """
        Interface method for TCP Socket -> FPA communication.
        """

        return self._phtx_tcp(
            ip__src=ip__local_address,
            ip__dst=ip__remote_address,
            tcp__sport=tcp__local_port,
            tcp__dport=tcp__remote_port,
            tcp__flag_syn=tcp__flag_syn,
            tcp__flag_ack=tcp__flag_ack,
            tcp__flag_fin=tcp__flag_fin,
            tcp__flag_rst=tcp__flag_rst,
            tcp__seq=tcp__seq,
            tcp__ack=tcp__ack,
            tcp__win=tcp__win,
            tcp__wscale=tcp__wscale,
            tcp__mss=tcp__mss,
            tcp__data=tcp__data,
        )

    def send_icmp4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        icmp4__message: Icmp4Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv4 Socket -> FPA communication.
        """

        return self._phtx_icmp4(
            ip4__src=ip4__local_address,
            ip4__dst=ip4__remote_address,
            icmp4__message=icmp4__message,
        )

    def send_icmp6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__hop: int = 64,
        icmp6__message: Icmp6Message,
    ) -> TxStatus:
        """
        Interface method for ICMPv4 Socket -> FPA communication.
        """

        return self._phtx_icmp6(
            ip6__src=ip6__local_address,
            ip6__dst=ip6__remote_address,
            ip6__hop=ip6__hop,
            icmp6__message=icmp6__message,
        )
