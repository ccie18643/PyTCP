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
Module holds references to the stack components and global structures.

pytcp/stack/__init__.py

ver 3.0.2
"""


from __future__ import annotations

import fcntl
import os
import struct
import sys
from typing import TYPE_CHECKING, Any

from net_addr.ip4_host import Ip4Host
from net_addr.ip6_host import Ip6Host
from net_addr.mac_address import MacAddress

from pytcp.lib.logger import log

from .arp_cache import ArpCache
from .nd_cache import NdCache
from .packet_handler import PacketHandler
from .rx_ring import RxRing
from .timer import Timer
from .tx_ring import TxRing

if TYPE_CHECKING:
    from net_addr import Ip4Address
    from pytcp.socket.socket import Socket


# Interface configuration.
INTERFACE__TAP__MTU = 1500
INTERFACE__TUN__MTU = 1500

# Addresses configuration.
MAC_ADDRESS = "02:00:00:77:77:77"
IP4_ADDRESS = None
IP4_GATEWAY = None
IP6_ADDRESS = None
IP6_GATEWAY = None

# Protocol support configuration.
IP6__SUPPORT_ENABLED = True
IP4__SUPPORT_ENABLED = True

# ARP cache configuration.
ARP__CACHE__ENTRY_MAX_AGE = 3600
ARP__CACHE__ENTRY_REFRESH_TIME = 300
ARP__CACHE__UPDATE_FROM_DIRECT_REQUEST = True
ARP__CACHE__UPDATE_FROM_GRATUITIOUS_REPLY = True

# ICMPv6 ND cache configuration.
ICMP6__ND__CACHE__ENTRY_MAX_AGE = 3600
ICMP6__ND__CACHE__ENTRY_REFRESH_TIME = 300

# Logger configuration - LOG__CHANNEL sets which subsystems of stack log to the
# console, LOG__DEBUG adds info about class/method caller.
# Following subsystems are supported:
# stack, timer, rx-ring, tx-ring, arp-c, nd-c, ether, arp, ip4, ip6, icmp4,
# icmp6, udp, tcp, socket, tcp-ss, service.
LOG__CHANNEL = {
    "stack",
    #    "timer",
    "rx-ring",
    "tx-ring",
    "arp-c",
    "nd-c",
    "ether",
    "arp",
    "ip4",
    "ip6",
    "icmp4",
    "icmp6",
    "udp",
    "tcp",
    "socket",
    "tcp-ss",
    "dhcp4",
    "service",
    "client",
}
LOG__DEBUG = False

version_string = "ver 3.0.2"
github_repository = "https://github.com/ccie18643/PyTCP"

timer: Timer
rx_ring: RxRing
tx_ring: TxRing
arp_cache: ArpCache
nd_cache: NdCache
packet_handler: PacketHandler

interface_mtu: int

sockets: dict[tuple[Any, ...], Socket] = {}

arp_probe_unicast_conflict: set[Ip4Address] = set()


def initialize_interface(interface_name: str, /) -> tuple[int, int]:
    """
    Initialize the TAP/TUN interface.
    """

    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    match interface_name[0:3].lower():
        case "tap":
            interface_type = IFF_TAP
            mtu = INTERFACE__TAP__MTU
        case "tun":
            interface_type = IFF_TUN
            mtu = INTERFACE__TUN__MTU
        case _:
            raise ValueError(
                "Interface name must start with 'tap' or 'tun'"
                f"Got: {interface_name!r}"
            )

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack(
            "16sH", interface_name.encode(), interface_type | IFF_NO_PI
        ),
    )

    return fd, mtu


def mock__init(
    *,
    mock__timer: Timer | None = None,
    mock__tx_ring: TxRing | None = None,
    mock__rx_ring: RxRing | None = None,
    mock__arp_cache: ArpCache | None = None,
    mock__nd_cache: NdCache | None = None,
    mock__packet_handler: PacketHandler | None = None,
) -> None:
    """
    Initialize stack components for unit testing.
    """

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler

    if mock__timer is not None:
        timer = mock__timer

    if mock__tx_ring is not None:
        tx_ring = mock__tx_ring

    if mock__rx_ring is not None:
        rx_ring = mock__rx_ring

    if mock__arp_cache is not None:
        arp_cache = mock__arp_cache

    if mock__nd_cache is not None:
        nd_cache = mock__nd_cache

    if mock__packet_handler is not None:
        packet_handler = mock__packet_handler


def init(
    fd: int,
    mtu: int = 1500,
    *,
    mac_address: MacAddress | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4Host | None = (
        None
        if IP4_ADDRESS is None
        else Ip4Host(IP4_ADDRESS, gateway=IP4_GATEWAY)  # type: ignore
    ),
    ip4_dhcp: bool = True if IP4_ADDRESS is None else False,
    ip6_support: bool = True,
    ip6_host: Ip6Host | None = (
        None
        if IP6_ADDRESS is None
        else Ip4Host(IP6_ADDRESS, gateway=IP6_GATEWAY)  # type: ignore
    ),
    ip6_gua_autoconfig: bool = True if IP6_ADDRESS is None else False,
    ip6_lla_autoconfig: bool = True,
) -> None:
    """
    Initialize stack components.
    """

    if mac_address is None:
        mac_address = MacAddress(MAC_ADDRESS)

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler, interface_mtu

    timer = Timer()
    tx_ring = TxRing(
        fd=fd,
        mtu=mtu,
    )
    rx_ring = RxRing(
        fd=fd,
        mtu=mtu,
    )
    arp_cache = ArpCache()
    nd_cache = NdCache()
    packet_handler = PacketHandler(
        mac_address=mac_address,
        interface_mtu=mtu,
        ip4_support=ip4_support,
        ip4_host=ip4_host,
        ip4_dhcp=ip4_dhcp,
        ip6_support=ip6_support,
        ip6_host=ip6_host,
        ip6_gua_autoconfig=ip6_gua_autoconfig,
        ip6_lla_autoconfig=ip6_lla_autoconfig,
    )

    interface_mtu = mtu


def start() -> None:
    """
    Start stack components.
    """

    timer.start()
    arp_cache.start()
    nd_cache.start()
    tx_ring.start()
    rx_ring.start()
    packet_handler.start()


def stop() -> None:
    """
    Stop stack components.
    """

    packet_handler.stop()
    rx_ring.stop()
    tx_ring.stop()
    arp_cache.stop()
    nd_cache.stop()
    timer.stop()
