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


"""
Module contains the main PyTCP stack class.

pytcp/__init__.py

ver 2.7
"""


import fcntl
import os
import struct
import sys

from pytcp import config
from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address, Ip4Host
from pytcp.lib.ip6_address import Ip6Address, Ip6Host
from pytcp.lib.logger import log
from pytcp.lib.mac_address import MacAddress

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def initialize_tap(*, tap_name: str) -> tuple[int, int]:
    """
    Initialize the TAP interface.
    """

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", tap_name.encode(), IFF_TAP | IFF_NO_PI),
    )

    return fd, fd


class TcpIpStack:
    """
    Main PyTCP library class.
    """

    def __init__(
        self,
        *,
        fd: tuple[int, int],
        mac_address: str | None = None,
        ip4_address: str | None = None,
        ip4_gateway: str | None = None,
        ip6_address: str | None = None,
        ip6_gateway: str | None = None,
    ):
        """
        Initialize stack on given interface.
        """

        # Set the MAC address.
        if mac_address is not None:
            stack.packet_handler.assign_mac_address(
                mac_unicast=MacAddress(mac_address)
            )

        # Set the IPv4 address.
        if ip4_address is None:
            config.IP4_SUPPORT = True
            config.IP4_HOST_DHCP = True
        else:
            ip4_host = Ip4Host(ip4_address)
            if ip4_gateway:
                ip4_host.gateway = Ip4Address(ip4_gateway)
            stack.packet_handler.assign_ip4_address(ip4_host)
            config.IP4_SUPPORT = True
            config.IP4_HOST_DHCP = False

        # Set the IPv6 address.
        if ip6_address is None:
            config.IP6_SUPPORT = True
            config.IP6_LLA_AUTOCONFIG = True
            config.IP6_GUA_AUTOCONFIG = True
        else:
            ip6_host = Ip6Host(ip6_address)
            if ip6_gateway:
                ip6_host.gateway = Ip6Address(ip6_gateway)
            stack.packet_handler.assign_ip6_address(ip6_host)
            config.IP6_SUPPORT = True
            config.IP6_LLA_AUTOCONFIG = True
            config.IP6_GUA_AUTOCONFIG = False
        self.rx_fd = fd[0]
        self.tx_fd = fd[1]

    def start(self) -> None:
        """
        Start stack components.
        """
        stack.timer.start()
        stack.arp_cache.start()
        stack.nd_cache.start()
        stack.rx_ring.start(self.rx_fd)
        stack.tx_ring.start(self.tx_fd)
        stack.packet_handler.start()
        stack.packet_handler.acquire_ip6_addresses()
        stack.packet_handler.acquire_ip4_addresses()
        stack.packet_handler.log_stack_address_info()

    def stop(self) -> None:
        """
        Stop stack components.
        """
        stack.packet_handler.stop()
        stack.tx_ring.stop()
        stack.rx_ring.stop()
        stack.arp_cache.stop()
        stack.nd_cache.stop()
        stack.timer.stop()
