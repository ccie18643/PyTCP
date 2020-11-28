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
# pytcp.py - main TCP/IP stack program
#


import fcntl
import os
import struct
import sys
import time
from ipaddress import IPv4Interface, IPv6Interface, IPv6Network

import loguru

import stack
from arp_cache import ArpCache
from client_icmpv4_echo import ClientICMPv4Echo
from client_tcp_echo import ClientTcpEcho
from client_udp_dhcp import ClientUdpDhcp
from icmpv6_nd_cache import ICMPv6NdCache
from ipv6_helper import ipv6_eui64
from ph import PacketHandler
from rx_ring import RxRing
from service_tcp_daytime import ServiceTcpDaytime
from service_tcp_discard import ServiceTcpDiscard
from service_tcp_echo import ServiceTcpEcho
from service_udp_daytime import ServiceUdpDaytime
from service_udp_discard import ServiceUdpDiscard
from service_udp_echo import ServiceUdpEcho
from stack_timer import StackTimer
from tx_ring import TxRing

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


########################################################
#                                                      #
#  For any configuration options edit 'stack.py' file  #
#                                                      #
#  For the TAP interface configuration check the       #
#  'setup_tap.sh script'                               #
#                                                      #
########################################################


def main():
    """ Main function """

    loguru.logger.remove(0)
    loguru.logger.add(
        sys.stdout,
        colorize=True,
        level="DEBUG",
        format="<green>{time:YY-MM-DD HH:mm:ss}</green> <level>| {level:7} "
        + "|</level> <level> <normal><cyan>{extra[object_name]}{function}:</cyan></normal> {message}</level>",
    )

    loguru.logger.add(
        "log",
        mode="w",
        level="DEBUG",
        format="<green>{time:YY-MM-DD HH:mm:ss}</green> <level>| {level:7} "
        + "|</level> <level> <normal><cyan>{extra[object_name]}{function}:</cyan></normal> {message}</level>",
    )

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", stack.interface, IFF_TAP | IFF_NO_PI))

    # Initialize stack components
    StackTimer()
    RxRing(tap)
    TxRing(tap)
    ArpCache()
    ICMPv6NdCache()
    PacketHandler()

    # Set proper local IP address pattern for services depending on whch version of IP is enabled
    if stack.ipv6_support and stack.ipv4_support:
        local_ip_address = "*"
    elif stack.ipv6_support:
        local_ip_address = "::"
    elif stack.ipv4_support:
        local_ip_address = "0.0.0.0"

    # Initialize UDP test services
    stack.service_udp_echo and ServiceUdpEcho(local_ip_address=local_ip_address)
    stack.service_udp_discard and ServiceUdpDiscard(local_ip_address=local_ip_address)
    stack.service_udp_daytime and ServiceUdpDaytime(local_ip_address=local_ip_address)

    # Initialize TCP test services
    stack.service_tcp_echo and ServiceTcpEcho(local_ip_address=local_ip_address)
    stack.service_tcp_discard and ServiceTcpDiscard(local_ip_address=local_ip_address)
    stack.service_tcp_daytime and ServiceTcpDaytime(local_ip_address=local_ip_address, message_count=-1, message_delay=1, message_size=1000)

    # Initialize TCP test clients
    stack.client_tcp_echo and ClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="192.168.9.102", remote_port=7, message_count=10)
    # stack.client_tcp_echo andClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="1.1.1.1", remote_port=7)
    # stack.client_tcp_echo andClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="192.168.9.9", remote_port=7)

    # Initialize ICMPv4 test clients
    stack.client_icmpv4_echo and ClientICMPv4Echo(local_ipv4_address="192.168.9.7", remote_ipv4_address="8.8.8.8")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
