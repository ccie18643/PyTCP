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

import loguru

import config
from arp_cache import ArpCache
from client_icmp_echo import ClientIcmpEcho
from client_tcp_echo import ClientTcpEcho
from icmp6_nd_cache import ICMPv6NdCache
from ipv4_address import IPv4Address, IPv4Interface
from ipv6_address import IPv6Address, IPv6Interface
from ph import PacketHandler
from rx_ring import RxRing
from service_tcp_daytime import ServiceTcpDaytime
from service_tcp_discard import ServiceTcpDiscard
from service_tcp_echo import ServiceTcpEcho
from service_udp_daytime import ServiceUdpDaytime
from service_udp_discard import ServiceUdpDiscard
from service_udp_echo import ServiceUdpEcho
from stack_cli_server import StackCliServer
from timer import Timer
from tx_ring import TxRing

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


#########################################################
#                                                       #
#  For any configuration options edit 'config.py' file  #
#                                                       #
#  For the TAP interface configuration check the        #
#  'setup_tap.sh script'                                #
#                                                       #
#########################################################


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
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", config.interface, IFF_TAP | IFF_NO_PI))

    # Initialize stack components
    StackCliServer()
    Timer()
    RxRing(tap)
    TxRing(tap)
    ArpCache()
    ICMPv6NdCache()
    PacketHandler()

    # Set proper local IP address pattern for services depending on whch version of IP is enabled
    if config.ip6_support and config.ip4_support:
        local_ip_address = "*"
    elif config.ip6_support:
        local_ip_address = "::"
    elif config.ip4_support:
        local_ip_address = "0.0.0.0"

    # Initialize UDP test services
    if config.service_udp_echo:
        ServiceUdpEcho(local_ip_address=local_ip_address)
    if config.service_udp_discard:
        ServiceUdpDiscard(local_ip_address=local_ip_address)
    if config.service_udp_daytime:
        ServiceUdpDaytime(local_ip_address=local_ip_address)

    # Initialize TCP test services
    if config.service_tcp_echo:
        ServiceTcpEcho(local_ip_address=local_ip_address)
    if config.service_tcp_discard:
        ServiceTcpDiscard(local_ip_address=local_ip_address)
    if config.service_tcp_daytime:
        ServiceTcpDaytime(local_ip_address=local_ip_address, message_count=-1, message_delay=1, message_size=1000)

    # Initialize TCP test clients
    if config.client_tcp_echo:
        ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.100.102", remote_port=7, message_count=10)
        ClientTcpEcho(
            local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fedf:8537", remote_port=7, message_count=10
        )
        # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7)
        # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.9", remote_port=7)

    # Initialize ICMP test client
    if config.client_icmp_echo:
        # Same subnet, source addess specified
        # ClientIcmpEcho(local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fedf:8537", message_count=10)
        # ClientIcmpEcho(local_ip_address="fe80::7", remote_ip_address="fe80::5054:ff:fe8b:aa9", message_count=10)

        # Same subnet, source addess not specified
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fe8b:aa9", message_count=10)
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fe80::5054:ff:fe8b:aa9", message_count=10)

        # Another subnet, source address specified
        # ClientIcmpEcho(local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)
        # ClientIcmpEcho(local_ip_address="192.168.9.7", remote_ip_address="8.8.8.8", message_count=10)

        # Another subnet, source address not specified
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)
        ClientIcmpEcho(local_ip_address="0.0.0.0", remote_ip_address="8.8.8.8", message_count=25)
        ClientIcmpEcho(local_ip_address="::", remote_ip_address="2001:4860:4860::8888", message_count=25)

        # Another subnet, source with no default gateway assigned
        # ClientIcmpEcho(local_ip_address="2007::1111", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
