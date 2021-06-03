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
# pytcp.py - main TCP/IP stack program
#


import fcntl
import os
import struct
import sys
import time

import loguru

import config
from client.icmp_echo import ClientIcmpEcho
from client.tcp_echo import ClientTcpEcho
from misc.ph import PacketHandler
from misc.stack_cli_server import StackCliServer
from misc.timer import Timer
from service.tcp_daytime import ServiceTcpDaytime
from service.tcp_discard import ServiceTcpDiscard
from service.tcp_echo import ServiceTcpEcho
from service.udp_daytime import ServiceUdpDaytime
from service.udp_discard import ServiceUdpDiscard
from service.udp_echo import ServiceUdpEcho

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


def main() -> int:
    """Main function"""

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

    _logger = loguru.logger.bind(object_name="pytcp.")

    try:
        tap = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        _logger.error("Unable to access '/dev/net/tun' device")
        sys.exit(-1)

    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", config.interface, IFF_TAP | IFF_NO_PI))

    # Initialize stack components
    StackCliServer()
    Timer()
    PacketHandler(tap)

    # Set proper local IP address pattern for services depending on which version of IP is enabled
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
        ServiceTcpDaytime(local_ip_address=local_ip_address, message_count=-1, message_delay=1, message_size=5)

    # Initialize TCP test clients
    if config.client_tcp_echo:
        ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.102", remote_port=7, message_count=10)
        ClientTcpEcho(
            local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fedf:8537", remote_port=7, message_count=10
        )
        ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7)
        ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.9", remote_port=7)

    # Initialize ICMP test client
    if config.client_icmp_echo:
        # Same subnet, source address specified
        # ClientIcmpEcho(local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fedf:8537", message_count=10)
        # ClientIcmpEcho(local_ip_address="fe80::7", remote_ip_address="fe80::5054:ff:fe8b:aa9", message_count=10)

        # Same subnet, source address not specified
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fe8b:aa9", message_count=10)
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fe80::5054:ff:fe8b:aa9", message_count=10)

        # Another subnet, source address specified
        # ClientIcmpEcho(local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)
        # ClientIcmpEcho(local_ip_address="192.168.9.7", remote_ip_address="8.8.8.8", message_count=10)

        # Another subnet, source address not specified
        # ClientIcmpEcho(local_ip_address="::", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)
        ClientIcmpEcho(local_ip_address="0.0.0.0", remote_ip_address="8.8.8.8", message_count=5)
        ClientIcmpEcho(local_ip_address="::", remote_ip_address="2001:4860:4860::8888", message_count=25)

        # Another subnet, source with no default gateway assigned
        # ClientIcmpEcho(local_ip_address="2007::1111", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)

    while True:
        time.sleep(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
