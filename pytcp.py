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

import config
from lib.logger import log
from lib.timer import Timer
from misc.ph import PacketHandler
from misc.stack_cli_server import StackCliServer

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

    try:
        tap = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", config.interface, IFF_TAP | IFF_NO_PI))

    # Initialize stack components
    StackCliServer()
    Timer()
    PacketHandler(tap)

    #
    # Initialize test services and clients - uncomment what's needed
    #

    # from service.udp_echo import ServiceUdpEcho
    # ServiceUdpEcho(local_ip_address="::")
    # ServiceUdpEcho(local_ip_address="0.0.0.0")

    # from service.udp_discard import ServiceUdpDiscard
    # ServiceUdpDiscard(local_ip_address="::")
    # ServiceUdpDiscard(local_ip_address="0.0.0.0")

    # from service.udp_daytime import ServiceUdpDaytime
    # ServiceUdpDaytime(local_ip_address="::")
    # ServiceUdpDaytime(local_ip_address="0.0.0.0")

    from service.tcp_echo import ServiceTcpEcho

    ServiceTcpEcho(local_ip_address="::")
    ServiceTcpEcho(local_ip_address="0.0.0.0")

    # from service.tcp_discard import ServiceTcpDiscard
    # ServiceTcpDiscard(local_ip_address="::")
    # ServiceTcpDiscard(local_ip_address="0.0.0.0")

    # from service.tcp_daytime import ServiceTcpDaytime
    # ServiceTcpDaytime(local_ip_address="::")
    # ServiceTcpDaytime(local_ip_address="0.0.0.0")

    # from client.udp_echo import ClientUdpEcho
    # ClientUdpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.102", remote_port=7)
    # ClientUdpEcho(local_ip_address="0.0.0.0", remote_ip_address="192.168.9.102", message_count=10)
    # ClientUdpEcho(local_ip_address="::", remote_ip_address="2603:9000:e307:9f09:5054:ff:fedf:8537", remote_port=7, message_count=10)
    # ClientUdpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7)
    # ClientUdpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.9", remote_port=7)

    # from client.tcp_echo import ClientTcpEcho
    # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.102", remote_port=7)
    # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7, message_count=10)
    # ClientTcpEcho(local_ip_address="fdd1:c296:f24f:9:0:ff:fe77:7777", remote_ip_address="fdd1:c296:f24f:9:5054:ff:fedf:8537", remote_port=7, message_count=10)
    # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7)
    # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.9", remote_port=7)

    # from client.icmp_echo import ClientIcmpEcho
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
    # ClientIcmpEcho(local_ip_address="0.0.0.0", remote_ip_address="8.8.8.8", message_count=5)
    # ClientIcmpEcho(local_ip_address="::", remote_ip_address="2600::", message_count=25)

    # Another subnet, source with no default gateway assigned
    # ClientIcmpEcho(local_ip_address="2007::1111", remote_ip_address="fdd1:c296:f24f:100:5054:ff:fef9:99aa", message_count=10)

    while True:
        time.sleep(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
