#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
pytcp.py - main TCP/IP stack program

"""

import os
import sys
import fcntl
import time
import struct
import loguru


from stack_timer import StackTimer
from arp_cache import ArpCache
from rx_ring import RxRing
from tx_ring import TxRing

from ph import PacketHandler

from service_udp_echo import ServiceUdpEcho
from service_udp_discard import ServiceUdpDiscard
from service_udp_daytime import ServiceUdpDaytime

from service_tcp_echo import ServiceTcpEcho
from service_tcp_discard import ServiceTcpDiscard
from service_tcp_daytime import ServiceTcpDaytime

# from client_udp_dhcp import ClientUdpDhcp
from client_tcp_echo import ClientTcpEcho

import stack


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_INTERFACE = b"tap7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"
STACK_IP_ADDRESS = [
    ("192.168.9.7", "255.255.255.0"),
    ("192.168.9.7", "255.255.255.0"),
    ("192.168.9.102", "255.255.255.0"),
    ("192.168.9.9", "255.255.255.0"),
    ("172.16.128.65", "255.255.255.240"),
]


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

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", STACK_INTERFACE, IFF_TAP | IFF_NO_PI))

    stack.stack_timer = StackTimer()
    stack.rx_ring = RxRing(tap, STACK_MAC_ADDRESS)
    stack.tx_ring = TxRing(tap, STACK_MAC_ADDRESS)
    stack.arp_cache = ArpCache()
    stack.packet_handler = PacketHandler(STACK_MAC_ADDRESS, STACK_IP_ADDRESS)

    # Start 'userspace' services / clinets
    # ServiceUdpEcho()
    # ServiceUdpDiscard()
    # ServiceUdpDaytime()

    # ServiceTcpEcho()
    # ServiceTcpDiscard()
    # ServiceTcpDaytime()

    # ClientUdpDhcp(STACK_MAC_ADDRESS)
    # ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="192.168.9.102", remote_port=7)
    ClientTcpEcho(local_ip_address="192.168.9.7", remote_ip_address="1.1.1.1", remote_port=7)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
