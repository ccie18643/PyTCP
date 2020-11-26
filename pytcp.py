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

from ipaddress import IPv4Interface, IPv6Interface

from stack_timer import StackTimer
from arp_cache import ArpCache
from icmpv6_nd_cache import ICMPv6NdCache
from rx_ring import RxRing
from tx_ring import TxRing

from ph import PacketHandler

from service_udp_echo import ServiceUdpEcho
from service_udp_discard import ServiceUdpDiscard
from service_udp_daytime import ServiceUdpDaytime

from service_tcp_echo import ServiceTcpEcho
from service_tcp_discard import ServiceTcpDiscard
from service_tcp_daytime import ServiceTcpDaytime

from client_udp_dhcp import ClientUdpDhcp
from client_tcp_echo import ClientTcpEcho
from client_icmpv4_echo import ClientIcmpEcho

from ipv6_helper import ipv6_eui64

import stack


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_INTERFACE = b"tap7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"

STACK_IPV6_ADDRESS_CANDIDATE = [
    # IPv6Interface("FE80::7/64"),
    # IPv6Interface("FE80::77/64"),
    # IPv6Interface("FE80::777/64"),
    # IPv6Interface("FE80::7777/64"),
    IPv6Interface("2007::7/64"),
    IPv6Interface("2007::7/64"),
    ipv6_eui64(STACK_MAC_ADDRESS, prefix="2007::/64"),
]

STACK_IPV4_ADDRESS_CANDIDATE = [
    IPv4Interface("192.168.9.7/24"),
    IPv4Interface("192.168.9.77/24"),
    IPv4Interface("192.168.9.102/24"),
    IPv4Interface("172.16.0.7/16"),
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

    loguru.logger.add(
        "log",
        mode="w",
        level="DEBUG",
        format="<green>{time:YY-MM-DD HH:mm:ss}</green> <level>| {level:7} "
        + "|</level> <level> <normal><cyan>{extra[object_name]}{function}:</cyan></normal> {message}</level>",
    )

    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", STACK_INTERFACE, IFF_TAP | IFF_NO_PI))

    stack.stack_timer = StackTimer()
    stack.rx_ring = RxRing(tap)
    stack.tx_ring = TxRing(tap)
    stack.arp_cache = ArpCache()
    stack.icmpv6_nd_cache = ICMPv6NdCache()
    stack.packet_handler = PacketHandler(
        stack_mac_address=STACK_MAC_ADDRESS,
        stack_ipv6_support=True,
        stack_ipv6_address_candidate=STACK_IPV6_ADDRESS_CANDIDATE,
        stack_ipv4_support=False,
        stack_ipv4_address_candidate=STACK_IPV4_ADDRESS_CANDIDATE,
    )

    # ServiceUdpEcho()
    # ServiceUdpDiscard()
    # ServiceUdpDaytime()

    ServiceTcpEcho()
    ServiceTcpDiscard()
    ServiceTcpDaytime(message_count=-1, message_delay=1, message_size=1000)

    # ClientUdpDhcp(STACK_MAC_ADDRESS)
    # ClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="192.168.9.102", remote_port=7, message_count=10)
    # ClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="1.1.1.1", remote_port=7)
    # ClientTcpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="192.168.9.9", remote_port=7)
    # ClientIcmpEcho(local_ipv4_address="192.168.9.7", remote_ipv4_address="8.8.8.8")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
