#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
stack.py - main TCP/IP stack program

"""

import os
import sys
import fcntl
import time
import struct
import loguru

from udp_socket import UdpSocket
from arp_cache import ArpCache
from rx_ring import RxRing
from tx_ring import TxRing

from ph import PacketHandler

from service_udp_echo_mt import ServiceUdpEcho


TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

STACK_INTERFACE = b"tap7"
STACK_IP_ADDRESS = "192.168.9.7"
STACK_MAC_ADDRESS = "02:00:00:77:77:77"


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

    arp_cache = ArpCache(STACK_MAC_ADDRESS, STACK_IP_ADDRESS)
    rx_ring = RxRing(tap, STACK_MAC_ADDRESS)
    tx_ring = TxRing(tap, STACK_MAC_ADDRESS, arp_cache)
    packet_handler = PacketHandler(STACK_MAC_ADDRESS, STACK_IP_ADDRESS, rx_ring, tx_ring, arp_cache)
    UdpSocket.set_packet_handler(packet_handler)
    ServiceUdpEcho(STACK_IP_ADDRESS)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
