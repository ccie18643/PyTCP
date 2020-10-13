#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
arp.py - arp protocol implementation

"""

import sys
import socket
import struct
import binascii

from ethernet_packet import EthernetPacket
from arp_packet import ArpPacket


def initialize_tap_interface(ip_address, ip_mask, mtu=1500):
    """ Initialize TAP interface with given subnet """

    from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI

    tap = TunTapDevice(flags=IFF_TAP|IFF_NO_PI)
    tap.addr = ip_address
    tap.netmask = ip_mask
    tap.mtu = mtu
    tap.up()

    return tap


def main():

    tap = initialize_tap_interface("10.0.0.1", "255.255.255.0")

    while True:

        raw_packet = tap.read(tap.mtu)

        if struct.unpack("!H", raw_packet[12:14])[0] >= 0x0600:
            ethernet_packet = EthernetPacket(raw_packet)

            if ethernet_packet.type == 0x0806:
                print(ethernet_packet)
                print(ArpPacket(ethernet_packet.packet_data))
                print("-" * 80)

if __name__ == "__main__":
    sys.exit(main())



