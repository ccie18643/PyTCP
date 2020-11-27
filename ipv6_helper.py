#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ipv6_helper.py - module contains IPv6 helper functions

"""

from re import sub
from ipaddress import IPv6Interface, IPv6Network, IPv6Address


def ipv6_eui64(mac, prefix=IPv6Network("fe80::/64")):
    """ Create IPv6 EUI64 address """

    assert prefix.prefixlen == 64

    eui64 = sub(r"[.:-]", "", mac).lower()
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
    eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
    return IPv6Interface(str(prefix.network_address) + eui64 + "/" + str(prefix.prefixlen))


def ipv6_solicited_node_multicast(ipv6_address):
    """ Create IPv6 solicited node multicast address """

    return IPv6Address("ff02::1:ff" + ipv6_address.exploded[-7:])


def ipv6_multicast_mac(ipv6_multicast_address):
    """ Create IPv6 multicast MAC address """

    return "33:33:" + ":".join(["".join(ipv6_multicast_address.exploded[-9:].split(":"))[_ : _ + 2] for _ in range(0, 8, 2)])
