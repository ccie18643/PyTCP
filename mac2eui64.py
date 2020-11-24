#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
mac2eui64.py - module contains function used to create IPv6 address based on MAC address

"""

from ipaddress import IPv6Address
import re


def mac2eui64(mac, prefix="ff80::"):
    """ Conver MAC address to IPv6 EUI64 address """

    eui64 = re.sub(r"[.:-]", "", mac).lower()
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
    eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
    return IPv6Address(prefix + eui64)
