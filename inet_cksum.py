#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
inet_cksum.py - module contains function used to compute Internet Checksum

"""


import struct


def compute_cksum(data):
    """ Compute Internet Checksum used by IP/TCP/UDP/ICMPv4 protocols """

    data = data + (b"\0" if len(data) & 1 else b"")
    cksum = sum(struct.unpack(f"! {len(data) >> 1}H", data))
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    return ~(cksum + (cksum >> 16)) & 0xFFFF
