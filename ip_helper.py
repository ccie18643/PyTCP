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
# ip_helper.py - module contains IPv6 helper functions
#


import struct
from ipaddress import AddressValueError, IPv4Address, IPv6Address, IPv6Interface, IPv6Network
from re import sub

import stack


def inet_cksum(data):
    """ Compute Internet Checksum used by IP/TCP/UDP/ICMPv4 protocols """

    data = data + (b"\0" if len(data) & 1 else b"")
    cksum = sum(struct.unpack(f"! {len(data) >> 1}H", data))
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    return ~(cksum + (cksum >> 16)) & 0xFFFF


def ip6_eui64(mac, prefix=IPv6Network("fe80::/64")):
    """ Create IPv6 EUI64 address """

    assert prefix.prefixlen == 64

    eui64 = sub(r"[.:-]", "", mac).lower()
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
    eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
    return IPv6Interface(prefix.network_address.exploded[0:20] + eui64 + "/" + str(prefix.prefixlen))


def ip6_solicited_node_multicast(ip6_address):
    """ Create IPv6 solicited node multicast address """

    return IPv6Address("ff02::1:ff" + ip6_address.exploded[-7:])


def ip6_is_solicited_node_multicast(ip6_address):
    """ Check if address is IPv6 solicited node multicast address """

    return str(ip6_address).startswith("ff02::1:ff")


def ip6_is_unicast(ip6_address):
    """ Check if address is IPv6 unicast address """

    return not (ip6_address.is_multicast or ip6_address.is_unspecified)


def ip6_multicast_mac(ip6_multicast_address):
    """ Create IPv6 multicast MAC address """

    return "33:33:" + ":".join(["".join(ip6_multicast_address.exploded[-9:].split(":"))[_ : _ + 2] for _ in range(0, 8, 2)])


def find_stack_ip6_address(ip6_unicast):
    """ Find stack address that belongs to the same subnet as given unicast address """

    for stack_ip6_address in stack.packet_handler.stack_ip6_address:
        if ip6_unicast in stack_ip6_address.network:
            return stack_ip6_address
    return None


def find_stack_ip4_address(ip4_unicast):
    """ Find stack address that belongs to the same subnet as given unicast address """

    for stack_ip4_address in stack.packet_handler.stack_ip4_address:
        if ip4_unicast in stack_ip4_address.network:
            return stack_ip4_address
    return None


def ip_pick_version(ip_address):
    """ Return correct IPv6Address or IPv4Address based on address string provided """

    try:
        return IPv6Address(ip_address)
    except AddressValueError:
        return IPv4Address(ip_address)
