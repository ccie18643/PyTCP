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
from ipaddress import AddressValueError

from ipv4_address import IPv4Address
from ipv6_address import IPv6Address


def inet_cksum(data, dptr, dlen, init=0):
    """Compute Internet Checksum used by IPv4/ICMPv4/ICMPv6/UDP/TCP protocols"""

    if dlen == 20:
        cksum = init + sum(struct.unpack_from("!5L", data, dptr))

    else:
        cksum = init + sum(struct.unpack_from(f"!{dlen >> 3}Q", data, dptr))
        if remainder := dlen & 7:
            cksum += struct.unpack("!Q", data[dptr + dlen - remainder : dptr + dlen] + b"\0" * (8 - remainder))[0]
        cksum = (cksum >> 64) + (cksum & 0xFFFFFFFFFFFFFFFF)

    cksum = (cksum >> 32) + (cksum & 0xFFFFFFFF)
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    return ~(cksum + (cksum >> 16)) & 0xFFFF


def ip_pick_version(ip_address):
    """Return correct IPv6Address or IPv4Address based on address string provided"""

    try:
        return IPv6Address(ip_address)
    except AddressValueError:
        return IPv4Address(ip_address)
