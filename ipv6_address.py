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
# ipv6_address.py - module contains IPv6 address manipulation classes (extensions to ipaddress standard library)
#

import ipaddress
from re import sub


class IPv6Interface(ipaddress.IPv6Interface):
    """ Extensions for ipaddress.IPv6Address class """

    @property
    def ip(self):
        """ Make sure class returns overloaded IPv6Address object """

        return IPv6Address(super().ip)

    @property
    def host_address(self):
        """ Return host address """

        return self.ip

    @property
    def solicited_node_multicast(self):
        """ Create IPv6 solicited node multicast address """

        return self.ip.solicited_node_multicast

    @property
    def is_solicited_node_multicast(self):
        """ Check if address is IPv6 solicited node multicast address """

        return self.ip.is_solicited_node_multicast

    @property
    def is_unicast(self):
        """ Check if address is IPv6 unicast address """

        return self.ip.is_unicast

    @property
    def is_reserved(self):
        """ Check if address is IPv6 reserved address """

        return self.ip.is_reserved

    @property
    def is_unspecified(self):
        """ Check if address is IPv6 unspecified address """

        return self.ip.is_unspecified

    @property
    def is_multicast(self):
        """ Check if address is IPv6 multicast address """

        return self.ip.is_multicast


class IPv6Network(ipaddress.IPv6Network):
    """ Extensions for ipaddress.IPv6Network class """

    def eui64(self, mac):
        """ Create IPv6 EUI64 interface address """

        assert self.prefixlen == 64

        eui64 = sub(r"[.:-]", "", mac).lower()
        eui64 = eui64[0:6] + "fffe" + eui64[6:]
        eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
        eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
        return IPv6Interface(self.network_address.exploded[0:20] + eui64 + "/" + str(self.prefixlen))


class IPv6Address(ipaddress.IPv6Address):
    """ Extensions for ipaddress.IPv6Address class """

    @property
    def solicited_node_multicast(self):
        """ Create IPv6 solicited node multicast address """

        return IPv6Address("ff02::1:ff" + self.exploded[-7:])

    @property
    def is_solicited_node_multicast(self):
        """ Check if address is IPv6 solicited node multicast address """

        return str(self).startswith("ff02::1:ff")

    @property
    def is_unicast(self):
        """ Check if address is IPv6 unicast address """

        return not (self.is_multicast or self.is_unspecified)

    @property
    def multicast_mac(self):
        """ Create IPv6 multicast MAC address """

        assert self.is_multicast

        return "33:33:" + ":".join(["".join(self.exploded[-9:].split(":"))[_ : _ + 2] for _ in range(0, 8, 2)])
