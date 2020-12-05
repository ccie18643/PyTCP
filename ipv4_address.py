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
# ipv4_address.py - module contains IPv4 address manipulation classes (extensions to ipaddress standard library)
#

import ipaddress


class IPv4Interface(ipaddress.IPv4Interface):
    """ Extensions for ipaddress.IPv4Address class """

    @property
    def ip(self):
        """ Make sure class returns overloaded IPv6Address object """

        return IPv4Address(super().ip)

    @property
    def host_address(self):
        """ Return host address """

        return self.ip

    @property
    def network_address(self):
        """ Return network address """

        return IPv4Address(self.network.network_address)

    @property
    def broadcast_address(self):
        """ Return broadcast address """

        return IPv4Address(self.network.broadcast_address)

    @property
    def is_limited_broadcast(self):
        """ Check if IPv4 address is a limited broadcast """

        return str(super().ip) == "255.255.255.255"


class IPv4Network(ipaddress.IPv4Network):
    """ Extensions for ipaddress.IPv4Network class """

    pass


class IPv4Address(ipaddress.IPv4Address):
    """ Extensions for ipaddress.IPv4Address class """

    @property
    def is_limited_broadcast(self):
        """ Check if IPv4 address is a limited broadcast """

        return str(self) == "255.255.255.255"
