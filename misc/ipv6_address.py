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


#
# misc/ipv6_address.py - module contains IPv6 address manipulation classes (extensions to ipaddress standard library)
#

from __future__ import annotations  # Required for Python version lower than 3.10

import ipaddress
from re import sub


class IPv6Address(ipaddress.IPv6Address):
    """Extensions for ipaddress.IPv6Address class"""

    def __init__(self, ip6_address: ipaddress.IPv6Address | str | int | bytes) -> None:
        """Class constructor"""

        super().__init__(ip6_address)

    @property
    def solicited_node_multicast(self) -> IPv6Address:
        """Create IPv6 solicited node multicast address"""

        return IPv6Address("ff02::1:ff" + self.exploded[-7:])

    @property
    def is_solicited_node_multicast(self) -> bool:
        """Check if address is IPv6 solicited node multicast address"""

        return str(self).startswith("ff02::1:ff")

    @property
    def is_unicast(self) -> bool:
        """Check if address is IPv6 unicast address"""

        return not (self.is_multicast or self.is_unspecified)

    @property
    def multicast_mac(self) -> str:
        """Create IPv6 multicast MAC address"""

        assert self.is_multicast

        return "33:33:" + ":".join(["".join(self.exploded[-9:].split(":"))[_ : _ + 2] for _ in range(0, 8, 2)])


class IPv6Network(ipaddress.IPv6Network):
    """Extensions for ipaddress.IPv6Network class"""

    def __init__(self, ip6_network: ipaddress.IPv6Network | str | int | tuple[bytes, int]) -> None:
        """Class constructor"""

        super().__init__(ip6_network)

    def eui64(self, mac: str) -> IPv6Interface:
        """Create IPv6 EUI64 interface address"""

        assert self.prefixlen == 64

        eui64 = sub(r"[.:-]", "", mac).lower()
        eui64 = eui64[0:6] + "fffe" + eui64[6:]
        eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]
        eui64 = ":".join(eui64[_ : _ + 4] for _ in range(0, 16, 4))
        return IPv6Interface(self.network_address.exploded[0:20] + eui64 + "/" + str(self.prefixlen))


class IPv6Interface(ipaddress.IPv6Interface):
    """Extensions for ipaddress.IPv6Address class"""

    def __init__(self, ip6_interface: ipaddress.IPv6Interface | str) -> None:
        """Class constructor"""

        self.gateway: IPv6Address | None = None

        super().__init__(ip6_interface)

    @property
    def ip(self) -> ipaddress.IPv6Address:
        """Make sure class returns overloaded IPv6Address object"""

        return IPv6Address(super().ip)

    @property
    def host_address(self) -> ipaddress.IPv6Address:
        """Return host address"""

        return self.ip

    @property
    def solicited_node_multicast(self) -> ipaddress.IPv6Address:
        """Create IPv6 solicited node multicast address"""

        return IPv6Address(super().ip).solicited_node_multicast

    @property
    def is_solicited_node_multicast(self) -> bool:
        """Check if address is IPv6 solicited node multicast address"""

        return IPv6Address(super().ip).is_solicited_node_multicast

    @property
    def is_unicast(self) -> bool:
        """Check if address is IPv6 unicast address"""

        return IPv6Address(super().ip).is_unicast

    @property
    def is_reserved(self) -> bool:
        """Check if address is IPv6 reserved address"""

        return IPv6Address(super().ip).is_reserved

    @property
    def is_unspecified(self) -> bool:
        """Check if address is IPv6 unspecified address"""

        return IPv6Address(super().ip).is_unspecified

    @property
    def is_multicast(self) -> bool:
        """Check if address is IPv6 multicast address"""

        return IPv6Address(super().ip).is_multicast
