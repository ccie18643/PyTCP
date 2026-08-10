################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains IPv4 interface address support class.

net_addr/ip4_ifaddr.py

ver 3.0.9
"""

from typing import ClassVar, Self, final

from net_addr.errors import (
    Ip4AddressFormatError,
    Ip4IfAddrFormatError,
    Ip4IfAddrSanityError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
    NetAddrError,
)
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_version import IpVersion


@final
class Ip4IfAddr(IfAddr[Ip4Address, Ip4Network]):
    """
    IPv4 interface address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    _sanity_error: ClassVar[type[NetAddrError]] = Ip4IfAddrSanityError

    def __init__(
        self,
        host: Self | tuple[Ip4Address, Ip4Network] | tuple[Ip4Address, Ip4Mask] | str,
        /,
    ) -> None:
        """
        Initialize the IPv4 interface address object.
        """

        if isinstance(host, Ip4IfAddr):
            self._address = host.address
            self._network = host.network
            return

        if isinstance(host, tuple):
            tuple_address, network_or_mask = host
            self._address = tuple_address
            if isinstance(network_or_mask, Ip4Network):
                self._network = network_or_mask
                if self._address not in self._network:
                    raise Ip4IfAddrSanityError(f"The IPv4 address doesn't belong to the provided network: {host!r}")
            elif isinstance(network_or_mask, Ip4Mask):
                # Containment holds by construction: the network
                # is derived by masking this same address.
                self._network = Ip4Network((tuple_address, network_or_mask))
            else:
                raise Ip4IfAddrFormatError(host)
            return

        if isinstance(host, str):
            try:
                # Accept both the CIDR 'addr/prefix' form and the
                # standard IPv4 'addr netmask' space form, matching
                # what Ip4Network parses. Surrounding whitespace is
                # stripped uniformly across every net_addr string
                # constructor.
                text = host.strip()
                address = text.split("/", 1)[0] if "/" in text else text.split(" ", 1)[0]
                self._address = Ip4Address(address)
                # No 'address in network' sanity check here (unlike
                # the tuple form): the network is derived by masking
                # this same host string, so containment holds by
                # construction.
                self._network = Ip4Network(text)
                return
            except (Ip4AddressFormatError, Ip4MaskFormatError, Ip4NetworkFormatError) as error:
                raise Ip4IfAddrFormatError(host) from error

        raise Ip4IfAddrFormatError(host)
