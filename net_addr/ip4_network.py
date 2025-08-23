#!/usr/bin/env python3

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
This module contains IPv4 network support class.

net_addr/ip4_network.py

ver 3.0.3
"""


from typing import Self, override

from net_addr.errors import (
    Ip4AddressFormatError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
)
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip_address import IpVersion
from net_addr.ip_network import IpNetwork


class Ip4Network(IpNetwork[Ip4Address, Ip4Mask]):
    """
    IPv4 network support class.
    """

    __slots__ = ()

    _version = IpVersion.IP4

    def __init__(
        self,
        network: Self | tuple[Ip4Address, Ip4Mask] | str | None = None,
        /,
    ) -> None:
        """
        Create a new IPv4 network object.
        """

        if network is None:
            self._address = Ip4Address()
            self._mask = Ip4Mask()
            return

        if isinstance(network, tuple):
            self._mask = network[1]
            self._address = Ip4Address(int(network[0]) & int(network[1]))
            return

        if isinstance(network, str):
            try:
                try:
                    address, mask = network.split("/")
                    mask = f"/{mask}"
                except ValueError:
                    address, mask = network.split(" ")
                self._mask = Ip4Mask(mask)
                self._address = Ip4Address(
                    int(Ip4Address(address)) & int(self._mask)
                )
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        if isinstance(network, Ip4Network):
            self._mask = network.mask
            self._address = Ip4Address(int(network.address) & int(network.mask))
            return

        raise Ip4NetworkFormatError(network)

    @property
    @override
    def last(self) -> Ip4Address:
        """
        Last address in the network.
        """

        return Ip4Address(int(self._address) + (~int(self._mask) & 0xFFFFFFFF))

    @property
    def broadcast(self) -> Ip4Address:
        """
        Broadcast address (same as last address in the network).
        """

        return self.last
