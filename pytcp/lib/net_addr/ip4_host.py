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
Module contains IPv4 host support class.

pytcp/lib/net_addr/ip4_host.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from .errors import (
    Ip4AddressFormatError,
    Ip4HostFormatError,
    Ip4HostGatewayError,
    Ip4MaskFormatError,
)
from .ip4_address import Ip4Address
from .ip4_mask import Ip4Mask
from .ip4_network import Ip4Network
from .ip_host import IpHost


class Ip4Host(IpHost):
    """
    IPv4 host support class.
    """

    def __init__(
        self,
        host: (
            Ip4Host
            | tuple[Ip4Address, Ip4Network]
            | tuple[Ip4Address, Ip4Mask]
            | str
        ),
    ) -> None:
        """
        Class constructor.
        """

        self._address: Ip4Address
        self._network: Ip4Network
        self._version: int = 4

        self._gateway: Ip4Address | None = None

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Network
                ):
                    self._address = host[0]
                    self._network = host[1]
                    return
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Mask
                ):
                    self._address = host[0]
                    self._network = Ip4Network((host[0], host[1]))
                    return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip4Address(address)
                self._network = Ip4Network(host)
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        if isinstance(host, Ip4Host):
            self._address = host.address
            self._network = host.network
            return

        raise Ip4HostFormatError(host)

    @property
    @override
    def address(self) -> Ip4Address:
        """
        Getter for the '_address' attribute.
        """

        return self._address

    @property
    @override
    def network(self) -> Ip4Network:
        """
        Getter for the '_network' attribute.
        """

        return self._network

    @property
    @override
    def gateway(self) -> Ip4Address | None:
        """
        Getter for the '_gateway' attribute.
        """

        return self._gateway

    @gateway.setter
    @override
    def gateway(
        self,
        address: Ip4Address | None,
    ) -> None:
        """
        Setter for the '_gateway' attribute.
        """

        if address is not None and (
            address not in self.network
            or address == self._network.address
            or address == self._network.broadcast
            or address == self._address
        ):
            raise Ip4HostGatewayError(address)

        self._gateway = address
