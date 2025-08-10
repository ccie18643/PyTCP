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

net_addr/ip4_host.py

ver 3.0.2
"""


from __future__ import annotations

import time
from enum import auto
from typing import override

from net_addr.ip_address import IpVersion

from .errors import (
    Ip4AddressFormatError,
    Ip4HostFormatError,
    Ip4HostGatewayError,
    Ip4HostSanityError,
    Ip4MaskFormatError,
)
from .ip4_address import Ip4Address
from .ip4_mask import Ip4Mask
from .ip4_network import Ip4Network
from .ip_host import IpHost, IpHostOrigin


class Ip4HostOrigin(IpHostOrigin):
    """
    IPv4 address origin enumeration.
    """

    STATIC = auto()
    DHCP = auto()
    UNKNOWN = auto()


class Ip4Host(IpHost[Ip4Address, Ip4Network, Ip4HostOrigin]):
    """
    IPv4 host support class.
    """

    _version: IpVersion = IpVersion.IP4
    _primary: bool
    _gateway: Ip4Address | None
    _origin: Ip4HostOrigin
    _expiration_time: int = 0

    def __init__(
        self,
        host: (
            Ip4Host
            | tuple[Ip4Address, Ip4Network]
            | tuple[Ip4Address, Ip4Mask]
            | str
        ),
        /,
        *,
        gateway: Ip4Address | None = None,
        origin: Ip4HostOrigin | None = None,
        expiration_time: int | None = None,
    ) -> None:
        """
        Get the IPv4 host address log string.
        """

        self._gateway = gateway
        self._origin = origin or Ip4HostOrigin.UNKNOWN
        self._expiration_time = expiration_time or 0

        if self._origin == Ip4HostOrigin.DHCP:
            assert self._expiration_time >= int(time.time())
        else:
            assert self._expiration_time == 0

        if isinstance(host, tuple):
            if len(host) == 2:
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Network
                ):
                    self._address = host[0]
                    self._network = host[1]
                    if self._address not in self._network:
                        raise Ip4HostSanityError(host)
                    self._validate_gateway(gateway)
                    return
                if isinstance(host[0], Ip4Address) and isinstance(
                    host[1], Ip4Mask
                ):
                    self._address = host[0]
                    self._network = Ip4Network((host[0], host[1]))
                    self._validate_gateway(gateway)
                    return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip4Address(address)
                self._network = Ip4Network(host)
                self._validate_gateway(gateway)
                return
            except (ValueError, Ip4AddressFormatError, Ip4MaskFormatError):
                pass

        if isinstance(host, Ip4Host):
            assert (
                gateway is None
            ), f"Gateway cannot be set when copying host. Got: {gateway!r}"
            assert (
                origin is None
            ), f"Origin cannot be set when copying host. Got: {origin!r}"
            assert (
                expiration_time is None
            ), f"Expiration time cannot be set when copying host. Got: {expiration_time!r}"
            self._address = host.address
            self._network = host.network
            self._gateway = host.gateway
            self._origin = host.origin
            self._expiration_time = host.expiration_time
            return

        raise Ip4HostFormatError(host)

    @override
    def _validate_gateway(self, address: Ip4Address | None, /) -> None:
        """
        Validate the IPv4 host address gateway.
        """

        if address is not None and (
            address not in self.network
            or address == self._network.address
            or address == self._network.broadcast
            or address == self._address
        ):
            raise Ip4HostGatewayError(address)
