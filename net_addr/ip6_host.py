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
This module contains IPv6 host support class.

net_addr/ip6_host.py

ver 3.0.3
"""


import time
from typing import Self, override

from net_addr.errors import (
    Ip6AddressFormatError,
    Ip6HostFormatError,
    Ip6HostGatewayError,
    Ip6HostSanityError,
    Ip6MaskFormatError,
)
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_host_origin import Ip6HostOrigin
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip_host import IpHost
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MacAddress


class Ip6Host(IpHost[Ip6Address, Ip6Network, Ip6HostOrigin]):
    """
    IPv6 host support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6
    _gateway: Ip6Address | None
    _origin: Ip6HostOrigin
    _expiration_time: int

    def __init__(
        self,
        host: (
            Self
            | tuple[Ip6Address, Ip6Network]
            | tuple[Ip6Address, Ip6Mask]
            | str
        ),
        /,
        *,
        gateway: Ip6Address | None = None,
        origin: Ip6HostOrigin | None = None,
        expiration_time: int | None = None,
    ) -> None:
        """
        Get the IPv6 host address log string.
        """

        self._gateway = gateway
        self._origin = origin or Ip6HostOrigin.UNKNOWN
        self._expiration_time = expiration_time or 0

        if self._origin in {Ip6HostOrigin.AUTOCONFIG, Ip6HostOrigin.DHCP}:
            assert self._expiration_time >= int(time.time())
        else:
            assert self._expiration_time == 0

        if isinstance(host, tuple):
            self._address = host[0]
            if isinstance(host[1], Ip6Network):
                self._network = host[1]
            else:
                self._network = Ip6Network((host[0], host[1]))
            if self._address not in self._network:
                raise Ip6HostSanityError(host)
            self._validate_gateway(gateway)
            return

        if isinstance(host, str):
            try:
                address, _ = host.split("/")
                self._address = Ip6Address(address)
                self._network = Ip6Network(host)
                return
            except (ValueError, Ip6AddressFormatError, Ip6MaskFormatError):
                pass

        if isinstance(host, Ip6Host):
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

        raise Ip6HostFormatError(host)

    @override
    def _validate_gateway(self, address: Ip6Address | None, /) -> None:
        """
        Validate the IPv6 host address gateway.
        """

        if address is not None and (
            not address.is_global
            and not address.is_link_local
            or address == self._network.address
            or address == self._address
        ):
            raise Ip6HostGatewayError(address)

    @classmethod
    def from_eui64(
        cls, *, mac_address: MacAddress, ip6_network: Ip6Network
    ) -> Self:
        """
        Create IPv6 EUI64 host address.
        """

        assert len(ip6_network.mask) == 64, (
            "The IPv6 EUI64 network address mask must be /64. "
            f"Got: {ip6_network.mask}"
        )

        interface_id = (
            ((int(mac_address) & 0xFFFFFF000000) << 16)
            | int(mac_address) & 0xFFFFFF
            | 0xFFFE000000
        ) ^ 0x0200000000000000

        return cls(
            (
                Ip6Address(int(ip6_network.address) | interface_id),
                Ip6Mask("/64"),
            )
        )
