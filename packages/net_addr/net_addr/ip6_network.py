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
This module contains IPv6 network support class.

net_addr/ip6_network.py

ver 3.0.10
"""

from collections.abc import Iterator
from typing import ClassVar, Self, final, override

from net_addr.errors import (
    Ip6AddressFormatError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
    Ip6NetworkSanityError,
    NetAddrError,
)
from net_addr.ip6_address import IP6__MASK, Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_wildcard import Ip6Wildcard
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion


@final
class Ip6Network(IpNetwork[Ip6Address, Ip6Mask]):
    """
    IPv6 network support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    _sanity_error: ClassVar[type[NetAddrError]] = Ip6NetworkSanityError

    def __init__(
        self,
        network: Self | tuple[Ip6Address, Ip6Mask] | str | None = None,
        /,
        *,
        # Deliberate deviation from net_addr.md §4.2 (no kwargs on a
        # value-type __init__): keyword-only 'strict' added by
        # maintainer decision for ipaddress-parity strict network
        # parsing. Default False preserves the silent
        # mask-on-construct contract the rest of the stack relies on;
        # pass strict=True to reject an address carrying host bits.
        strict: bool = False,
    ) -> None:
        """
        Initialize the IPv6 network object. Pass strict=True to
        reject an address carrying bits outside the network mask
        ('Ip6NetworkFormatError'); the default silently masks.
        """

        if network is None:
            self._address = Ip6Address()
            self._mask = Ip6Mask()
            return

        if isinstance(network, Ip6Network):
            self._mask = network.mask
            self._address = Ip6Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            if len(network) != 2:
                raise Ip6NetworkFormatError(network)
            tuple_address, tuple_mask = network
            # Defensive runtime guard: the parameter is typed
            # 'tuple[Ip6Address, Ip6Mask]', so mypy proves the first
            # 'isinstance' operand statically true, but the check is
            # load-bearing — a mistyped tuple must raise the net_addr
            # error here rather than blowing up later on 'int(...)'.
            if not (
                isinstance(tuple_address, Ip6Address)  # type: ignore[redundant-expr]
                and isinstance(tuple_mask, Ip6Mask)
            ):
                raise Ip6NetworkFormatError(network)
            # A prefix has no RFC 4007 zone; reject a scoped
            # address rather than silently dropping the zone.
            if tuple_address.scope_id is not None:
                raise Ip6NetworkFormatError(network)
            if strict and int(tuple_address) & ~int(tuple_mask) & IP6__MASK:
                raise Ip6NetworkFormatError(network)
            self._mask = tuple_mask
            self._address = Ip6Address(int(tuple_address) & int(tuple_mask))
            return

        if isinstance(network, str):
            try:
                # Surrounding whitespace is stripped uniformly
                # across every net_addr string constructor; a
                # prefix-less address is a /128 host route
                # (stdlib ipaddress parity).
                address, sep, mask = network.strip().partition("/")
                self._mask = Ip6Mask("/" + mask) if sep else Ip6Mask("/128")
                address_obj = Ip6Address(address)
                # A prefix has no RFC 4007 zone; reject a scoped
                # address rather than silently dropping the zone.
                if address_obj.scope_id is not None:
                    raise Ip6NetworkFormatError(network)
                raw_address = int(address_obj)
                if strict and raw_address & ~int(self._mask) & IP6__MASK:
                    raise Ip6NetworkFormatError(network)
                self._address = Ip6Address(raw_address & int(self._mask))
                return
            except (Ip6AddressFormatError, Ip6MaskFormatError) as error:
                raise Ip6NetworkFormatError(network) from error

        raise Ip6NetworkFormatError(network)

    @property
    @override
    def last(self) -> Ip6Address:
        """
        Last address in the network.
        """

        return Ip6Address(int(self._address) + (~int(self._mask) & IP6__MASK))

    @property
    @override
    def hostmask(self) -> Ip6Wildcard:
        """
        Get the network wildcard (inverted netmask).
        """

        return Ip6Wildcard(~int(self._mask) & IP6__MASK)

    @override
    def hosts(self) -> Iterator[Ip6Address]:
        """
        Iterate over the usable host addresses, excluding the
        Subnet-Router anycast (network) address. IPv6 has no
        broadcast address. A /127 and a single-host /128 yield
        every address instead.
        """

        if len(self._mask) >= 127:
            yield from self
            return

        for value in range(int(self._address) + 1, int(self.last) + 1):
            yield Ip6Address(value)
