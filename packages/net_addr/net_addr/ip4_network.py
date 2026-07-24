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

ver 3.0.9
"""

from collections.abc import Iterator
from typing import ClassVar, Self, final, override

from net_addr.errors import (
    Ip4AddressFormatError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
    Ip4NetworkSanityError,
    NetAddrError,
)
from net_addr.ip4_address import IP4__MASK, Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion


@final
class Ip4Network(IpNetwork[Ip4Address, Ip4Mask]):
    """
    IPv4 network support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    _sanity_error: ClassVar[type[NetAddrError]] = Ip4NetworkSanityError

    def __init__(
        self,
        network: Self | tuple[Ip4Address, Ip4Mask] | str | None = None,
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
        Initialize the IPv4 network object. Pass strict=True to
        reject an address carrying bits outside the network mask
        ('Ip4NetworkFormatError'); the default silently masks.
        """

        if network is None:
            self._address = Ip4Address()
            self._mask = Ip4Mask()
            return

        if isinstance(network, Ip4Network):
            self._mask = network.mask
            self._address = Ip4Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            if len(network) != 2:
                raise Ip4NetworkFormatError(network)
            tuple_address, tuple_mask = network
            # Defensive runtime guard: the parameter is typed
            # 'tuple[Ip4Address, Ip4Mask]', so mypy proves the first
            # 'isinstance' operand statically true, but the check is
            # load-bearing — a mistyped tuple must raise the net_addr
            # error here rather than blowing up later on 'int(...)'.
            if not (
                isinstance(tuple_address, Ip4Address)  # type: ignore[redundant-expr]
                and isinstance(tuple_mask, Ip4Mask)
            ):
                raise Ip4NetworkFormatError(network)
            if strict and int(tuple_address) & ~int(tuple_mask) & IP4__MASK:
                raise Ip4NetworkFormatError(network)
            self._mask = tuple_mask
            self._address = Ip4Address(int(tuple_address) & int(tuple_mask))
            return

        # Accepted textual forms (stdlib `ipaddress` parity):
        #   'a.b.c.d/prefixlen'  (RFC 4632 §3.1 CIDR)
        #   'a.b.c.d/m.m.m.m'    (RFC 950 dotted netmask)
        #   'a.b.c.d m.m.m.m'    (space-separated netmask)
        #   'a.b.c.d'            (prefix-less -> /32 host route)
        # Surrounding whitespace is stripped uniformly across every
        # net_addr string constructor; a mask token that is all
        # digits is a prefix length, otherwise a dotted netmask.
        if isinstance(network, str):
            text = network.strip()
            try:
                if "/" in text:
                    address_str, _, mask_str = text.partition("/")
                    if "/" in mask_str:
                        raise Ip4NetworkFormatError(network)
                    mask = Ip4Mask("/" + mask_str if mask_str.isdigit() else mask_str)
                elif " " in text:
                    address_str, _, mask_str = text.partition(" ")
                    mask = Ip4Mask(mask_str)
                else:
                    address_str = text
                    mask = Ip4Mask("/32")
                self._mask = mask
                raw_address = int(Ip4Address(address_str))
                if strict and raw_address & ~int(self._mask) & IP4__MASK:
                    raise Ip4NetworkFormatError(network)
                self._address = Ip4Address(raw_address & int(self._mask))
                return
            except (Ip4AddressFormatError, Ip4MaskFormatError) as error:
                raise Ip4NetworkFormatError(network) from error

        raise Ip4NetworkFormatError(network)

    @property
    @override
    def last(self) -> Ip4Address:
        """
        Last address in the network.
        """

        return Ip4Address(int(self._address) + (~int(self._mask) & IP4__MASK))

    @property
    def broadcast(self) -> Ip4Address:
        """
        Broadcast address (same as last address in the network).
        """

        return self.last

    @property
    @override
    def hostmask(self) -> Ip4Wildcard:
        """
        Get the network wildcard (inverted netmask).
        """

        return Ip4Wildcard(~int(self._mask) & IP4__MASK)

    @override
    def hosts(self) -> Iterator[Ip4Address]:
        """
        Iterate over the usable host addresses, excluding the
        network and broadcast addresses. A /31 (RFC 3021) and a
        single-host /32 yield every address instead.
        """

        if len(self._mask) >= 31:
            yield from self
            return

        for value in range(int(self._address) + 1, int(self.last)):
            yield Ip4Address(value)
