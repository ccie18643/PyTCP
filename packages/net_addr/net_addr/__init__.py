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
This package contains classes used to represent network addresses.

net_addr/__init__.py

ver 3.0.9
"""

from typing import TYPE_CHECKING

from net_addr.buffer import Buffer
from net_addr.errors import (
    IfAddrError,
    IfAddrFormatError,
    IfAddrSanityError,
    Ip4AddressError,
    Ip4AddressFormatError,
    Ip4AddressSanityError,
    Ip4IfAddrError,
    Ip4IfAddrFormatError,
    Ip4IfAddrSanityError,
    Ip4MaskError,
    Ip4MaskFormatError,
    Ip4NetworkError,
    Ip4NetworkFormatError,
    Ip4NetworkSanityError,
    Ip4WildcardError,
    Ip4WildcardFormatError,
    Ip6AddressError,
    Ip6AddressFormatError,
    Ip6AddressSanityError,
    Ip6IfAddrError,
    Ip6IfAddrFormatError,
    Ip6IfAddrSanityError,
    Ip6MaskError,
    Ip6MaskFormatError,
    Ip6NetworkError,
    Ip6NetworkFormatError,
    Ip6NetworkSanityError,
    Ip6WildcardError,
    Ip6WildcardFormatError,
    IpAddressError,
    IpAddressFormatError,
    IpAddressSanityError,
    IpMaskError,
    IpMaskFormatError,
    IpNetworkError,
    IpNetworkFormatError,
    IpNetworkSanityError,
    IpWildcardError,
    IpWildcardFormatError,
    MacAddressError,
    MacAddressFormatError,
    MacAddressSanityError,
    NetAddrError,
)
from net_addr.ip4_address import IP4__ADDRESS_LEN, Ip4Address
from net_addr.ip4_ifaddr import Ip4IfAddr
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip6_address import IP6__ADDRESS_LEN, Ip6Address
from net_addr.ip6_ifaddr import Ip6IfAddr
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip6_wildcard import Ip6Wildcard
from net_addr.ip_address import IpAddress
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_mask import IpMask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion
from net_addr.ip_wildcard import IpWildcard
from net_addr.mac_address import MAC__ADDRESS_LEN, MacAddress

# The 'click'-typed CLI helpers are an opt-in extra: importing
# 'net_addr' (or any value type) must not drag in 'click'. The
# names below are re-exported lazily via the module '__getattr__'
# so 'from net_addr import ClickTypeIp4Address' still works but
# imports 'click' only on first access. The TYPE_CHECKING block
# gives static checkers (mypy strict, with no_implicit_reexport)
# the real bindings, and listing the names in '__all__' marks
# them as the explicit public surface.
if TYPE_CHECKING:
    from net_addr.click_types import (
        ClickTypeIfAddr,
        ClickTypeIp4Address,
        ClickTypeIp4IfAddr,
        ClickTypeIp4Network,
        ClickTypeIp6Address,
        ClickTypeIp6IfAddr,
        ClickTypeIp6Network,
        ClickTypeIpAddress,
        ClickTypeIpNetwork,
        ClickTypeMacAddress,
    )

_LAZY_CLICK_TYPES: frozenset[str] = frozenset(
    {
        "ClickTypeIfAddr",
        "ClickTypeIp4Address",
        "ClickTypeIp4IfAddr",
        "ClickTypeIp4Network",
        "ClickTypeIp6Address",
        "ClickTypeIp6IfAddr",
        "ClickTypeIp6Network",
        "ClickTypeIpAddress",
        "ClickTypeIpNetwork",
        "ClickTypeMacAddress",
    }
)


def __getattr__(name: str, /) -> object:
    """
    Lazily resolve the opt-in 'click'-typed CLI helpers so the
    'click' import is deferred to first access.
    """

    if name in _LAZY_CLICK_TYPES:
        from net_addr import click_types

        return getattr(click_types, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """
    List the public names, including the lazily-exposed CLI
    helpers.
    """

    return sorted(__all__)


__version__: str = "3.0.9"

__all__ = [
    "Buffer",
    "ClickTypeIfAddr",
    "ClickTypeIp4Address",
    "ClickTypeIp4IfAddr",
    "ClickTypeIp4Network",
    "ClickTypeIp6Address",
    "ClickTypeIp6IfAddr",
    "ClickTypeIp6Network",
    "ClickTypeIpAddress",
    "ClickTypeIpNetwork",
    "ClickTypeMacAddress",
    "IP4__ADDRESS_LEN",
    "IP6__ADDRESS_LEN",
    "IfAddr",
    "IfAddrError",
    "IfAddrFormatError",
    "IfAddrSanityError",
    "Ip4Address",
    "Ip4AddressError",
    "Ip4AddressFormatError",
    "Ip4AddressSanityError",
    "Ip4IfAddr",
    "Ip4IfAddrError",
    "Ip4IfAddrFormatError",
    "Ip4IfAddrSanityError",
    "Ip4Mask",
    "Ip4MaskError",
    "Ip4MaskFormatError",
    "Ip4Network",
    "Ip4NetworkError",
    "Ip4NetworkFormatError",
    "Ip4NetworkSanityError",
    "Ip4Wildcard",
    "Ip4WildcardError",
    "Ip4WildcardFormatError",
    "Ip6Address",
    "Ip6AddressError",
    "Ip6AddressFormatError",
    "Ip6AddressSanityError",
    "Ip6IfAddr",
    "Ip6IfAddrError",
    "Ip6IfAddrFormatError",
    "Ip6IfAddrSanityError",
    "Ip6Mask",
    "Ip6MaskError",
    "Ip6MaskFormatError",
    "Ip6Network",
    "Ip6NetworkError",
    "Ip6NetworkFormatError",
    "Ip6NetworkSanityError",
    "Ip6Wildcard",
    "Ip6WildcardError",
    "Ip6WildcardFormatError",
    "IpAddress",
    "IpAddressError",
    "IpAddressFormatError",
    "IpAddressSanityError",
    "IpMask",
    "IpMaskError",
    "IpMaskFormatError",
    "IpNetwork",
    "IpNetworkError",
    "IpNetworkFormatError",
    "IpNetworkSanityError",
    "IpVersion",
    "IpWildcard",
    "IpWildcardError",
    "IpWildcardFormatError",
    "MAC__ADDRESS_LEN",
    "MacAddress",
    "MacAddressError",
    "MacAddressFormatError",
    "MacAddressSanityError",
    "NetAddrError",
]
