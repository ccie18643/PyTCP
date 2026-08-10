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
This module contains error classes for the NetAddr library.

net_addr/errors.py

ver 3.0.10
"""


class NetAddrError(Exception):
    """
    Base class for all NetAddr exceptions.
    """


#
# Concept umbrellas — "any error of this value-type concept,
# any version, any axis". The catch-all a consumer uses to
# handle "any problem with this kind of value".
#


class IpAddressError(NetAddrError):
    """
    Base class for all IP address exceptions.
    """


class IpMaskError(NetAddrError):
    """
    Base class for all IP mask exceptions.
    """


class IpWildcardError(NetAddrError):
    """
    Base class for all IP wildcard exceptions.
    """


class IpNetworkError(NetAddrError):
    """
    Base class for all IP network exceptions.
    """


class IfAddrError(NetAddrError):
    """
    Base class for all IP interface address exceptions.
    """


#
# Axis bases — the version-agnostic Format / Sanity grouping
# (e.g. "any IP address format error, v4 or v6"). Retained as
# the second parent of every concrete leaf via multiple
# inheritance so the pre-existing axis grouping stays
# catchable.
#


class IpAddressFormatError(IpAddressError):
    """
    Base class for all IP address format exceptions.
    """


class IpAddressSanityError(IpAddressError):
    """
    Base class for all IP address sanity exceptions.
    """


class IpMaskFormatError(IpMaskError):
    """
    Base class for all IP mask format exceptions.
    """


class IpWildcardFormatError(IpWildcardError):
    """
    Base class for all IP wildcard format exceptions.
    """


class IpNetworkFormatError(IpNetworkError):
    """
    Base class for all IP network format exceptions.
    """


class IpNetworkSanityError(IpNetworkError):
    """
    Base class for all IP network sanity exceptions.
    """


class IfAddrFormatError(IfAddrError):
    """
    Base class for all IP interface address format exceptions.
    """


class IfAddrSanityError(IfAddrError):
    """
    Base class for all IP interface address sanity exceptions.
    """


#
# Per-type umbrellas — "any error of this concrete type, both
# axes" (the MAC-parallel grouping; cf. MacAddressError).
#


class Ip4AddressError(IpAddressError):
    """
    Base class for all IPv4 address exceptions.
    """


class Ip6AddressError(IpAddressError):
    """
    Base class for all IPv6 address exceptions.
    """


class Ip4MaskError(IpMaskError):
    """
    Base class for all IPv4 mask exceptions.
    """


class Ip6MaskError(IpMaskError):
    """
    Base class for all IPv6 mask exceptions.
    """


class Ip4WildcardError(IpWildcardError):
    """
    Base class for all IPv4 wildcard exceptions.
    """


class Ip6WildcardError(IpWildcardError):
    """
    Base class for all IPv6 wildcard exceptions.
    """


class Ip4NetworkError(IpNetworkError):
    """
    Base class for all IPv4 network exceptions.
    """


class Ip6NetworkError(IpNetworkError):
    """
    Base class for all IPv6 network exceptions.
    """


class Ip4IfAddrError(IfAddrError):
    """
    Base class for all IPv4 interface address exceptions.
    """


class Ip6IfAddrError(IfAddrError):
    """
    Base class for all IPv6 interface address exceptions.
    """


#
# Concrete leaves — each sits in both its per-type umbrella
# and its version-agnostic axis base via multiple inheritance
# (MI within the NetAddrError tree only; this is the sanctioned
# two-axis expression and is distinct from the net_addr.md §7.1
# prohibition on MI with a builtin). The umbrellas carry no
# '__init__', so they are transparent in the MRO and the
# message-formatting '__init__' below resolves to Exception
# unchanged.
#


class Ip4AddressFormatError(Ip4AddressError, IpAddressFormatError):
    """
    Exception raised when IPv4 address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 address format is invalid: {value!r}")


class Ip4AddressSanityError(Ip4AddressError, IpAddressSanityError):
    """
    Exception raised when an IPv4 address operation precondition is violated.
    """


class Ip6AddressFormatError(Ip6AddressError, IpAddressFormatError):
    """
    Exception raised when IPv6 address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 address format is invalid: {value!r}")


class Ip6AddressSanityError(Ip6AddressError, IpAddressSanityError):
    """
    Exception raised when an IPv6 address operation precondition is violated.
    """


class Ip4MaskFormatError(Ip4MaskError, IpMaskFormatError):
    """
    Exception raised when IPv4 mask format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 mask format is invalid: {value!r}")


class Ip6MaskFormatError(Ip6MaskError, IpMaskFormatError):
    """
    Exception raised when IPv6 mask format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 mask format is invalid: {value!r}")


class Ip4WildcardFormatError(Ip4WildcardError, IpWildcardFormatError):
    """
    Exception raised when IPv4 wildcard format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 wildcard format is invalid: {value!r}")


class Ip6WildcardFormatError(Ip6WildcardError, IpWildcardFormatError):
    """
    Exception raised when IPv6 wildcard format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 wildcard format is invalid: {value!r}")


class Ip4NetworkFormatError(Ip4NetworkError, IpNetworkFormatError):
    """
    Exception raised when IPv4 network format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 network format is invalid: {value!r}")


class Ip4NetworkSanityError(Ip4NetworkError, IpNetworkSanityError):
    """
    Exception raised when an IPv4 network operation argument or invariant is invalid.
    """


class Ip6NetworkFormatError(Ip6NetworkError, IpNetworkFormatError):
    """
    Exception raised when IPv6 network format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 network format is invalid: {value!r}")


class Ip6NetworkSanityError(Ip6NetworkError, IpNetworkSanityError):
    """
    Exception raised when an IPv6 network operation argument or invariant is invalid.
    """


class Ip4IfAddrFormatError(Ip4IfAddrError, IfAddrFormatError):
    """
    Exception raised when IPv4 interface address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 interface address format is invalid: {value!r}")


class Ip4IfAddrSanityError(Ip4IfAddrError, IfAddrSanityError):
    """
    Exception raised when IPv4 interface address doesn't belong to provided network.
    """


class Ip6IfAddrFormatError(Ip6IfAddrError, IfAddrFormatError):
    """
    Exception raised when IPv6 interface address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 interface address format is invalid: {value!r}")


class Ip6IfAddrSanityError(Ip6IfAddrError, IfAddrSanityError):
    """
    Exception raised when IPv6 interface address doesn't belong to provided network.
    """


#
# MAC — a single concrete type with no version split, so its
# per-type umbrella 'MacAddressError' already joins both axes
# directly (the shape the IP families above now mirror).
#


class MacAddressError(NetAddrError):
    """
    Base class for all MAC address exceptions.
    """


class MacAddressFormatError(MacAddressError):
    """
    Exception raised when MAC address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The MAC address format is invalid: {value!r}")


class MacAddressSanityError(MacAddressError):
    """
    Exception raised when a MAC address operation precondition is violated.
    """
