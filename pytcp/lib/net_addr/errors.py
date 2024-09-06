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
Module contains error classes for the NetAddr library.

pytcp/lib/net_addr/errors.py

ver 3.0.2
"""


from __future__ import annotations

from typing import Any


class NetAddrError(Exception):
    """
    Base class for all NetAddr exceptions.
    """


class IpAddressFormatError(NetAddrError):
    """
    Base class for all IP address format exceptions.
    """


class IpMaskFormatError(NetAddrError):
    """
    Base class for all IP mask format exceptions.
    """


class IpNetworkFormatError(NetAddrError):
    """
    Base class for all IP network format exceptions.
    """


class IpHostFormatError(NetAddrError):
    """
    Base class for all IP host format exceptions.
    """


class IpHostGatewayError(NetAddrError):
    """
    Base class for all IP host gateway exceptions.
    """


class Ip4AddressFormatError(IpAddressFormatError):
    """
    Exception raised when IPv4 address format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv4 address format is invalid: {message!r}")


class Ip4MaskFormatError(IpMaskFormatError):
    """
    Exception raised when IPv4 mask format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv4 mask format is invalid: {message!r}")


class Ip4NetworkFormatError(IpNetworkFormatError):
    """
    Exception raised when IPv4 network format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv4 network format is invalid: {message!r}")


class Ip4HostFormatError(IpHostFormatError):
    """
    Exception raised when IPv4 host format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv4 host format is invalid: {message!r}")


class Ip4HostSanityError(IpHostFormatError):
    """
    Exception raised when IPv4 host doesn't belong to provided network.
    """

    def __init__(self, message: Any, /):
        super().__init__(
            f"The IPv4 address doesn't belong to the provided network: {message!r}"
        )


class Ip4HostGatewayError(IpHostGatewayError):
    """
    Exception raised when IPv4 host gateway is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv4 host gateway is invalid: {message!r}")


class Ip6AddressFormatError(IpAddressFormatError):
    """
    Exception raised when IPv6 address format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv6 address format is invalid: {message!r}")


class Ip6MaskFormatError(IpMaskFormatError):
    """
    Exception raised when IPv6 mask format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv6 mask format is invalid: {message!r}")


class Ip6NetworkFormatError(IpNetworkFormatError):
    """
    Exception raised when IPv6 network format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv6 network format is invalid: {message!r}")


class Ip6HostFormatError(IpHostFormatError):
    """
    Exception raised when IPv6 host format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv6 host format is invalid: {message!r}")


class Ip6HostSanityError(IpHostFormatError):
    """
    Exception raised when IPv6 host doesn't belong to provided network.
    """

    def __init__(self, message: Any, /):
        super().__init__(
            f"The IPv6 host doesn't belong to provided network: {message!r}"
        )


class Ip6HostGatewayError(IpHostGatewayError):
    """
    Exception raised when IPv6 host gateway is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The IPv6 host gateway is invalid: {message!r}")


class MacAddressFormatError(Exception):
    """
    Exception raised when MAC address format is invalid.
    """

    def __init__(self, message: Any, /):
        super().__init__(f"The MAC address format is invalid: {message!r}")
