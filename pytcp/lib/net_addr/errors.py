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


class NetAddrError(Exception): ...


class IpAddressFormatError(NetAddrError): ...


class IpMaskFormatError(NetAddrError): ...


class IpNetworkFormatError(NetAddrError): ...


class IpHostFormatError(NetAddrError): ...


class IpHostGatewayError(NetAddrError): ...


class Ip4AddressFormatError(IpAddressFormatError): ...


class Ip4MaskFormatError(IpMaskFormatError): ...


class Ip4NetworkFormatError(IpNetworkFormatError): ...


class Ip4HostFormatError(IpHostFormatError): ...


class Ip4HostGatewayError(IpHostGatewayError): ...


class Ip6AddressFormatError(IpAddressFormatError): ...


class Ip6MaskFormatError(IpMaskFormatError): ...


class Ip6NetworkFormatError(IpNetworkFormatError): ...


class Ip6HostFormatError(IpHostFormatError): ...


class Ip6HostGatewayError(IpHostGatewayError): ...


class MacAddressFormatError(Exception): ...
