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

# pylint: disable=inconsistent-return-statements


"""
This module contains Click type classes related to network addresses.

net_addr/click_types.py

ver 3.0.3
"""


from click import ParamType
from click.core import Context, Parameter

from .errors import NetAddrError
from .ip4_address import Ip4Address
from .ip4_host import Ip4Host
from .ip4_network import Ip4Network
from .ip6_address import Ip6Address
from .ip6_host import Ip6Host
from .ip6_network import Ip6Network
from .mac_address import MacAddress


class ClickTypeMacAddress(ParamType):
    """
    Custom Click type for handling the MAC address argument.
    """

    name = "xx:xx:xx:xx:xx:xx"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> MacAddress:
        """
        Convert MAC address string to MacAddress object.
        """

        try:
            return MacAddress(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid MAC address argument '{value}'. Make sure to use "
                    "format 'xx:xx:xx:xx:xx:xx'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIpAddress(ParamType):
    """
    Custom Click type for handling IP address argument.
    """

    name = "x:x:x:x::x or x.x.x.x"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Address | Ip4Address:
        """
        Convert IPv6 address string to Ip6Address or Ip4Address object.
        """

        try:
            return Ip6Address(value)

        except NetAddrError:
            try:
                return Ip4Address(value)

            except NetAddrError:
                self.fail(
                    message=(
                        f"Invalid IP address argument '{value}'. Make sure to use "
                        "format 'x:x:x:x::x' for IPv6 or 'x.x.x.x' for IPv4."
                    ),
                    param=param,
                    ctx=ctx,
                )


class ClickTypeIp6Address(ParamType):
    """
    Custom Click type for handling IPv6 address argument.
    """

    name = "x:x:x:x::x"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Address:
        """
        Convert IPv6 address string to Ip6Address object.
        """

        try:
            return Ip6Address(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv6 address argument '{value}'. Make sure to use "
                    "format 'x:x:x:x::x'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIp4Address(ParamType):
    """
    Custom Click type for handling IPv4 address argument.
    """

    name = "x.x.x.x"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip4Address:
        """
        Convert IPv4 address string to Ip4Address object.
        """

        try:
            return Ip4Address(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv4 address argument '{value}'. Make sure to use "
                    "format 'x.x.x.x'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIpNetwork(ParamType):
    """
    Custom Click type for handling IP network argument.
    """

    name = "x:x:x:x::x/n or x.x.x.x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Network | Ip4Network:
        """
        Convert IPv6 network string to Ip6Network or Ip4Network object.
        """

        try:
            return Ip6Network(value)

        except NetAddrError:
            try:
                return Ip4Network(value)

            except NetAddrError:
                self.fail(
                    message=(
                        f"Invalid IP network argument '{value}'. Make sure to use "
                        "format 'x:x:x:x::x/n' for IPv6 or 'x.x.x.x/n' for IPv4."
                    ),
                    param=param,
                    ctx=ctx,
                )


class ClickTypeIp6Network(ParamType):
    """
    Custom Click type for handling IPv6 network argument.
    """

    name = "x:x:x:x::x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Network:
        """
        Convert IPv6 network string to Ip6Network object.
        """

        try:
            return Ip6Network(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv6 network argument '{value}'. Make sure to use "
                    "format 'x:x:x:x::x/n'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIp4Network(ParamType):
    """
    Custom Click type for handling IPv4 network argument.
    """

    name = "x.x.x.x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip4Network:
        """
        Convert IPv4 network string to Ip4Network object.
        """

        try:
            return Ip4Network(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv4 network argument '{value}'. Make sure to use "
                    "format 'x.x.x.x/n'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIpHost(ParamType):
    """
    Custom Click type for handling IP host argument.
    """

    name = "x:x:x:x::x/n or x.x.x.x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Host | Ip4Host:
        """
        Convert IPv6 host string to Ip6Host or Ip4Host object.
        """

        try:
            return Ip6Host(value)

        except NetAddrError:
            try:
                return Ip4Host(value)

            except NetAddrError:
                self.fail(
                    message=(
                        f"Invalid IP host argument '{value}'. Make sure to use "
                        "format 'x:x:x:x::x/n' for IPv6 or 'x.x.x.x/n' for IPv4."
                    ),
                    param=param,
                    ctx=ctx,
                )


class ClickTypeIp6Host(ParamType):
    """
    Custom Click type for handling IPv6 host argument.
    """

    name = "x:x:x:x::x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Host:
        """
        Convert IPv6 host string to Ip6Host object.
        """

        try:
            return Ip6Host(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv6 host argument '{value}'. Make sure to use "
                    "format 'x:x:x:x::x/n'."
                ),
                param=param,
                ctx=ctx,
            )


class ClickTypeIp4Host(ParamType):
    """
    Custom Click type for handling IPv4 host argument.
    """

    name = "x.x.x.x/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip4Host:
        """
        Convert IPv4 host string to Ip6Host object.
        """

        try:
            return Ip4Host(value)

        except NetAddrError:
            self.fail(
                message=(
                    f"Invalid IPv4 host argument '{value}'. Make sure to use "
                    "format 'x.x.x.x/n'."
                ),
                param=param,
                ctx=ctx,
            )
