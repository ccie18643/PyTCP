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
Module contains Click types classes.

pytcp/lib/net_addr/click_types.py

ver 3.0.2
"""


from __future__ import annotations

from click import ParamType
from click.core import Context, Parameter

from pytcp.lib.net_addr.errors import NetAddrError
from pytcp.lib.net_addr.ip4_address import Ip4Address
from pytcp.lib.net_addr.ip4_host import Ip4Host
from pytcp.lib.net_addr.ip4_network import Ip4Network
from pytcp.lib.net_addr.ip6_address import Ip6Address
from pytcp.lib.net_addr.ip6_host import Ip6Host
from pytcp.lib.net_addr.ip6_network import Ip6Network
from pytcp.lib.net_addr.mac_address import MacAddress


class ClickTypeMacAddress(ParamType):
    """
    Custom Click type for handling MAC address argument.
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
                message=(f"Invalid MAC address argument: {value}. "),
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
        Convert IPv6 address string to Ip6Address object.
        """

        try:
            return Ip6Address(value)

        except NetAddrError:
            try:
                return Ip4Address(value)

            except NetAddrError:
                self.fail(
                    message=(f"Invalid IP address argument: {value}. "),
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
                message=(f"Invalid IPv6 address argument: {value}. "),
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
                message=(f"Invalid IPv4 address argument: {value}. "),
                param=param,
                ctx=ctx,
            )


class ClickTypeIp6Mask(ParamType):
    """
    Custom Click type for handling IPv6 mask argument.
    """

    name = "/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Network:
        """
        Convert IPv6 mask string to Ip6Mask object.
        """

        try:
            return Ip6Network(value)

        except NetAddrError:
            self.fail(
                message=(f"Invalid IPv6 mask argument: {value}. "),
                param=param,
                ctx=ctx,
            )


class ClickTypeIp4Mask(ParamType):
    """
    Custom Click type for handling IPv4 mask argument.
    """

    name = "/n"

    def convert(
        self,
        value: str,
        param: Parameter | None,
        ctx: Context | None,
    ) -> Ip6Network:
        """
        Convert IPv4 mask string to Ip4Mask object.
        """

        try:
            return Ip6Network(value)

        except NetAddrError:
            self.fail(
                message=(f"Invalid IPv4 mask argument: {value}. "),
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
                message=(f"Invalid IPv6 network argument: {value}. "),
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
                message=(f"Invalid IPv4 network argument: {value}. "),
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
                message=(f"Invalid IPv6 host argument: {value}. "),
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
                message=(f"Invalid IPv4 host argument: {value}. "),
                param=param,
                ctx=ctx,
            )
