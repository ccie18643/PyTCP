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
This module contains code that runs the stack without any 'user space' services.
Stack should only respond to the ping packets. This example is also used as a
base to run other examples provided as the subsystems.

examples/stack.py

ver 3.0.3
"""


import time

import click

from examples.lib.subsystem import Subsystem
from net_addr import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeMacAddress,
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    MacAddress,
)
from pytcp import stack


@click.command()
@click.option(
    "--stack-interface",
    "stack__interface",
    default="tap7",
    help="Name of the interface to be used by the stack.",
)
@click.option(
    "--stack-mac-address",
    "stack__mac_address",
    type=ClickTypeMacAddress(),
    default=None,
    help="MAC address to be assigned to the stack interface.",
)
@click.option(
    "--stack-no-ip6",
    "stack__ip6_support",
    is_flag=True,
    default=True,
    help="Do not enable stack IPv6 support.",
)
@click.option(
    "--stack-ip6-address",
    "stack__ip6_host",
    type=ClickTypeIp6Host(),
    default=None,
    help="IPv6 address/mask to be assigned to the stack interface.",
)
@click.option(
    "--stack-ip6-gateway",
    "stack__ip6_gateway",
    type=ClickTypeIp6Address(),
    default=None,
    help="IPv6 gateway address to be assigned to the stack interface.",
)
@click.option(
    "--stack-no-ip4",
    "stack__ip4_support",
    is_flag=True,
    default=True,
    help="Do not enable stack IPv4 support.",
)
@click.option(
    "--stack-ip4-address",
    "stack__ip4_host",
    type=ClickTypeIp4Host(),
    default=None,
    help="IPv4 address/mask to be assigned to the stack interface.",
)
@click.option(
    "--stack-ip4-gateway",
    "stack__ip4_gateway",
    type=ClickTypeIp4Address(),
    default=None,
    help="IPv4 gateway address to be assigned to the stack interface.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    stack__interface: str,
    stack__mac_address: MacAddress | None,
    stack__ip6_support: bool,
    stack__ip6_host: Ip6Host | None,
    stack__ip6_gateway: Ip6Address | None,
    stack__ip4_support: bool,
    stack__ip4_host: Ip4Host | None,
    stack__ip4_gateway: Ip4Address | None,
    subsystems: list[Subsystem] | None = None,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C. Also
    run the provided subsystems if any.
    """

    match stack__interface[:3]:
        case "tap":
            interface_args = stack.initialize_interface__tap(
                interface_name=stack__interface, mac_address=stack__mac_address
            )
        case "tun":
            if stack__ip4_support and not stack__ip4_host:
                click.secho(
                    "IPv4 host address must be provided for TUN interface when IPv4 support is enabled.",
                    fg="red",
                )
                ctx.exit(1)
            if stack__ip6_support and not stack__ip6_host:
                click.secho(
                    "IPv6 host address must be provided for TUN interface when IPv6 support is enabled.",
                    fg="red",
                )
                ctx.exit(1)
            interface_args = stack.initialize_interface__tun(
                interface_name=stack__interface,
            )
        case _:
            click.secho(
                f"Invalid interface type '{stack__interface[:3]}'. "
                "Only 'tap' and 'tun' interfaces are supported.",
                fg="red",
            )
            ctx.exit(1)

    if subsystems is None:
        subsystems = []

    if stack__ip6_support and stack__ip6_host:
        stack__ip6_host.gateway = stack__ip6_gateway

    if stack__ip4_support and stack__ip4_host:
        stack__ip4_host.gateway = stack__ip4_gateway

    stack.init(
        **interface_args,
        ip6_support=stack__ip6_support,
        ip6_host=stack__ip6_host,
        ip4_support=stack__ip4_support,
        ip4_host=stack__ip4_host,
    )

    try:
        stack.start()
        for subsystem in subsystems:
            if stack__ip6_support:
                subsystem.stack_ip6_address = (
                    stack__ip6_host.address if stack__ip6_host else Ip6Address()
                )
            if stack__ip4_support:
                subsystem.stack_ip4_address = (
                    stack__ip4_host.address if stack__ip4_host else Ip4Address()
                )
            subsystem.start()

        while (
            any(subsystem.is_alive for subsystem in subsystems if subsystem)
            or not subsystems
        ):
            time.sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        for subsystem in subsystems:
            if subsystem.is_alive:
                subsystem.stop()
        stack.stop()


if __name__ == "__main__":
    cli.main()
