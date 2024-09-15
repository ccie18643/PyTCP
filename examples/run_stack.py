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
Run stack without any 'user space' services. Stack should only respond to
ping packets.

examples/run_stack.py

ver 3.0.2
"""


import time

import click

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
    "--interface",
    default="tap7",
    help="Name of the interface to be used by the stack.",
)
@click.option(
    "--mac-address",
    type=ClickTypeMacAddress(),
    default=None,
    help="MAC address to be assigned to the interface.",
)
@click.option(
    "--ip6-address",
    "ip6_host",
    type=ClickTypeIp6Host(),
    default=None,
    help="IPv6 address/mask to be assigned to the interface.",
)
@click.option(
    "--ip6-gateway",
    type=ClickTypeIp6Address(),
    default=None,
    help="IPv6 gateway address to be assigned to the interface.",
)
@click.option(
    "--ip4-address",
    "ip4_host",
    type=ClickTypeIp4Host(),
    default=None,
    help="IPv4 address/mask to be assigned to the interface.",
)
@click.option(
    "--ip4-gateway",
    type=ClickTypeIp4Address(),
    default=None,
    help="IPv4 gateway address to be assigned to the interface.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_host: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_host: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    """

    if ip6_host:
        ip6_host.gateway = ip6_gateway

    if ip4_host:
        ip4_host.gateway = ip4_gateway

    stack.init(
        *stack.initialize_interface(interface),
        mac_address=mac_address,
        ip6_host=ip6_host,
        ip4_host=ip4_host,
    )

    try:
        stack.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
