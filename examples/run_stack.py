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

from pytcp import TcpIpStack, initialize_interface


@click.command()
@click.option("--interface", default="tap7")
@click.option("--mac-address", default=None)
@click.option("--ip6-address", default=None)
@click.option("--ip6-gateway", default=None)
@click.option("--ip4-address", default=None)
@click.option("--ip4-gateway", default=None)
def cli(
    *,
    interface: str,
    mac_address: str | None,
    ip6_address: str | None,
    ip6_gateway: str | None,
    ip4_address: str | None,
    ip4_gateway: str | None,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    """

    stack = TcpIpStack(
        fd=initialize_interface(interface),
        mac_address=mac_address,
        ip6_address=ip6_address,
        ip6_gateway=ip6_gateway,
        ip4_address=ip4_address,
        ip4_gateway=ip4_gateway,
    )

    try:
        stack.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
