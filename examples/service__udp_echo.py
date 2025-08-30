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
This module contains the example 'user space' service UDP Echo (RFC 862).

examples/service__udp_echo.py

ver 3.0.3
"""


import threading
from typing import Any, override

import click
from net_addr import (
    Ip4Address,
    Ip6Address,
    IpAddress,
)

from examples.lib.malpi import malpa, malpi, malpka
from examples.lib.udp_service import UdpService
from examples.stack import cli as stack_cli
from pytcp.socket.socket import Socket


class UdpEchoService(UdpService):
    """
    UDP Echo service support class.
    """

    _subsystem_name = f"{UdpService._protocol_name} Echo Service"

    _event__stop_subsystem: threading.Event

    def __init__(self, *, local_ip_address: IpAddress, local_port: int):
        """
        Class constructor.
        """

        self._local_ip_address = local_ip_address
        self._local_port = local_port

        super().__init__()

    @override
    def _service(self, *, socket: Socket) -> None:
        """
        Service logic handler.
        """

        while not self._event__stop_subsystem.is_set():

            try:
                message, remote_address = socket.recvfrom(timeout=1)

                if message:
                    self._log(
                        f"Received {len(message)} bytes from "
                        f"{remote_address[0]}, port {remote_address[1]}."
                    )

                    if b"malpka" in message.strip().lower():
                        message = malpka
                    elif b"malpa" in message.strip().lower():
                        message = malpa
                    elif b"malpi" in message.strip().lower():
                        message = malpi

                    socket.sendto(message, remote_address)

                    self._log(
                        f"Sent {len(message)} bytes back to "
                        f"{remote_address[0]}, port {remote_address[1]}."
                    )

            except TimeoutError:
                continue


@click.command()
@click.option(
    "--local-port",
    default=7,
    type=int,
    help="Local port number to be used by the service.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    local_port: int,
    **kwargs: Any,
) -> None:
    """
    Start ICMP Echo service.
    """

    ctx.invoke(
        stack_cli,
        subsystems=[
            UdpEchoService(
                local_ip_address=(
                    kwargs["stack__ip6_host"].address
                    if kwargs["stack__ip6_host"]
                    else Ip6Address()
                ),
                local_port=local_port,
            ),
            UdpEchoService(
                local_ip_address=(
                    kwargs["stack__ip4_host"].address
                    if kwargs["stack__ip4_host"]
                    else Ip4Address()
                ),
                local_port=local_port,
            ),
        ],
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
