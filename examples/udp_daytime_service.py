#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# examples/udp_daytime_service.py - The 'user space' service UDP Daytime (RFC 867).
#
# ver 2.7
#


from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING

import click
from udp_service import UdpService

from pytcp import TcpIpStack

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class UdpDaytimeService(UdpService):
    """
    UDP Echo service support class.
    """

    def __init__(
        self, *, local_ip_address: str = "0.0.0.0", local_port: int = 13
    ):
        """
        Class constructor.
        """

        super().__init__(
            service_name="Echo",
            local_ip_address=local_ip_address,
            local_port=local_port,
        )

    def service(self, *, listening_socket: Socket) -> None:
        """
        Inbound connection handler.
        """

        while self._run_thread:
            _, remote_address = listening_socket.recvfrom()
            message = bytes(str(datetime.now()), "utf-8")
            listening_socket.sendto(message, remote_address)
            click.echo(
                f"Service UDP Daytime: Sent {len(message)} bytes to "
                f"{remote_address[0]}, port {remote_address[1]}."
            )


@click.command()
@click.option("--interface", default="tap7")
def cli(*, interface: str):
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Run the UDP Daytime service.
    """

    stack = TcpIpStack(interface)
    service = UdpDaytimeService()

    try:
        stack.start()
        service.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        service.stop()
        stack.stop()


if __name__ == "__main__":
    cli()
