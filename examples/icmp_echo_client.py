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

# pylint: disable = redefined-outer-name

"""
The example 'user space' client for ICMPv4/v6 Echo.

examples/icmp_echo_client.py

ver 3.0.2
"""


from __future__ import annotations

import random
import threading
import time
from datetime import datetime

import click

from pytcp import TcpIpStack, initialize_tap
from pytcp.lib import stack
from pytcp.lib.ip_helper import str_to_ip
from pytcp.lib.net_addr import Ip4Address, Ip6Address
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_request import (
    Icmp6EchoRequestMessage,
)


class IcmpEchoClient:
    """
    ICMPv4/v6 Echo client support class.
    """

    def __init__(
        self,
        *,
        local_ip_address: str = "0.0.0.0",
        remote_ip_address: str,
        message_count: int = -1,
    ) -> None:
        """
        Class constructor.
        """

        self._local_ip_address = str_to_ip(local_ip_address)
        self._remote_ip_address = str_to_ip(remote_ip_address)
        self._message_count = message_count
        self._run_thread = False

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo("Starting the ICMP Echo client.")
        self._run_thread = True
        threading.Thread(target=self.__thread_client).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo("Stopinging the ICMP Echo client.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_client(self) -> None:
        assert self._local_ip_address is not None

        flow_id = random.randint(0, 65535)

        message_count = self._message_count

        message_seq = 0
        while self._run_thread and message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            if self._local_ip_address.version == 4:
                assert isinstance(self._local_ip_address, Ip4Address)
                assert isinstance(self._remote_ip_address, Ip4Address)
                stack.packet_handler.send_icmp4_packet(
                    ip4__local_address=self._local_ip_address,
                    ip4__remote_address=self._remote_ip_address,
                    icmp4__message=Icmp4EchoRequestMessage(
                        id=flow_id,
                        seq=message_seq,
                        data=message,
                    ),
                )

            if self._local_ip_address.version == 6:
                assert isinstance(self._local_ip_address, Ip6Address)
                assert isinstance(self._remote_ip_address, Ip6Address)
                stack.packet_handler.send_icmp6_packet(
                    ip6__local_address=self._local_ip_address,
                    ip6__remote_address=self._remote_ip_address,
                    icmp6__message=Icmp6EchoRequestMessage(
                        id=flow_id,
                        seq=message_seq,
                        data=message,
                    ),
                )

            click.echo(
                f"Client ICMP Echo: Sent ICMP Echo ({flow_id}/{message_seq}) "
                f"to {self._remote_ip_address} - {str(message)}."
            )
            time.sleep(1)
            message_seq += 1
            message_count = min(message_count, message_count - 1)


@click.command()
@click.option("--interface", default="tap7")
@click.argument("remote_ip_address")
def cli(*, interface: str, remote_ip_address: str) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Run the ICMP Echo client.
    """

    stack = TcpIpStack(fd=initialize_tap(tap_name=interface))
    client = IcmpEchoClient(
        remote_ip_address=remote_ip_address,
    )

    try:
        stack.start()
        client.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        client.stop()
        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
