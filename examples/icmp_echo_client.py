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
The example 'user space' client for ICMP echo. It actively sends messages
to the ICMP Echo service.

examples/icmp_echo_client.py

ver 3.0.2
"""


from __future__ import annotations

import os
import struct
import time
from typing import Any, override

import click
from net_addr import Ip4Address
from net_addr import Ip6Address
from net_addr import IpVersion

from examples.lib.client import Client
from net_addr import (
    ClickTypeIpAddress,
)
from pytcp import socket
from run_stack import cli as stack_cli

ICMP4__ECHO_REQUEST__TYPE = 8
ICMP4__ECHO_REQUEST__CODE = 0

ICMP6_ECHO_REQUEST_TYPE = 128
ICMP6_ECHO_REQUEST_CODE = 0


class IcmpEchoClient(Client):
    """
    ICMP Echo client support class.
    """

    _protocol_name = "ICMP"
    _client_name = "Echo"

    def __init__(
        self,
        *,
        remote_ip_address: Ip6Address | Ip4Address,
        message_count: int = -1,
        message_delay: int = 1,
        message_size: int = 5,
    ) -> None:
        """
        Class constructor.
        """

        self._remote_ip_address = remote_ip_address
        self._message_count = message_count
        self._message_delay = message_delay
        self._message_size = message_size
        self._run_thread = False

    @classmethod
    def _create_icmp4_message(cls, identifier: int, sequence: int) -> bytes:
        """
        Create ICMPv4 Echo Request packet.
        """

        header = struct.pack(
            "!BBHHH",
            ICMP4__ECHO_REQUEST__TYPE,
            ICMP4__ECHO_REQUEST__CODE,
            0,
            identifier,
            sequence,
        )

        payload = struct.pack("!d", time.time())

        return header + payload

    @classmethod
    def _create_icmp6_message(cls, identifier: int, sequence: int) -> bytes:
        """
        Create ICMPv6 Echo Request packet.
        """

        header = struct.pack(
            "!BBHHH",
            ICMP6_ECHO_REQUEST_TYPE,
            ICMP6_ECHO_REQUEST_CODE,
            0,
            identifier,
            sequence,
        )

        payload = struct.pack("!d", time.time())

        return header + payload

    @override
    def _thread__client__sender(self) -> None:
        """
        Client thread used to send data.
        """

        click.echo("Client ICMP Echo: Started sender thread.")

        identifier = os.getpid() & 0xFFFF

        if self._client_socket:
            message_count = self._message_count

            while self._run_thread and message_count:
                match self._remote_ip_address.version:
                    case IpVersion.IP6:
                        icmp_message = self._create_icmp6_message(
                            identifier=identifier,
                            sequence=self._message_count - message_count + 1,
                        )
                    case IpVersion.IP4:
                        icmp_message = self._create_icmp4_message(
                            identifier=identifier,
                            sequence=self._message_count - message_count + 1,
                        )

                try:
                    self._client_socket.send(icmp_message)
                except OSError as error:
                    click.echo(f"Client ICMP Echo: send() error - {error!r}.")
                    break

                click.echo(
                    f"Client ICMP Echo: Sent {len(icmp_message) - 8} bytes to "
                    f"'{self._remote_ip_address}'."
                )
                time.sleep(self._message_delay)
                message_count = min(message_count, message_count - 1)

            self._client_socket.close()
            click.echo(
                "Client ICMP Echo: Closed connection to "
                f"'{self._remote_ip_address}'.",
            )

            click.echo("Client ICMP Echo: Stopped sender thread.")

    @override
    def _thread__client__receiver(self) -> None:
        """
        Client thread used to receive data.
        """

        if self._client_socket:
            click.echo("Client ICMP Echo: Started receiver thread.")

            while self._run_thread:
                try:
                    data, _ = self._client_socket.recvfrom(
                        bufsize=1024,
                        timeout=1,
                    )
                    if data:
                        click.echo(
                            f"Client ICMP Echo: Received {len(data) - 8} bytes from "
                            f"'{self._remote_ip_address}'."
                        )
                except socket.ReceiveTimeout:
                    pass

            click.echo("Client ICMP Echo: Stopped receiver thread.")


@click.command()
@click.argument(
    "remote_ip_address",
    type=ClickTypeIpAddress(),
    required=True,
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    remote_ip_address: Ip6Address | Ip4Address,
    **kwargs: dict[str, Any],
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start ICMP Echo client.
    """

    match remote_ip_address.version:
        case IpVersion.IP6:
            client = IcmpEchoClient(remote_ip_address=remote_ip_address)
        case IpVersion.IP4:
            client = IcmpEchoClient(remote_ip_address=remote_ip_address)

    ctx.invoke(stack_cli, subsystem=client, **kwargs)


if __name__ == "__main__":
    cli.main()
