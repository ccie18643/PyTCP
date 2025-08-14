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
The example 'user space' client for ICMP Echo protocol. It actively sends the
ICMP Echo Request messages to the remote IP address and waits for responses.
It is very basic implementation that essentially mimics operation of the UNIX
'ping' utility.

examples/client__icmp_echo.py

ver 3.0.3
"""


from __future__ import annotations

import os
import struct
import threading
from typing import Any, override

import click

from examples.lib.client import Client
from examples.lib.payload import payload
from examples.stack import cli as stack_cli
from net_addr import (
    ClickTypeIpAddress,
    Ip4Address,
    Ip6Address,
    IpVersion,
)
from pytcp.socket.socket import ReceiveTimeout

ICMP4__ECHO_REQUEST__TYPE = 8
ICMP4__ECHO_REQUEST__CODE = 0
ICMP6_ECHO_REQUEST_TYPE = 128
ICMP6_ECHO_REQUEST_CODE = 0


class IcmpEchoClient(Client):
    """
    ICMP Echo client support class.
    """

    _protocol_name = "ICMP"
    _subsystem_name = f"{_protocol_name} Echo Client"

    _event__stop_subsystem: threading.Event

    def __init__(
        self,
        *,
        remote_ip_address: Ip6Address | Ip4Address,
        message_count: int = -1,
        message_delay: int = 1,
        message_size: int = 64,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._remote_ip_address = remote_ip_address
        self._message_count = message_count
        self._message_delay = message_delay
        self._message_size = message_size

    @staticmethod
    def _parse_icmp_echo_reply_message(
        *, data: bytes
    ) -> tuple[int, int, bytes]:
        """
        Parse ICMP Echo Reply message.
        """

        if len(data) < 8:
            raise ValueError(f"ICMP message too short ({len(data)} bytes).")

        _, _, _, identifier, sequence = struct.unpack("!BBHHH", data[:8])
        payload = data[8:]

        return identifier, sequence, payload

    @staticmethod
    def _assemble_icmp_echo_request_message(
        *,
        ip_version: IpVersion,
        identifier: int,
        sequence: int,
        message_size: int,
    ) -> bytes:
        """
        Create ICMP Echo Request message.
        """

        match ip_version:
            case IpVersion.IP6:
                icmp_type = ICMP6_ECHO_REQUEST_TYPE
                icmp_code = ICMP6_ECHO_REQUEST_CODE
            case IpVersion.IP4:
                icmp_type = ICMP4__ECHO_REQUEST__TYPE
                icmp_code = ICMP4__ECHO_REQUEST__CODE

        header = struct.pack(
            "!BBHHH",
            icmp_type,
            icmp_code,
            0,  # Checksum will be calculated later by stack.
            identifier,
            sequence,
        )

        return header + payload(length=message_size)

    @override
    def _thread__sender(self) -> None:
        """
        Thread used to send data.
        """

        self._log("Started the sender thread.")

        identifier = os.getpid() & 0xFFFF

        if self._client_socket:
            message_count = self._message_count

            while not self._event__stop_subsystem.is_set() and message_count:
                icmp_message = self._assemble_icmp_echo_request_message(
                    ip_version=self._remote_ip_address.version,
                    identifier=identifier,
                    sequence=self._message_count - message_count + 1,
                    message_size=self._message_size,
                )

                try:
                    self._client_socket.send(icmp_message)
                except OSError as error:
                    self._log(f"The 'send()' method failed. Error: {error!r}.")
                    break

                self._log(
                    f"Sent {len(icmp_message) - 8} bytes to '{self._remote_ip_address}', "
                    f"id {identifier}, "
                    f"seq {self._message_count - message_count + 1}."
                )
                message_count = min(message_count, message_count - 1)

                if self._event__stop_subsystem.wait(
                    timeout=self._message_delay
                ):
                    break

            self._client_socket.close()
            self._log(
                f"Closed the connection to '{self._remote_ip_address}'.",
            )

            self._event__stop_subsystem.set()

            self._log("Stopped the sender thread.")

    @override
    def _thread__receiver(self) -> None:
        """
        Thread used to receive data.
        """

        if self._client_socket:
            self._log("Started the receiver thread.")

            while not self._event__stop_subsystem.is_set():
                try:
                    if data := self._client_socket.recv(
                        bufsize=1024,
                        timeout=1,
                    ):
                        identifier, sequence, payload = (
                            self._parse_icmp_echo_reply_message(data=data)
                        )
                        self._log(
                            f"Received {len(payload)} bytes from '{self._remote_ip_address}', "
                            f"id {identifier}, seq {sequence}."
                        )
                except ReceiveTimeout:
                    pass

            self._log("Stopped the receiver thread.")


@click.command()
@click.option(
    "--count",
    "-c",
    "message_count",
    type=click.IntRange(-1),
    default=-1,
    help="Number of messages to send.",
)
@click.option(
    "--delay",
    "-d",
    "message_delay",
    type=click.IntRange(0),
    default=1,
    help="Delay between messages in seconds.",
    show_default=True,
)
@click.option(
    "--size",
    "-s",
    "message_size",
    type=click.IntRange(0),
    default=64,
    help="Size of the payload in bytes.",
    show_default=True,
)
@click.argument(
    "remote_ip_address",
    type=ClickTypeIpAddress(),
    required=True,
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    message_count: int,
    message_delay: int,
    message_size: int,
    remote_ip_address: Ip6Address | Ip4Address,
    **kwargs: Any,
) -> None:
    """
    Start ICMP Echo client.
    """

    ctx.invoke(
        stack_cli,
        subsystem=IcmpEchoClient(
            remote_ip_address=remote_ip_address,
            message_count=message_count,
            message_delay=message_delay,
            message_size=message_size,
        ),
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
