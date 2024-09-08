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
The example 'user space' client for ICMPv4/v6 Echo.

examples/icmp_echo_client.py

ver 3.0.2
"""


from __future__ import annotations

import random
import threading
import time
from datetime import datetime
from typing import cast

import click

from pytcp import TcpIpStack, initialize_interface
from pytcp.lib import stack
from pytcp.lib.net_addr import Ip4Address, Ip6Address
from pytcp.lib.net_addr.click_types import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeIpAddress,
    ClickTypeMacAddress,
)
from pytcp.lib.net_addr.ip4_host import Ip4Host
from pytcp.lib.net_addr.ip6_host import Ip6Host
from pytcp.lib.net_addr.ip_address import IpAddress
from pytcp.lib.net_addr.mac_address import MacAddress
from pytcp.lib.stack import github_repository, version_string
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
        local_ip_address: IpAddress,
        remote_ip_address: IpAddress,
        message_count: int = -1,
    ) -> None:
        """
        Class constructor.
        """

        self._local_ip_address = local_ip_address
        self._remote_ip_address = remote_ip_address
        self._message_count = message_count
        self._run_thread = False

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo("Starting the ICMP Echo client.")
        self._run_thread = True
        threading.Thread(target=self.__thread__client).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo("Stopinging the ICMP Echo client.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread__client(self) -> None:
        assert self._local_ip_address is not None

        flow_id = random.randint(0, 65535)

        message_count = self._message_count

        message_seq = 0
        while self._run_thread and message_count:
            message = bytes(
                f"PyTCP {version_string}, {github_repository} - {str(datetime.now())}",
                "utf-8",
            )

            match self._local_ip_address.version, self._remote_ip_address.version:
                case 4, 4:
                    stack.packet_handler.send_icmp4_packet(
                        ip4__local_address=cast(
                            Ip4Address, self._local_ip_address
                        ),
                        ip4__remote_address=cast(
                            Ip4Address, self._remote_ip_address
                        ),
                        icmp4__message=Icmp4EchoRequestMessage(
                            id=flow_id,
                            seq=message_seq,
                            data=message,
                        ),
                    )
                case 6, 6:
                    stack.packet_handler.send_icmp6_packet(
                        ip6__local_address=cast(
                            Ip6Address, self._local_ip_address
                        ),
                        ip6__remote_address=cast(
                            Ip6Address, self._remote_ip_address
                        ),
                        icmp6__message=Icmp6EchoRequestMessage(
                            id=flow_id,
                            seq=message_seq,
                            data=message,
                        ),
                    )
                case _:
                    raise ValueError(
                        "Unsupported IP version combination: "
                        f"{self._local_ip_address.version=}, "
                        f"{self._remote_ip_address.version=}"
                    )

            click.echo(
                f"Client ICMP Echo: Sent ICMP Echo ({flow_id}/{message_seq}) "
                f"to {self._remote_ip_address} - {str(message)}."
            )
            time.sleep(1)
            message_seq += 1
            message_count = min(message_count, message_count - 1)


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
@click.option(
    "--remote-ip-address",
    type=ClickTypeIpAddress(),
    required=True,
    help="Remote IP address to be pinged.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_address: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_address: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
    remote_ip_address: IpAddress,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start Icmp Echo client.
    """

    fd, mtu = initialize_interface(interface)

    ip6_host = (
        None
        if ip6_address is None
        else Ip6Host(ip6_address, gateway=ip6_gateway)
    )
    ip4_host = (
        None
        if ip4_address is None
        else Ip4Host(ip4_address, gateway=ip4_gateway)
    )

    stack = TcpIpStack(
        fd=fd,
        mtu=mtu,
        mac_address=mac_address,
        ip6_host=ip6_host,
        ip4_host=ip4_host,
    )

    match remote_ip_address.version:
        case 6:
            client = IcmpEchoClient(
                local_ip_address=ip6_host.address if ip6_host else Ip6Address(),
                remote_ip_address=remote_ip_address,
            )
        case 4:
            client = IcmpEchoClient(
                local_ip_address=ip4_host.address if ip4_host else Ip4Address(),
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
