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
This module contains the example 'user space' IPv4 multicast listener
service — it joins an IPv4 multicast group (driving IGMP: a state-change
Report on join, a Leave on stop) and logs datagrams received on it.

examples_legacy/service__mcast_listener.py

ver 3.0.8
"""

import contextlib
import threading
from typing import Any, override

import click
from examples_legacy.lib.udp_service import UdpService
from examples_legacy.stack import cli as stack_cli

from net_addr import Ip4Address, NetAddrError
from pytcp.runtime.socket import (
    IP_ADD_MEMBERSHIP,
    IP_DROP_MEMBERSHIP,
    IPPROTO_IP,
    socket,
)
from pytcp.stack import sysctl


def _ip_mreq(group: Ip4Address, /) -> bytes:
    """
    Pack an 8-byte 'ip_mreq' (imr_multiaddr + imr_interface) joining
    'group' on the kernel-chosen IPv4 interface (imr_interface =
    INADDR_ANY).
    """

    return bytes(group) + bytes(Ip4Address())


class MulticastListenerService(UdpService):
    """
    IPv4 multicast listener service support class.
    """

    _subsystem_name = f"{UdpService._protocol_name} Multicast Listener"

    _event__stop_subsystem: threading.Event

    def __init__(self, *, group: Ip4Address, local_port: int, pingable: bool) -> None:
        """
        Class constructor.
        """

        # Bind the wildcard address so the socket receives datagrams sent
        # to the joined group on the chosen port (the join, not the bind
        # address, is what subscribes the interface to the group).
        self._local_ip_address = Ip4Address()
        self._local_port = local_port
        self._group = group
        self._pingable = pingable

        super().__init__()

    @override
    def _service(self, *, socket: socket) -> None:
        """
        Service logic handler.
        """

        # Join the group — this drives the IGMP state-change Report
        # (CHANGE_TO_EXCLUDE_MODE) to 224.0.0.22 and programs the group's
        # multicast MAC. Dropping it on exit drives the IGMP Leave.
        socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(self._group))
        if __debug__:
            self._log(f"Joined IPv4 multicast group {self._group}, listening on port {self._local_port}.")

        # With '--pingable', answer 'ping <group>' for the life of the
        # service by clearing the Linux-style 'icmp4.echo_ignore_broadcasts'
        # knob (default 1 = ignore broadcast/multicast echo); restored on
        # exit. The Echo Reply is sourced from the stack's unicast address.
        # Without it, the Smurf-mitigation default stays and the group does
        # not answer ping.
        echo_gate: contextlib.AbstractContextManager[None]
        if self._pingable:
            echo_gate = sysctl.override("icmp4.echo_ignore_broadcasts", 0)
            if __debug__:
                self._log("--pingable: set icmp4.echo_ignore_broadcasts=0 so the group answers ping.")
        else:
            echo_gate = contextlib.nullcontext()

        with echo_gate:
            try:
                while not self._event__stop_subsystem.is_set():

                    try:
                        message, remote_address = socket.recvfrom(timeout=1)

                        if message and __debug__:
                            self._log(
                                f"Received {len(message)} bytes for group {self._group} "
                                f"from {remote_address[0]}, port {remote_address[1]}."
                            )

                    except TimeoutError:
                        continue

            finally:
                socket.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, _ip_mreq(self._group))
                if __debug__:
                    self._log(f"Left IPv4 multicast group {self._group}.")


@click.command()
@click.option(
    "--group",
    default="239.1.1.1",
    type=str,
    help="IPv4 multicast group to join.",
)
@click.option(
    "--local-port",
    default=5007,
    type=int,
    help="Local UDP port the listener binds to.",
)
@click.option(
    "--pingable/--no-pingable",
    default=False,
    help=(
        "Answer 'ping <group>' while running by clearing the "
        "'icmp4.echo_ignore_broadcasts' sysctl (Echo Reply sourced from "
        "the stack unicast address). Off by default (Smurf mitigation)."
    ),
)
@click.pass_context
def cli(
    ctx: click.Context,
    /,
    *,
    group: str,
    local_port: int,
    pingable: bool,
    **kwargs: Any,
) -> None:
    """
    Start the IPv4 multicast listener service.
    """

    if not kwargs["stack__ip4_support"]:
        raise click.UsageError("The multicast listener requires IPv4 support (IGMP is IPv4-only).")

    try:
        group_address = Ip4Address(group)
    except NetAddrError as error:
        raise click.BadParameter(f"{group!r} is not a valid IPv4 address.") from error

    if not group_address.is_multicast:
        raise click.BadParameter(f"{group} is not an IPv4 multicast (224.0.0.0/4) address.")

    ctx.invoke(
        stack_cli,
        subsystems=[
            MulticastListenerService(
                group=group_address,
                local_port=local_port,
                pingable=pingable,
            )
        ],
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
