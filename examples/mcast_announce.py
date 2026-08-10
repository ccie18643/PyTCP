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
This module contains a multicast service announcer for the PyTCP daemon —
the sender half of the multicast service-discovery example. It periodically
multicasts a small text announcement to a group, so a listener that joined
the group ('mcast_discover.py') learns the service exists. This is the shape
real LAN discovery protocols (SSDP / UPnP, mDNS, cluster beacons) use.

The socket source is injectable ('make_socket') so the same logic is
exercised over real sockets in the project's test suite; the 'main' entry
point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock python -m examples.mcast_announce \
        --service echo --host <stack-ip> --service-port 7

examples/mcast_announce.py

ver 3.0.10
"""

import socket
import time
from collections.abc import Callable
from typing import cast

import click

from examples.mcast_proto import Announcement, format_announcement
from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET datagram socket. The
# daemon wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

DISCOVERY__GROUP: str = "239.192.0.1"
DISCOVERY__PORT: int = 1900


def announce_once(sock: socket.socket, /, *, group: str, port: int, announcement: Announcement) -> int:
    """
    Multicast one announcement for 'announcement' to '(group, port)' over an
    already-open socket. Returns the number of bytes sent.
    """

    return sock.sendto(format_announcement(announcement), (group, port))


def announce(
    *,
    group: str,
    port: int,
    announcement: Announcement,
    interval: float,
    count: int | None,
    make_socket: MakeSocket,
) -> int:
    """
    Multicast 'announcement' to '(group, port)' every 'interval' seconds,
    'count' times (or forever when 'count' is None). Returns the number of
    announcements sent.
    """

    sock = make_socket()
    sent = 0
    try:
        while count is None or sent < count:
            announce_once(sock, group=group, port=port, announcement=announcement)
            sent += 1
            if count is not None and sent >= count:
                break
            time.sleep(interval)
    finally:
        sock.close()
    return sent


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET datagram socket (typed as a
    'socket.socket' for the stdlib-shaped plumbing).
    """

    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--group", default=DISCOVERY__GROUP, show_default=True, help="Multicast group to announce on.")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=DISCOVERY__PORT, show_default=True)
@click.option("--service", default="echo", show_default=True, help="Advertised service name.")
@click.option("--host", required=True, help="Advertised service host (IPv4 address).")
@click.option("--service-port", type=click.IntRange(1, 0xFFFF), default=7, show_default=True)
@click.option("--interval", type=float, default=2.0, show_default=True, help="Seconds between announcements.")
@click.option("--count", type=click.IntRange(min=1), default=None, help="Stop after COUNT announcements.")
def mcast_announce(
    group: str, port: int, service: str, host: str, service_port: int, interval: float, count: int | None
) -> None:
    """
    Periodically multicast a service announcement to a discovery group.
    """

    if not Ip4Address(group).is_multicast:
        raise click.UsageError(f"--group {group} is not a multicast address (224.0.0.0/4).")
    Ip4Address(host)  # validate; raises a clear net_addr error on a bad literal

    announcement = Announcement(service=service, host=host, port=service_port)
    click.echo(f"Announcing {service} at {host}:{service_port} to {group}:{port} every {interval:g}s")
    try:
        announce(
            group=group,
            port=port,
            announcement=announcement,
            interval=interval,
            count=count,
            make_socket=_pytcp_make_socket,
        )
    except KeyboardInterrupt:
        click.echo("\nStopped.")


if __name__ == "__main__":
    mcast_announce()  # pylint: disable=no-value-for-parameter  # click injects the arguments
