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
This module contains a multicast service discoverer for the PyTCP daemon —
the listener half of the multicast service-discovery example. It JOINS a
multicast group (IP_ADD_MEMBERSHIP), listens for announcements the
'mcast_announce.py' sender multicasts, and prints the discovered services;
on exit it LEAVES the group (IP_DROP_MEMBERSHIP). This exercises the stack's
IGMP group-membership API (RFC 1112 / 3376) end to end.

The socket source is injectable ('make_socket') so the same logic is
exercised over a daemon socket in the project's test suite; the 'main' entry
point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock python -m examples.mcast_discover
    # (run 'mcast_announce.py' on another stack on the same link)

examples/mcast_discover.py

ver 3.0.9
"""

import socket
import time
from collections.abc import Callable
from typing import cast

import click

from examples.mcast_proto import Announcement, parse_announcement
from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET datagram socket. The
# daemon wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

# A discovered service keyed by (source address, service name) — the natural
# dedup key so repeated announcements collapse to one entry.
type Discovered = dict[tuple[str, str], Announcement]

DISCOVERY__GROUP: str = "239.192.0.1"
DISCOVERY__PORT: int = 1900
DISCOVERY__ANY_INTERFACE: str = "0.0.0.0"


def _mreq(group: str, interface: str, /) -> bytes:
    """
    Build the 'ip_mreq' bytes (4-byte group + 4-byte interface address) for
    an IP_ADD/DROP_MEMBERSHIP option. A '0.0.0.0' interface lets the stack
    pick the first IPv4-capable interface.
    """

    return socket.inet_aton(group) + socket.inet_aton(interface)


def join_group(sock: socket.socket, /, *, group: str, interface: str = DISCOVERY__ANY_INTERFACE) -> None:
    """
    Join the multicast 'group' on 'interface' (IP_ADD_MEMBERSHIP).
    """

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, _mreq(group, interface))


def drop_group(sock: socket.socket, /, *, group: str, interface: str = DISCOVERY__ANY_INTERFACE) -> None:
    """
    Leave the multicast 'group' on 'interface' (IP_DROP_MEMBERSHIP).
    """

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, _mreq(group, interface))


def discover(
    *,
    group: str,
    port: int,
    duration: float,
    make_socket: MakeSocket,
    interface: str = DISCOVERY__ANY_INTERFACE,
) -> Discovered:
    """
    Join 'group' on '(group, port)', collect announcements for 'duration'
    seconds, and return the discovered services deduplicated by (source
    address, service name). The group is left on exit.
    """

    sock = make_socket()
    discovered: Discovered = {}
    try:
        # Bind to INADDR_ANY (not the group address): the join is what
        # delivers the group's datagrams, and PyTCP binds only stack-owned
        # addresses. The port must still match the group's port.
        sock.bind(("0.0.0.0", port))
        join_group(sock, group=group, interface=interface)
        deadline = time.monotonic() + duration
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, address = sock.recvfrom(65535)
            except TimeoutError:
                break
            announcement = parse_announcement(data)
            if announcement is not None:
                discovered[(address[0], announcement.service)] = announcement
    finally:
        try:
            drop_group(sock, group=group, interface=interface)
        except OSError:
            pass  # already implicitly left on close; best-effort explicit leave
        sock.close()
    return discovered


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET datagram socket (typed as a
    'socket.socket' for the stdlib-shaped plumbing).
    """

    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--group", default=DISCOVERY__GROUP, show_default=True, help="Multicast group to join.")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=DISCOVERY__PORT, show_default=True)
@click.option("--duration", type=float, default=5.0, show_default=True, help="Seconds to listen.")
@click.option(
    "--interface",
    default=DISCOVERY__ANY_INTERFACE,
    show_default=True,
    help="Local interface address to join on (0.0.0.0 = let the stack pick).",
)
def mcast_discover(group: str, port: int, duration: float, interface: str) -> None:
    """
    Join a discovery group and print the services announced on it.
    """

    if not Ip4Address(group).is_multicast:
        raise click.UsageError(f"--group {group} is not a multicast address (224.0.0.0/4).")
    Ip4Address(interface)  # validate; raises a clear net_addr error on a bad literal

    click.echo(f"Discovering services on {group}:{port} for {duration:g}s...")
    found = discover(group=group, port=port, duration=duration, interface=interface, make_socket=_pytcp_make_socket)

    if not found:
        click.echo("No services discovered.")
        return
    for (source, _service), announcement in sorted(found.items()):
        click.echo(f"  {announcement.service} at {announcement.host}:{announcement.port}  (from {source})")


if __name__ == "__main__":
    mcast_discover()  # pylint: disable=no-value-for-parameter  # click injects the arguments
