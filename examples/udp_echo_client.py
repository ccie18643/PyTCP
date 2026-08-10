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
This module contains a minimal UDP Echo client (RFC 862) for the PyTCP
daemon — the companion to 'udp_echo_server__async.py'. It sends one
datagram to an echo server and prints the reply (send 'malpi' to get an
ASCII-art monkey back from the example server).

The socket source is injectable ('make_socket') so the same client logic is
exercised over real loopback sockets in the project's test suite; the 'main'
entry point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock \
        python -m examples.udp_echo_client <server-ip> --message malpi

examples/udp_echo_client.py

ver 3.0.10
"""

import socket
from collections.abc import Callable
from typing import cast

import click

from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET datagram socket. The
# daemon wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

ECHO__PORT: int = 7


def echo_once(*, host: str, port: int, message: bytes, timeout: float, make_socket: MakeSocket) -> bytes:
    """
    Send 'message' to the echo server at '(host, port)' and return the
    reply, waiting up to 'timeout' seconds. Raises 'TimeoutError' if no
    reply arrives in time.
    """

    sock = make_socket()
    try:
        sock.settimeout(timeout)
        sock.sendto(message, (host, port))
        reply, _ = sock.recvfrom(65535)
    finally:
        sock.close()
    return reply


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET datagram socket (typed as a
    'socket.socket' for the stdlib-shaped client plumbing).
    """

    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("host")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=ECHO__PORT, show_default=True)
@click.option("--message", "-m", default="malpi", show_default=True, help="Text to send to the echo server.")
@click.option("--timeout", "-W", type=float, default=5.0, show_default=True, help="Seconds to wait for the reply.")
def udp_echo_client(host: str, port: int, message: str, timeout: float) -> None:
    """
    Send one datagram to the UDP Echo server at HOST and print the reply.
    """

    Ip4Address(host)  # validate; raises a clear net_addr error on a bad literal

    try:
        reply = echo_once(
            host=host,
            port=port,
            message=message.encode("utf-8", "replace"),
            timeout=timeout,
            make_socket=_pytcp_make_socket,
        )
    except TimeoutError:
        raise click.ClickException(f"No reply from {host}:{port} within {timeout:g} s.") from None

    click.echo(reply.decode("utf-8", "replace"), nl=False)


if __name__ == "__main__":
    udp_echo_client()  # pylint: disable=no-value-for-parameter  # click injects the arguments
