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
This module contains a minimal TCP Echo client (RFC 862) for the PyTCP
daemon — the companion to 'tcp_echo_server__async.py'. It connects, sends
one message, half-closes its write side (so the server replies and closes),
and prints everything the server sent back — the greeting, the echoed
message (send 'malpi' for an ASCII-art monkey), and the closing farewell.

The socket source is injectable ('make_socket') so the same client logic is
exercised over real loopback sockets in the project's test suite; the 'main'
entry point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock \
        python -m examples.tcp_echo_client <server-ip> --message malpi

examples/tcp_echo_client.py

ver 3.0.8
"""

import socket
from collections.abc import Callable
from typing import cast

import click

from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET stream socket. The daemon
# wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

ECHO__PORT: int = 7
ECHO__CHUNK_SIZE: int = 65536


def echo_once(*, host: str, port: int, message: bytes, timeout: float, make_socket: MakeSocket) -> bytes:
    """
    Connect to the echo server at '(host, port)', send 'message', half-close
    the write side, and return everything the server sends back before it
    closes (greeting + echoed message + farewell). Blocks up to 'timeout'
    seconds per socket operation.
    """

    sock = make_socket()
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(message)
        # Half-close: signal "done sending" so the server echoes, sends its
        # farewell, and closes — letting us drain the reply to EOF.
        sock.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while chunk := sock.recv(ECHO__CHUNK_SIZE):
            chunks.append(chunk)
    finally:
        sock.close()
    return b"".join(chunks)


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET stream socket (typed as a
    'socket.socket' for the stdlib-shaped client plumbing).
    """

    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("host")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=ECHO__PORT, show_default=True)
@click.option("--message", "-m", default="malpi", show_default=True, help="Text to send to the echo server.")
@click.option("--timeout", "-W", type=float, default=5.0, show_default=True, help="Seconds per socket operation.")
def tcp_echo_client(host: str, port: int, message: str, timeout: float) -> None:
    """
    Connect to a TCP Echo server at HOST, send one message, and print the
    server's reply (greeting + echo + farewell).
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
    except (TimeoutError, ConnectionError) as error:
        raise click.ClickException(f"Echo exchange with {host}:{port} failed: {error}") from error

    click.echo(reply.decode("utf-8", "replace"), nl=False)


if __name__ == "__main__":
    tcp_echo_client()  # pylint: disable=no-value-for-parameter  # click injects the arguments
