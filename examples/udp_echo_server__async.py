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
This module contains an async UDP Echo server (RFC 862) for the PyTCP
daemon — an asyncio program that runs over the daemon's drop-in datagram
socket. Every datagram it receives is echoed back to the sender; as an
easter egg carried over from the legacy examples, a request containing
'malpka' / 'malpa' / 'malpi' is answered with the matching ASCII-art monkey
instead.

It is built on 'asyncio.create_datagram_endpoint', passing an explicit
PyTCP socket via 'sock=' — the supported integration path (a global
sys.modules['socket'] swap is NOT viable because asyncio's own event loop
needs the real socket module for its self-pipe / selector). The datagram
transport is driven by the asyncio selector polling the socket's real
data-channel fd.

The socket source is injectable ('make_socket') so the same server logic is
exercised over real loopback sockets in the project's test suite; the 'main'
entry point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    sudo make tap7 && sudo make bridge
    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock \
        python -m examples.udp_echo_server__async --host <stack-ip>
    # then, from a peer on the link:
    echo malpi | nc -u <stack-ip> 7

examples/udp_echo_server__async.py

ver 3.0.9
"""

import asyncio
import socket
from collections.abc import Callable
from typing import Any, cast, override

import click

from examples.lib.malpi import echo_reply
from net_addr import Ip4Address, Ip6Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET datagram socket. The
# daemon wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

ECHO__PORT: int = 7


class _EchoServerProtocol(asyncio.DatagramProtocol):
    """
    An asyncio datagram protocol that echoes each received datagram back to
    its sender (answering a monkey request with the ASCII-art payload).
    """

    def __init__(self) -> None:
        """
        Initialize with no transport yet (set on connection_made).
        """

        self._transport: asyncio.DatagramTransport | None = None

    @override
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Record the datagram transport used to send replies.
        """

        self._transport = cast(asyncio.DatagramTransport, transport)

    @override
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        """
        Echo 'data' (or the matching monkey) back to the sender 'addr'. A
        zero-length datagram is silently dropped (legacy echo-service
        parity — an empty request gets no reply).
        """

        if not data:
            return
        assert self._transport is not None  # connection_made runs first
        self._transport.sendto(echo_reply(data), addr)


def _pytcp_make_socket(family: int) -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed datagram socket of the given
    address family (typed as a 'socket.socket' for the duck-typed asyncio
    datagram plumbing).
    """

    # The drop-in Socket is a duck-typed stand-in for the 'socket.socket'
    # asyncio names; asyncio drives it through fileno / recvfrom / sendto /
    # setblocking, all of which the drop-in implements.
    return cast(socket.socket, pytcp_socket.socket(family, pytcp_socket.SOCK_DGRAM))


async def serve(*, host: str, port: int, make_socket: MakeSocket) -> None:
    """
    Bind a datagram socket via 'make_socket' and echo datagrams forever.
    """

    loop = asyncio.get_running_loop()
    sock = make_socket()
    sock.bind((host, port))
    transport, _ = await loop.create_datagram_endpoint(_EchoServerProtocol, sock=sock)
    try:
        await asyncio.Event().wait()  # serve until cancelled (Ctrl-C)
    finally:
        transport.close()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default=None, help="Stack IPv4 / IPv6 address to bind (the daemon's configured host).")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=ECHO__PORT, show_default=True)
def udp_echo_server(host: str | None, port: int) -> None:
    """
    Run an async UDP Echo server (RFC 862) over the PyTCP daemon.
    """

    if host is None:
        raise click.UsageError("--host is required (the stack IPv4 / IPv6 address the daemon is configured with).")
    # An IPv6 literal (contains ':') binds an AF_INET6 socket; otherwise
    # AF_INET. Validate against the matching net_addr type for a clear
    # error on a bad literal.
    if ":" in host:
        Ip6Address(host)
        family = pytcp_socket.AF_INET6
    else:
        Ip4Address(host)
        family = pytcp_socket.AF_INET

    click.echo(f"PyTCP async UDP echo server on {host}:{port} (send 'malpi' for a surprise)")
    try:
        asyncio.run(serve(host=host, port=port, make_socket=lambda: _pytcp_make_socket(family)))
    except KeyboardInterrupt:
        click.echo("\nShutting down.")


if __name__ == "__main__":
    udp_echo_server()  # pylint: disable=no-value-for-parameter  # click injects the arguments
