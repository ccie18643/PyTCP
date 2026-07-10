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
This module contains an async TCP Echo server (RFC 862) for the PyTCP
daemon — an asyncio program that runs over the daemon's drop-in stream
socket. On connect it sends a greeting, then echoes every chunk it receives
back to the client; as an easter egg carried over from the legacy examples,
a chunk naming a monkey ('malpka' / 'malpa' / 'malpi') is answered with the
matching ASCII-art payload. A 'quit' / 'close' / 'bye' / 'exit' line, or the
client closing its write half, ends the session with a farewell.

It is built on 'asyncio.start_server', passing an explicit PyTCP socket via
'sock=' — the supported integration path (a global sys.modules['socket']
swap is NOT viable because asyncio's own event loop needs the real socket
module for its self-pipe / selector). Each accepted connection is handled by
its own coroutine, so many clients are served concurrently on one loop.

The socket source is injectable ('make_socket') so the same server logic is
exercised over real loopback sockets in the project's test suite; the 'main'
entry point wires it to a PyTCP daemon socket.

Needs a running daemon that owns the TAP interface, e.g.:

    pytcp stack start -i tap7 --ip4-host <stack-ip>/24
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock \
        python -m examples.tcp_echo_server__async --host <stack-ip>
    # then, from a peer on the link:
    printf 'malpi\n' | nc <stack-ip> 7

examples/tcp_echo_server__async.py

ver 3.0.8
"""

import asyncio
import socket
from collections.abc import Callable
from typing import cast

import click

from examples.lib.malpi import echo_reply
from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET stream socket. The daemon
# wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

ECHO__PORT: int = 7
ECHO__CHUNK_SIZE: int = 65536

GREETING: bytes = b"***CLIENT OPEN / SERVICE OPEN***\n"
FAREWELL__PEER_CLOSED: bytes = b"***CLIENT CLOSED, SERVICE CLOSING***\n"
FAREWELL__QUIT: bytes = b"***CLIENT OPEN, SERVICE CLOSING***\n"
QUIT_WORDS: frozenset[bytes] = frozenset({b"quit", b"close", b"bye", b"exit"})


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Drive one echo connection: greet, echo each received chunk (answering a
    monkey request with its ASCII art), and close with a farewell when the
    client sends a quit word or closes its write half.
    """

    writer.write(GREETING)
    await writer.drain()
    try:
        while True:
            data = await reader.read(ECHO__CHUNK_SIZE)
            if not data:
                writer.write(FAREWELL__PEER_CLOSED)
                await writer.drain()
                break
            if data.strip().lower() in QUIT_WORDS:
                writer.write(FAREWELL__QUIT)
                await writer.drain()
                break
            writer.write(echo_reply(data))
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET stream socket (typed as a
    'socket.socket' for the duck-typed asyncio plumbing).
    """

    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM))


async def serve(*, host: str, port: int, make_socket: MakeSocket) -> None:
    """
    Bind a listener via 'make_socket' and serve TCP echo forever.
    """

    listener = make_socket()
    listener.bind((host, port))
    server = await asyncio.start_server(_handle, sock=listener)
    async with server:
        await server.serve_forever()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default=None, help="Stack IPv4 address to bind (the daemon's configured host).")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=ECHO__PORT, show_default=True)
def tcp_echo_server(host: str | None, port: int) -> None:
    """
    Run an async TCP Echo server (RFC 862) over the PyTCP daemon.
    """

    if host is None:
        raise click.UsageError("--host is required (the stack IPv4 address the daemon is configured with).")
    Ip4Address(host)  # validate; raises a clear net_addr error on a bad literal

    click.echo(f"PyTCP async TCP echo server on {host}:{port} (send 'malpi' for a surprise)")
    try:
        asyncio.run(serve(host=host, port=port, make_socket=_pytcp_make_socket))
    except KeyboardInterrupt:
        click.echo("\nShutting down.")


if __name__ == "__main__":
    tcp_echo_server()  # pylint: disable=no-value-for-parameter  # click injects the arguments
