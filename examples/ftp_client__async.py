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
This module contains a minimal anonymous async FTP client for the PyTCP
daemon — the client-side companion to 'ftp_server__async.py'. It connects
to an FTP server (RFC 959), logs in anonymously, and either lists a
directory or retrieves a file over a PASV data connection.

It is built on 'asyncio.open_connection(sock=...)' over a PyTCP socket
that 'loop.sock_connect' has already connected — the supported high-level
asyncio client path over the daemon (a global sys.modules['socket'] swap
is not viable; asyncio's own loop needs the real socket module). Both the
control and PASV-data connections are daemon-backed PyTCP sockets driven
by the asyncio selector.

The socket source is injectable ('make_socket') so the same client logic
is exercised over real loopback sockets in the project's test suite; the
'main' entry point wires it to PyTCP daemon sockets.

Needs a running daemon that owns the TAP interface (see
'ftp_server__async.py' / docs/refactor/daemon_socket_library_and_cli.md §9
for the setup). Then, against any FTP server the stack can reach:

    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_client__async.py \
        --host <ftp-server-ip>                 # list the root
    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_client__async.py \
        --host <ftp-server-ip> --get readme.txt > readme.txt

examples/ftp_client__async.py

ver 3.0.9
"""

import asyncio
import socket
import sys
from collections.abc import Callable
from typing import cast

import click

from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET stream socket. The daemon
# wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

FTP__CONTROL_PORT: int = 21
FTP__CHUNK_SIZE: int = 65536


class FtpError(Exception):
    """
    Raised when the server returns a 4xx / 5xx reply to a command.
    """


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET stream socket (typed as a
    'socket.socket' for the duck-typed asyncio plumbing).
    """

    # The drop-in Socket is a duck-typed stand-in for the 'socket.socket'
    # asyncio names; asyncio uses it through fileno / connect / recv / send.
    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM))


async def _open(host: str, port: int, make_socket: MakeSocket) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Connect a fresh socket to '(host, port)' and wrap it in an asyncio
    stream pair — the high-level asyncio client path over a PyTCP socket.
    """

    loop = asyncio.get_running_loop()
    sock = make_socket()
    sock.setblocking(False)
    await loop.sock_connect(sock, (host, port))
    return await asyncio.open_connection(sock=sock)


async def _read_reply(reader: asyncio.StreamReader) -> str:
    """
    Read one FTP reply, consuming a multi-line 'NNN-...' block through its
    terminating 'NNN ' line, and return the final reply line. Raise
    'FtpError' on a 4xx / 5xx status.
    """

    line = (await reader.readline()).decode("ascii", "replace").rstrip("\r\n")
    if len(line) >= 4 and line[3] == "-":
        code = line[:3]
        while True:
            nxt = (await reader.readline()).decode("ascii", "replace").rstrip("\r\n")
            if nxt.startswith(code + " "):
                line = nxt
                break
    if line[:1] in {"4", "5"}:
        raise FtpError(line)
    return line


async def _command(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, command: str) -> str:
    """
    Send one FTP command and return the server's reply line.
    """

    writer.write(command.encode("ascii", "replace") + b"\r\n")
    await writer.drain()
    return await _read_reply(reader)


def _parse_pasv(reply: str) -> tuple[str, int]:
    """
    Parse a '227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).' reply into the
    data-channel '(host, port)'.
    """

    numbers = reply[reply.index("(") + 1 : reply.index(")")].split(",")
    host = ".".join(numbers[:4])
    port = (int(numbers[4]) << 8) + int(numbers[5])
    return host, port


async def _transfer(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    make_socket: MakeSocket,
    command: str,
) -> bytes:
    """
    Run a PASV data command (LIST / RETR): open the passive data channel,
    issue the command, drain the data connection to EOF, and return its
    bytes.
    """

    data_host, data_port = _parse_pasv(await _command(reader, writer, "PASV"))
    data_reader, data_writer = await _open(data_host, data_port, make_socket)
    try:
        await _command(reader, writer, command)  # 150 opening data connection
        chunks: list[bytes] = []
        while chunk := await data_reader.read(FTP__CHUNK_SIZE):
            chunks.append(chunk)
    finally:
        data_writer.close()
    await _read_reply(reader)  # 226 transfer complete
    return b"".join(chunks)


async def run_client(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    get_path: str | None,
    list_path: str,
    make_socket: MakeSocket,
) -> bytes:
    """
    Connect, log in anonymously, and either RETR 'get_path' or LIST
    'list_path'; return the transferred bytes.
    """

    reader, writer = await _open(host, port, make_socket)
    try:
        await _read_reply(reader)  # 220 greeting
        await _command(reader, writer, f"USER {user}")
        await _command(reader, writer, f"PASS {password}")
        await _command(reader, writer, "TYPE I")
        command = f"RETR {get_path}" if get_path is not None else f"LIST {list_path}".rstrip()
        data = await _transfer(reader, writer, make_socket, command)
        await _command(reader, writer, "QUIT")
    finally:
        writer.close()
    return data


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", required=True, help="FTP server IPv4 address the stack can reach.")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=FTP__CONTROL_PORT, show_default=True)
@click.option("--user", default="anonymous", show_default=True)
@click.option("--password", default="anonymous@pytcp", show_default=True)
@click.option("--get", "get_path", default=None, metavar="PATH", help="RETR a file, writing it to stdout.")
@click.option("--list", "list_path", default="", metavar="PATH", help="LIST a directory (default: the root).")
def ftp_client(host: str, port: int, user: str, password: str, get_path: str | None, list_path: str) -> None:
    """
    Connect to an FTP server over the PyTCP daemon and LIST a directory or
    RETR a file (anonymous, passive mode).
    """

    Ip4Address(host)  # validate; raises a clear net_addr error on a bad literal

    try:
        data = asyncio.run(
            run_client(
                host=host,
                port=port,
                user=user,
                password=password,
                get_path=get_path,
                list_path=list_path,
                make_socket=_pytcp_make_socket,
            )
        )
    except FtpError as error:
        raise SystemExit(f"FTP error: {error}") from error

    if get_path is not None:
        sys.stdout.buffer.write(data)
    else:
        click.echo(data.decode("utf-8", "replace"), nl=False)


if __name__ == "__main__":
    ftp_client()  # pylint: disable=no-value-for-parameter  # click injects the arguments
