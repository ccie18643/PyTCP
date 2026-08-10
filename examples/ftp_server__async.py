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
This module contains a read-only anonymous async FTP server for the PyTCP
daemon — a real-world asyncio program that runs over the daemon's drop-in
socket. It serves a directory tree over the FTP control / PASV-data model
(RFC 959): USER / PASS / SYST / FEAT / PWD / CWD / CDUP / TYPE / PASV /
LIST / NLST / SIZE / RETR / QUIT.

It is built on 'asyncio.start_server', passing an explicit PyTCP socket via
'sock=' — the supported integration path (a global sys.modules['socket']
swap is NOT viable because asyncio's own event loop needs the real socket
module for its self-pipe / selector). Every connection (control and each
PASV data transfer) is a daemon-backed PyTCP socket driven by the asyncio
selector polling its real data-channel fd.

The socket source is injectable ('make_socket') so the same server logic
is exercised over real loopback sockets in the project's test suite; the
'main' entry point wires it to PyTCP daemon sockets.

Needs a running daemon that owns the TAP interface. 'pytcp stack start'
autoconfigures via DHCPv4, so either run a DHCP server on the link or boot
the daemon with a static address ('run_daemon(..., ip4_host=...)'). Then:

    PYTCP_DAEMON_SOCKET=/tmp/pytcp.sock ./examples/ftp_server__async.py \
        --host <stack-ip> --root /srv/ftp
    ftp <stack-ip>          # any FTP client, passive mode

Verified live end-to-end (real TAP + real 'ftplib' client, control +
PASV-data connections, byte-exact binary transfer); the full reproducible
recipe is in 'docs/refactor/daemon_socket_library_and_cli.md' (§9).

examples/ftp_server__async.py

ver 3.0.9
"""

import asyncio
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import click

from net_addr import Ip4Address
from pytcp import socket as pytcp_socket

# A 'make_socket' returns a fresh, unbound AF_INET stream socket. The daemon
# wiring returns a PyTCP drop-in socket; tests pass a stdlib factory.
type MakeSocket = Callable[[], socket.socket]

FTP__CONTROL_PORT: int = 21
FTP__CHUNK_SIZE: int = 65536


@dataclass
class _PasvData:
    """
    A pending PASV data channel: its one-shot server plus the future that
    resolves to the accepted client's stream pair.
    """

    server: asyncio.AbstractServer
    incoming: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]]
    port: int


@dataclass
class _Session:
    """
    Per-control-connection FTP state.
    """

    root: Path
    cwd: Path
    binary: bool = True
    pasv: _PasvData | None = field(default=None)


def _pytcp_make_socket() -> socket.socket:
    """
    Create a fresh PyTCP daemon-backed AF_INET stream socket (typed as a
    'socket.socket' for the duck-typed asyncio / FTP plumbing).
    """

    # The drop-in Socket is a duck-typed stand-in for the 'socket.socket'
    # asyncio's plumbing names; asyncio uses it through fileno / recv / send
    # / accept / setblocking, all of which the drop-in implements.
    return cast(socket.socket, pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM))


async def _send(writer: asyncio.StreamWriter, line: str) -> None:
    """
    Send one CRLF-terminated FTP reply line and flush it.
    """

    writer.write(line.encode("ascii", "replace") + b"\r\n")
    await writer.drain()


def _resolve(session: _Session, arg: str) -> Path | None:
    """
    Resolve an FTP path argument against the session, confining the result
    to the served root (returns None on an escape attempt).
    """

    target = (session.cwd if not arg.startswith("/") else session.root) / arg.lstrip("/") if arg else session.cwd
    try:
        resolved = target.resolve()
        resolved.relative_to(session.root)
    except OSError, ValueError:
        return None
    return resolved


def _list_line(entry: Path) -> str:
    """
    Render one 'ls -l'-style LIST line for 'entry'.
    """

    try:
        stat = entry.stat()
        size = stat.st_size
    except OSError:
        size = 0
    kind = "d" if entry.is_dir() else "-"
    return f"{kind}rw-r--r-- 1 ftp ftp {size:>12} Jan  1 00:00 {entry.name}"


async def _open_pasv(session: _Session, host: str, make_socket: MakeSocket) -> int:
    """
    Open a PASV data listener bound to an ephemeral port, arm a one-shot
    accept, store it on the session, and return the bound port.
    """

    listener = make_socket()
    listener.bind((host, 0))
    _, port = listener.getsockname()
    port = int(port)

    loop = asyncio.get_running_loop()
    incoming: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = loop.create_future()

    async def _on_data(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not incoming.done():
            incoming.set_result((reader, writer))

    server = await asyncio.start_server(_on_data, sock=listener)
    session.pasv = _PasvData(server=server, incoming=incoming, port=port)
    return int(port)


async def _take_data_writer(session: _Session) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """
    Wait for the armed PASV client to connect and return its stream pair,
    or None when no PASV channel is pending.
    """

    if (pasv := session.pasv) is None:
        return None
    session.pasv = None
    try:
        return await asyncio.wait_for(pasv.incoming, timeout=30.0)
    except TimeoutError, asyncio.TimeoutError:
        pasv.server.close()
        return None


async def _cmd_list(session: _Session, writer: asyncio.StreamWriter, arg: str) -> None:
    """
    Handle LIST / NLST: stream the directory listing over the PASV channel.
    """

    target = _resolve(session, arg)
    pair = await _take_data_writer(session)
    if pair is None:
        await _send(writer, "425 Use PASV first.")
        return
    data_reader, data_writer = pair
    await _send(writer, "150 Here comes the directory listing.")
    if target is not None and target.is_dir():
        for entry in sorted(target.iterdir()):
            data_writer.write((_list_line(entry) + "\r\n").encode("ascii", "replace"))
    await data_writer.drain()
    data_writer.close()
    _ = data_reader
    await _send(writer, "226 Directory send OK.")


async def _cmd_retr(session: _Session, writer: asyncio.StreamWriter, arg: str) -> None:
    """
    Handle RETR: stream a file's bytes over the PASV channel.
    """

    target = _resolve(session, arg)
    if target is None or not target.is_file():
        await _send(writer, "550 Failed to open file.")
        return
    pair = await _take_data_writer(session)
    if pair is None:
        await _send(writer, "425 Use PASV first.")
        return
    _, data_writer = pair
    await _send(writer, "150 Opening data connection.")
    try:
        with target.open("rb") as handle:
            while chunk := handle.read(FTP__CHUNK_SIZE):
                data_writer.write(chunk)
                await data_writer.drain()
        reply = "226 Transfer complete."
    except OSError:
        reply = "451 Local error reading file."
    data_writer.close()
    await _send(writer, reply)


async def _handle(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    root: Path,
    host: str,
    make_socket: MakeSocket,
) -> None:
    """
    Drive one FTP control connection through the command loop.
    """

    session = _Session(root=root, cwd=root)
    await _send(writer, "220 PyTCP async FTP server ready.")
    try:
        while not reader.at_eof():
            raw = await reader.readline()
            if not raw:
                break
            command, _, arg = raw.decode("ascii", "replace").strip().partition(" ")
            command = command.upper()
            arg = arg.strip()

            match command:
                case "USER":
                    await _send(writer, "331 Please specify the password.")
                case "PASS":
                    await _send(writer, "230 Login successful.")
                case "SYST":
                    await _send(writer, "215 UNIX Type: L8")
                case "FEAT":
                    await _send(writer, "211-Features:")
                    await _send(writer, " PASV")
                    await _send(writer, "211 End")
                case "TYPE":
                    session.binary = arg.upper().startswith("I")
                    await _send(writer, "200 Type set.")
                case "PWD":
                    rel = "/" + str(session.cwd.relative_to(session.root)).replace(".", "").lstrip("/")
                    await _send(writer, f'257 "{rel.rstrip("/") or "/"}" is the current directory.')
                case "CWD":
                    target = _resolve(session, arg)
                    if target is not None and target.is_dir():
                        session.cwd = target
                        await _send(writer, "250 Directory changed.")
                    else:
                        await _send(writer, "550 Failed to change directory.")
                case "CDUP":
                    parent = _resolve(session, "..")
                    session.cwd = parent if parent is not None else session.cwd
                    await _send(writer, "250 Directory changed.")
                case "SIZE":
                    target = _resolve(session, arg)
                    if target is not None and target.is_file():
                        await _send(writer, f"213 {target.stat().st_size}")
                    else:
                        await _send(writer, "550 Could not get file size.")
                case "PASV":
                    port = await _open_pasv(session, host, make_socket)
                    octets = ",".join(str(byte) for byte in bytes(Ip4Address(host)))
                    await _send(writer, f"227 Entering Passive Mode ({octets},{port >> 8},{port & 0xFF}).")
                case "LIST" | "NLST":
                    await _cmd_list(session, writer, arg)
                case "RETR":
                    await _cmd_retr(session, writer, arg)
                case "NOOP":
                    await _send(writer, "200 NOOP ok.")
                case "QUIT":
                    await _send(writer, "221 Goodbye.")
                    break
                case _:
                    await _send(writer, "502 Command not implemented.")
    except ConnectionError, asyncio.IncompleteReadError:
        pass
    finally:
        if session.pasv is not None:
            session.pasv.server.close()
        writer.close()


async def serve(*, host: str, port: int, root: Path, make_socket: MakeSocket) -> None:
    """
    Bind a control listener via 'make_socket' and serve FTP forever.
    """

    control = make_socket()
    control.bind((host, port))
    server = await asyncio.start_server(
        lambda reader, writer: _handle(reader, writer, root=root, host=host, make_socket=make_socket),
        sock=control,
    )
    async with server:
        await server.serve_forever()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default=None, help="Stack IPv4 address to bind (default: the daemon's first IPv4 host).")
@click.option("--port", type=click.IntRange(1, 0xFFFF), default=FTP__CONTROL_PORT, show_default=True)
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path.cwd,
    help="Directory to serve (read-only).",
)
def ftp_server(host: str | None, port: int, root: Path) -> None:
    """
    Run a read-only anonymous async FTP server over the PyTCP daemon.
    """

    if host is None:
        raise click.UsageError("--host is required (the stack IPv4 address the daemon is configured with).")
    Ip4Address(host)  # validate; raises a clear net_addr error on a bad literal

    click.echo(f"PyTCP async FTP server on {host}:{port} serving {root} (read-only)")
    try:
        asyncio.run(serve(host=host, port=port, root=root.resolve(), make_socket=_pytcp_make_socket))
    except KeyboardInterrupt:
        click.echo("\nShutting down.")


if __name__ == "__main__":
    ftp_server()  # pylint: disable=no-value-for-parameter  # click injects the arguments
