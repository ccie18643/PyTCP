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
Tests for the async anonymous FTP server / client examples (RFC 959). The
server and client are exercised end-to-end over real loopback stream
sockets via the examples' injectable socket factory (no daemon required),
covering anonymous login, the PASV data channel, a directory LIST, and a
byte-exact binary RETR.

pytcp/tests/integration/examples/test__examples__ftp.py

ver 3.0.9
"""

import asyncio
import socket
import tempfile
from pathlib import Path
from typing import override
from unittest import IsolatedAsyncioTestCase

from examples.ftp_client__async import run_client
from examples.ftp_server__async import serve

# A deterministic binary payload (2 KiB) served as the RETR target, chosen
# to be non-text so a byte-exact transfer is a meaningful assertion.
_BLOB_NAME = "blob.bin"
_BLOB = bytes(range(256)) * 8


def _stream_socket() -> socket.socket:
    """
    Build a fresh unbound loopback-capable AF_INET stream socket.
    """

    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class TestFtpServerClient(IsolatedAsyncioTestCase):
    """
    The async FTP server / client end-to-end tests over loopback.
    """

    @override
    def setUp(self) -> None:
        """
        Build a temporary FTP root holding the binary RETR target.
        """

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._root = Path(self._tmp.name)
        (self._root / _BLOB_NAME).write_bytes(_BLOB)

    async def _serve_on_free_port(self) -> tuple[str, int]:
        """
        Start the example's async 'serve' on a free loopback TCP port over
        the temporary root and return the '(host, port)' the client targets.
        'serve' binds its own fresh socket (from make_socket), so the probe
        is closed before 'serve' rebinds the port.
        """

        probe = _stream_socket()
        probe.bind(("127.0.0.1", 0))
        host, port = probe.getsockname()
        probe.close()

        server_task = asyncio.ensure_future(
            serve(host=host, port=port, root=self._root, make_socket=_stream_socket),
        )
        self.addCleanup(server_task.cancel)
        # Give the control listener a moment to arm before the client connects.
        await asyncio.sleep(0.05)
        return host, port

    async def _run_client(self, *, get_path: str | None, list_path: str) -> bytes:
        """
        Run the async FTP client against a freshly-served root and return the
        transferred bytes (the RETR body or the LIST listing).
        """

        host, port = await self._serve_on_free_port()
        return await run_client(
            host=host,
            port=port,
            user="anonymous",
            password="anonymous@pytcp",
            get_path=get_path,
            list_path=list_path,
            make_socket=_stream_socket,
        )

    async def test__ftp__retr_transfers_bytes_exactly(self) -> None:
        """
        Ensure an anonymous RETR of a binary file returns the file's bytes
        exactly over the PASV data channel.

        Reference: RFC 959 (File Transfer Protocol — RETR / PASV / TYPE I).
        """

        body = await self._run_client(get_path=_BLOB_NAME, list_path="")

        self.assertEqual(
            body,
            _BLOB,
            msg="RETR must transfer the served file's bytes exactly.",
        )

    async def test__ftp__list_shows_the_served_file(self) -> None:
        """
        Ensure an anonymous LIST of the root directory names the served file
        over the PASV data channel.

        Reference: RFC 959 (File Transfer Protocol — LIST / PASV).
        """

        listing = await self._run_client(get_path=None, list_path="")

        self.assertIn(
            _BLOB_NAME.encode("ascii"),
            listing,
            msg="LIST must name the served file in the directory listing.",
        )
