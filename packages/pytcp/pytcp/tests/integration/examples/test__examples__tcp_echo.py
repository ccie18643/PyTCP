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
Tests for the async TCP Echo server example (RFC 862 + the malpi easter
egg) and its sync client. The async server is exercised end-to-end over
real loopback stream sockets via the examples' injectable socket factory
(no daemon required); the blocking client runs in a worker thread so it does
not stall the server's event loop.

pytcp/tests/integration/examples/test__examples__tcp_echo.py

ver 3.0.9
"""

import asyncio
import socket
from unittest import IsolatedAsyncioTestCase

from examples.lib.malpi import malpi
from examples.tcp_echo_client import echo_once
from examples.tcp_echo_server__async import FAREWELL__PEER_CLOSED, GREETING, serve


def _stream_socket() -> socket.socket:
    """
    Build a fresh unbound loopback-capable AF_INET stream socket.
    """

    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class TestTcpEchoServer(IsolatedAsyncioTestCase):
    """
    The async TCP Echo server / client end-to-end tests over loopback.
    """

    async def _serve_on_free_port(self) -> tuple[str, int]:
        """
        Start the example's async 'serve' on a free loopback TCP port and
        return the '(host, port)' the client should target. 'serve' binds
        its OWN fresh socket (from make_socket), so the factory yields an
        UNBOUND socket.
        """

        probe = _stream_socket()
        probe.bind(("127.0.0.1", 0))
        host, port = probe.getsockname()
        probe.close()

        server_task = asyncio.ensure_future(serve(host=host, port=port, make_socket=_stream_socket))
        self.addCleanup(server_task.cancel)
        # Give the listener a moment to arm before the client connects.
        await asyncio.sleep(0.05)
        return host, port

    async def _exchange(self, message: bytes, /) -> bytes:
        """
        Run one client exchange (in a worker thread so the blocking client
        does not stall the server's loop) and return the full server reply.
        """

        host, port = await self._serve_on_free_port()
        return await asyncio.to_thread(
            echo_once,
            host=host,
            port=port,
            message=message,
            timeout=5.0,
            make_socket=_stream_socket,
        )

    async def test__tcp_echo__serves_greeting_monkey_and_farewell(self) -> None:
        """
        Ensure a 'malpi' request receives the connect greeting, the
        ASCII-art monkey (not the literal 'malpi'), and the peer-closed
        farewell over the async stream endpoint.

        Reference: RFC 862 (Echo Protocol — return the data received).
        """

        reply = await self._exchange(b"malpi")

        self.assertIn(GREETING, reply, msg="The server must send its greeting on connect.")
        self.assertIn(malpi, reply, msg="A 'malpi' request must be answered with the monkey.")
        self.assertIn(FAREWELL__PEER_CLOSED, reply, msg="The server must send a farewell after the client half-closes.")

    async def test__tcp_echo__echoes_plain_message(self) -> None:
        """
        Ensure a plain (non-monkey) message is echoed back verbatim over
        the async stream endpoint.

        Reference: RFC 862 (Echo Protocol — return the data received).
        """

        reply = await self._exchange(b"hello over the stream")

        self.assertIn(
            b"hello over the stream",
            reply,
            msg="A plain message must be echoed back unchanged.",
        )
